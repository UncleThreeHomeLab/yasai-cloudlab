import copy
import base64
import json
import socket
import tempfile
from pathlib import Path
import unittest
import yaml
from unittest.mock import MagicMock, Mock, patch
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from playbooks.previews.tests import browser_live as proof, fixtures, live_acceptance
from playbooks.previews.files import contract


class BrowserTests(unittest.TestCase):
    def test_controller_launch_inputs_and_offline_credential_separation(self):
        recipe = Path(__file__).with_name('compose.browser-live.yml')
        services = yaml.safe_load(recipe.read_text())['services']
        controller, checks, browser = (services[name] for name in ('controller', 'checks', 'browser'))
        root = recipe.parents[4]
        for name in ('.git', '.gitignore', '.gitattributes'):
            bindings = [value.split(':') for value in controller['volumes']
                        if value.split(':')[1] == '/workspace/'+name]
            self.assertEqual(len(bindings), 1, name)
            source, destination, mode = bindings[0]
            self.assertEqual((recipe.parent/source).resolve(), root/name)
            self.assertEqual(mode, 'ro')
        for service in (controller, checks):
            self.assertEqual(service['environment']['ANSIBLE_REMOTE_TEMP'], '/tmp/ansible-remote')
            self.assertIs(service['read_only'], True)
            self.assertEqual(service['tmpfs'], ['/tmp:mode=1777,size=128m'])
        self.assertEqual(checks['environment'], controller['environment'])
        self.assertNotIn('ANSIBLE_REMOTE_TEMP', browser['environment'])
        for service in (browser, checks):
            for value in service['volumes']:
                source, destination, mode = value.split(':')
                self.assertEqual(mode, 'ro')
                self.assertNotIn(destination, ('/workspace/.git', '/workspace/.env', '/recovery', '/state'))
                self.assertNotIn(source, ('recovery', 'state'))
        self.assertEqual(checks['network_mode'], 'none')
        self.assertEqual(checks['networks'], [])
        self.assertEqual(checks['depends_on'], [])

    def fixture(self):
        rows = [fixtures.approval(letter * 32) for letter in ('a', 'd')]
        for index, row in enumerate(rows):
            row.update(createdAt=1000, expiresAt=1900, pullRequest=7+index)
        settings = fixtures.catalog(rows)
        identity = {'realm': 'applications', 'username': 'proof-'+'e'*32, 'email': 'viewer@example.invalid',
                    'user_id': '11111111-1111-1111-1111-111111111111', 'enabled': True}
        state = {'viewer': {'nonce': 'e'*32, 'realm': 'applications'}, 'identity': identity, 'enrolled': True,
                 'executionPlatform': 'c'*40, 'instances': [row['instance'] for row in rows],
                 'browserApprovals': {}, 'pulls': {}}
        for slot, row in zip(('a', 'b'), rows):
            state['browserApprovals'][slot] = {'instance': row['instance'], 'approvalDigest': contract.digest(contract.canonical(row))}
            state['pulls'][slot] = {'repository': row['repository'], 'repositoryId': row['repositoryId'],
                                  'number': row['pullRequest'], 'head': row['sourceSha'], 'pending': None}
        runtime = {'zone': 'example.invalid', 'private': {'zone': 'internal.example.invalid',
                   'identity_host': 'login.example.invalid', 'tailnet_gateway': '100.64.0.1'}}
        return state, settings, identity, runtime

    def test_owned_bindings_and_foreign_refusals(self):
        original = self.fixture()
        self.assertEqual(len(proof.bindings(*original, now=1200)[0]), 2)
        for mutate in (
            lambda s,c,i,r: s.pop('browserApprovals'),
            lambda s,c,i,r: s['instances'].pop(),
            lambda s,c,i,r: s['browserApprovals']['a'].update(approvalDigest='f'*64),
            lambda s,c,i,r: s['pulls']['a'].update(head='f'*40),
            lambda s,c,i,r: s.update(offboarded=True),
            lambda s,c,i,r: c['ownership'].clear(),
            lambda s,c,i,r: i.update(enabled=False),
            lambda s,c,i,r: r['private'].update(tailnet_gateway='192.0.2.1'),
            lambda s,c,i,r: r.update(zone='foreign.invalid'),
        ):
            values = copy.deepcopy(original)
            mutate(*values)
            with self.assertRaises((ValueError, KeyError)): proof.bindings(*values, now=1200)

    def test_refusal_before_viewer_vault_read_or_browser_connection(self):
        state, settings, identity, runtime = self.fixture()
        state.pop('browserApprovals')
        api = Mock()
        with patch('playbooks.keycloak.tests.scoped_session.private_context') as context, \
                patch('playbooks.previews.tests.catalog_fixture.inspect', return_value={'catalog': settings}), \
                patch('playbooks.access.files.verify.remote', return_value=runtime), \
                patch('playbooks.secrets.files.vault.fields') as vault, patch.object(proof.socket, 'create_connection') as connect:
            context.return_value.__enter__.return_value = api
            with self.assertRaises(ValueError): proof.run({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, state, lambda *args: identity, Mock())
            vault.assert_not_called(); connect.assert_not_called()
            self.assertEqual(state['browserFailure'], {'stage':'preflight'})

    def test_exact_callback_readiness_refuses_before_credentials_connection_or_mfa(self):
        good={'status':200,'body':b'{"callback":true}'}
        cases=[good,{'status':503,'body':b'upstream unavailable'},{'status':302,'body':b'{"callback":true}'},
            *[{'status':200,'body':body} for body in (b'{',b'[]',b'{"callback":false}',b'{"callback":1}',
                b'{"callback":"true"}',b'{"callback":true,"extra":true}',b'{"callback":false,"callback":true}')],
            socket.timeout('synthetic timeout')]
        for failure in cases:
            for target in (0,1):
                with self.subTest(failure=failure,target=target):
                    state,settings,identity,runtime=self.fixture();rows=settings['approvals']
                    responses=[copy.deepcopy(good),copy.deepcopy(good)];responses[target]=failure
                    stop=RuntimeError('stop before reading credentials')
                    with patch('playbooks.keycloak.tests.scoped_session.private_context'), \
                            patch('playbooks.previews.tests.catalog_fixture.inspect',return_value={'catalog':settings}), \
                            patch('playbooks.previews.tests.catalog_fixture.verified_pull',side_effect=lambda api,receipt,*args:
                                fixtures.pull(next(row for row in rows if row['pullRequest']==receipt['number']))), \
                            patch('playbooks.previews.files.github.GitHub.blob',side_effect=lambda reader,row:contract.canonical(row['definition'])), \
                            patch('playbooks.access.files.verify.remote',return_value=runtime),patch.object(proof,'active'), \
                            patch.object(proof.time,'time',return_value=1200), \
                            patch('playbooks.previews.tests.probe_transport.handoff'), \
                            patch('playbooks.access.files.traffic.https',side_effect=responses) as https, \
                            patch('playbooks.secrets.files.vault.fields',side_effect=stop) as vault, \
                            patch.object(proof.socket,'create_connection') as connect:
                        begin=Mock()
                        with self.assertRaises(Exception) as caught:
                            proof.run({'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'},state,lambda *args:identity,begin)
                        if failure==good:
                            self.assertIs(caught.exception,stop);vault.assert_called_once()
                            self.assertEqual(https.call_count,2)
                        else:
                            vault.assert_not_called();self.assertEqual(https.call_count,target+1)
                        for row,call in zip(rows,https.call_args_list):
                            url=proof.urlsplit(contract.client(row,settings)['callbacks'][0])
                            self.assertEqual(call.args,(url.hostname,))
                            self.assertEqual(call.kwargs,{'address':'100.64.0.1','path':url.path,'timeout':5})
                        connect.assert_not_called();begin.assert_not_called()
                        self.assertNotIn('browserAttempted',state)
                        self.assertEqual(state['browserFailure'],{'stage':'enrollment' if failure==good else 'preflight'})

    def test_actual_run_owner_persists_only_fixed_failure_stages_and_preserves_one_shot_rules(self):
        stages=('preflight','enrollment','authorization','token-exchange','token-validation',
                'gateway-protection','dataplane','callback-rejection','origins')
        cases=[(stage,'fault') for stage in stages]+[('enrollment','credentials')]+[('enrollment',mode) for mode in
            ('timeout','eof','malformed','duplicate','oversized','extra-field','extra-frame','generic-failure',
             'terminal-unknown','terminal-type','terminal-false','terminal-extra','terminal-duplicate')]+[
             ('enrollment','terminal:'+value) for value in sorted(proof.ENROLLMENT_STAGES)]+[
             ('authorization','wrong-phase'),(None,'interruption')]
        native_channel=proof.Channel;sentinel='private-sentinel-never-persist'
        for stage,mode in cases:
            with self.subTest(stage=stage,mode=mode),tempfile.TemporaryDirectory() as directory, \
                    patch.object(live_acceptance.fixture,'JOURNALS',Path(directory)):
                state,settings,identity,runtime=self.fixture();rows=settings['approvals']
                state.update(baseline={},intent=None,provisioned=True,staged=True)
                path=Path(directory)/state['viewer']['nonce']/'journal.json'
                expected=live_acceptance.fixture.journal(path,state);saved=[];fault_enabled=[True]
                def save():
                    nonlocal expected
                    expected=live_acceptance.fixture.journal(path,state,expected=expected)
                    saved.append(json.loads(path.read_text()))
                error=KeyboardInterrupt(sentinel) if mode=='interruption' else socket.timeout(sentinel) if mode=='timeout' else RuntimeError(sentinel)
                connection=MagicMock();connection.__enter__.return_value=connection
                wire=MagicMock();wire.deadline=proof.time.monotonic()+240
                wire.read.side_effect=[{'ready':True},{'callback':sentinel},{'callback':sentinel},
                    {'rejected':True},{'rejected':True},dict.fromkeys(('origins','storage','dom','cors'),True)]
                if mode not in ('fault','interruption','credentials'):
                    payload={'eof':b'', 'malformed':b'{'+sentinel.encode()+b'\n',
                        'duplicate':b'{"ready":true,"ready":true,"private":"'+sentinel.encode()+b'"}\n',
                        'oversized':(sentinel.encode()+b'x'*proof.FRAME)[:proof.FRAME]+b'\n',
                        'extra-field':b'{"ready":true,"private":"'+sentinel.encode()+b'"}\n',
                        'extra-frame':b'{"ready":true}\n{"private":"'+sentinel.encode()+b'"}\n',
                        'generic-failure':b'{"failed":true}\n',
                        'terminal-unknown':json.dumps({'failed':True,'enrollmentStage':sentinel}).encode()+b'\n',
                        'terminal-type':b'{"failed":true,"enrollmentStage":[] }\n',
                        'terminal-false':b'{"failed":1,"enrollmentStage":"launch"}\n',
                        'terminal-extra':json.dumps({'failed':True,'enrollmentStage':'launch','private':sentinel}).encode()+b'\n',
                        'terminal-duplicate':b'{"failed":true,"enrollmentStage":"launch","enrollmentStage":"'+sentinel.encode()+b'"}\n'}.get(mode,b'')
                    if mode.startswith('terminal:'):
                        payload=json.dumps({'failed':True,'enrollmentStage':mode.split(':',1)[1]}).encode()+b'\n'
                    chunks=[payload[index:index+4096] for index in range(0,len(payload),4096)] or [b'']
                    if mode=='wrong-phase':chunks=[b'{"ready":true}\n',b'{"failed":true,"enrollmentStage":"launch"}\n']
                    connection.recv.side_effect=error if mode=='timeout' else chunks
                    wire=native_channel(connection)
                def fail(operation):
                    if mode=='fault' and fault_enabled[0] and stage==operation:raise error
                def send(value):
                    current=json.loads(path.read_text())
                    self.assertTrue(current['browserAttempted'])
                    if value['action']=='enroll':
                        self.assertEqual(current['intent'],{'action':'browser','slot':None})
                        if mode=='interruption':raise error
                    operation={'enroll':'enrollment','authorize':'authorization','reject':'callback-rejection','origins':'origins'}[value['action']]
                    fail(operation)
                if mode in ('fault','interruption','credentials'):wire.send.side_effect=send
                else:connection.sendall.side_effect=lambda raw:send(json.loads(raw))
                def observe(*args):fail('preflight');return identity
                def json_get(url,**kwargs):
                    if url.endswith('/token'):fail('token-exchange')
                    return {'private':sentinel}
                def claims(*args):fail('token-validation');return sentinel
                def protected(*args):fail('gateway-protection')
                def handoff(*args,**kwargs):
                    if args[2]:fail('dataplane');return {'result':{'protected':True}}
                    return {'approved':True}
                def credentials(*args):
                    if mode=='credentials' and fault_enabled[0]:raise error
                    return dict(username=identity['username'],email=identity['email'],password=sentinel,ownership_id=state['viewer']['nonce'])
                with patch('playbooks.keycloak.tests.scoped_session.private_context'), \
                        patch('playbooks.previews.tests.catalog_fixture.inspect',return_value={'catalog':settings}), \
                        patch('playbooks.previews.tests.catalog_fixture.verified_pull',side_effect=lambda api,receipt,*args:
                            fixtures.pull(next(row for row in rows if row['pullRequest']==receipt['number']))), \
                        patch('playbooks.previews.files.github.GitHub.blob',side_effect=lambda reader,row:contract.canonical(row['definition'])), \
                        patch('playbooks.access.files.verify.remote',return_value=runtime),patch.object(live_acceptance,'remote',side_effect=observe), \
                        patch.multiple(proof,active=Mock(),callback=Mock(return_value=sentinel)), \
                        patch.object(proof.time,'time',return_value=1200), \
                        patch('playbooks.previews.tests.probe_transport.handoff',side_effect=handoff), \
                        patch('playbooks.access.files.traffic.https',return_value={'status':200,'body':b'{"callback":true}'}), \
                        patch('playbooks.secrets.files.vault.fields',side_effect=credentials) as vault, \
                        patch('playbooks.keycloak.files.health.json_get',side_effect=json_get), \
                        patch.object(proof.socket,'create_connection',return_value=connection) as connect, \
                        patch.object(proof,'Channel',return_value=wire), \
                        patch.object(proof,'claims',side_effect=claims),patch.object(proof,'protected',side_effect=protected):
                    values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
                    with self.assertRaises(KeyboardInterrupt if mode=='interruption' else Exception) as caught:
                        live_acceptance.execute('browser',values,state,save)
                    if mode in ('fault','timeout','interruption','credentials'):self.assertIs(caught.exception,error)
                    else:self.assertIsInstance(caught.exception,ValueError)
                    persisted=json.loads(path.read_text());self.assertNotIn(sentinel,path.read_text())
                    self.assertNotIn('browserProof',persisted)
                    if mode=='interruption':
                        self.assertNotIn('browserFailure',persisted)
                        self.assertEqual(persisted['intent'],{'action':'browser','slot':None})
                    else:
                        diagnostic={'stage':stage}
                        if mode.startswith('terminal:'):diagnostic['enrollmentStage']=mode.split(':',1)[1]
                        self.assertEqual(persisted['browserFailure'],diagnostic)
                        self.assertTrue(persisted['browserFailed']);self.assertIsNone(persisted['intent'])
                    if stage=='preflight' or mode=='credentials':
                        self.assertNotIn('browserAttempted',persisted);connect.assert_not_called()
                        if stage=='preflight':vault.assert_not_called()
                        else:self.assertEqual(vault.call_count,1)
                        fault_enabled[0]=False
                        live_acceptance.execute('browser',values,state,save)
                        self.assertEqual(state['browserFailure'],{'stage':stage})
                        self.assertEqual(state['browserProof'],dict(authentication=True,audiences=True,callbacks=True,origins=True,
                            dataplane={'result':{'protected':True}},platform=state['executionPlatform'],approvals=state['browserApprovals']))
                    count=len(saved);credential_reads=vault.call_count;connections=connect.call_count
                    with self.assertRaises(ValueError):live_acceptance.execute('browser',values,state,save)
                    self.assertEqual(len(saved),count);self.assertEqual(vault.call_count,credential_reads);self.assertEqual(connect.call_count,connections)
                    live_acceptance.prerequisites('offboard-propose',state,None)
                self.assertEqual(path.stat().st_mode & 0o777,0o600)
                if mode not in ('fault','interruption','credentials'):
                    self.assertTrue(connection.settimeout.called)
                    self.assertTrue(all(0<call.args[0]<=35 for call in connection.settimeout.call_args_list))

    def test_callback_unique_exact_bounded_query(self):
        redirect = 'https://preview.example.invalid/callback'
        issuer = 'https://login.example.invalid/realms/applications'
        query = urlencode({'code': 'private-code', 'state': 'private-state', 'iss': issuer, 'session_state': 'session'})
        self.assertEqual(proof.callback(redirect+'?'+query, redirect, 'private-state', issuer), 'private-code')
        for value in (redirect+'?'+query+'#fragment', redirect+'?'+query+'#', redirect+'?'+query+'&code=duplicate',
                      redirect+'?'+query+'&unknown=private', redirect+'?code=secret&state=wrong',
                      redirect+'/changed?'+query, 'https://foreign.invalid/callback?'+query,
                      redirect+'?code=&state=private-state', redirect+'?error=denied&state=private-state'):
            with self.assertRaises(ValueError): proof.callback(value, redirect, 'private-state', issuer)

    def test_protocol_schema_size_deadline_and_disconnect(self):
        for raw in (b'{"ready":true,"private":"secret"}\n', b'{"ready":false,"ready":true}\n', b'{}\n{}\n', b'x'*32769, b'', b'not-json\n'):
            connection = Mock(); connection.recv.return_value = raw
            with self.assertRaises((ValueError, json.JSONDecodeError)): proof.Channel(connection).read({'ready'})
        connection = Mock(); connection.recv.side_effect = [b'{"rea', b'dy":true}\n']
        self.assertEqual(proof.Channel(connection).read({'ready'}), {'ready': True})
        wire = proof.Channel(connection); wire.deadline = 0
        with self.assertRaises(ValueError): wire.send({'ready': True})
        terminal=b'{"failed":true,"enrollmentStage":"launch"}\n'
        for keys in ({'ready'},{'callback'},{'rejected'},{'origins','storage','dom','cors'}):
            connection=Mock();connection.recv.return_value=terminal
            with self.assertRaises(ValueError):proof.Channel(connection).read(keys)
        for raw in (terminal+b' ',terminal+b'{}\n',b'{"failed":true,"enrollmentStage":null}\n',
                    b'{"failed":true,"enrollmentStage":true}\n',b'{"failed":false,"enrollmentStage":"launch"}\n'):
            connection=Mock();connection.recv.return_value=raw
            with self.assertRaises(ValueError):proof.Channel(connection).read({'ready'},enrollment=True)
        for value in sorted(proof.ENROLLMENT_STAGES):
            connection=Mock();connection.recv.return_value=json.dumps({'failed':True,'enrollmentStage':value}).encode()+b'\n'
            self.assertEqual(proof.Channel(connection).read({'ready'},enrollment=True),{'failed':True,'enrollmentStage':value})

    def test_existing_jwt_signature_plus_exact_subject_azp_and_lifetime(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = key.public_key().public_numbers()
        encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip('=')
        integer = lambda value: encode(value.to_bytes((value.bit_length()+7)//8, 'big'))
        jwks = {'keys': [{'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'kid': 'fixture',
                          'n': integer(numbers.n), 'e': integer(numbers.e)}]}
        issuer, client, subject = 'https://login.example.invalid/realms/applications', 'preview-'+'a'*32, 'viewer-subject'
        def token(kind, **changes):
            value = dict(iss=issuer, aud=client, azp=client, sub=subject, iat=1200, exp=1400, typ=kind, nonce='nonce')
            value.update(changes)
            raw = encode(contract.canonical({'alg': 'RS256', 'typ': 'JWT', 'kid': 'fixture'}))+'.'+encode(contract.canonical(value))
            return raw+'.'+encode(key.sign(raw.encode(), padding.PKCS1v15(), hashes.SHA256()))
        response = {'id_token': token('ID'), 'access_token': token('Bearer')}
        self.assertEqual(proof.claims(response, jwks, issuer, client, 'nonce', subject, now=1250), response['access_token'])
        for changes in ({'sub': 'foreign'}, {'azp': 'foreign'}, {'exp': 1800}, {'aud': 'foreign'},
                        {'aud': [client, 'foreign']}, {'nonce': 'foreign'}):
            invalid = {'id_token': token('ID', **changes), 'access_token': token('Bearer', **changes)}
            with self.assertRaises(ValueError): proof.claims(invalid, jwks, issuer, client, 'nonce', subject, now=1250)
        response['access_token'] = response['access_token'][:-5]+'wrong'
        with self.assertRaises(ValueError): proof.claims(response, jwks, issuer, client, 'nonce', subject, now=1250)

    def test_https_status_and_body_never_classify_redirect_or_network_error_as_denial(self):
        _, settings, _, _ = self.fixture()
        rows, tokens = settings['approvals'], ['token-a', 'token-b']
        def request(host, **arguments):
            index = 0 if rows[0]['instance'] in host else 1
            if arguments['headers'].get('Authorization') == 'Bearer '+tokens[index]:
                return {'status': 200, 'body': json.dumps({'message': rows[index]['definition']['message'], 'source': rows[index]['sourceSha']})}
            return {'status': 403, 'body': ''}
        proof.protected(rows, settings, '100.64.0.1', tokens, request=request)
        for status in (200, 302, 404, 500):
            def bad(host, **arguments):
                value = request(host, **arguments)
                return dict(value, status=status) if value['status'] == 403 else value
            with self.assertRaises(ValueError): proof.protected(rows, settings, '100.64.0.1', tokens, request=bad)
        with self.assertRaises(OSError): proof.protected(rows, settings, '100.64.0.1', tokens, request=Mock(side_effect=OSError('private metadata')))

    def test_cli_requires_explicit_receipts_before_intent_and_retains_sanitized_result(self):
        state, _, _, _ = self.fixture(); state['baseline'] = {}; state['intent'] = None
        with patch.object(proof, 'run', return_value={'origins': True}) as run:
            live_acceptance.execute('browser', {}, state, lambda: None)
            self.assertEqual(state['browserProof'], {'origins': True}); run.assert_called_once()
        state.pop('browserApprovals')
        save = Mock()
        with self.assertRaises(ValueError): live_acceptance.execute('browser', {}, state, save)
        save.assert_not_called()

    def test_failed_browser_attempt_is_consumed_and_existing_offboarding_remains_available(self):
        state, _, _, _ = self.fixture()
        state.update(baseline={}, intent=None, provisioned=True, staged=True)
        saved = []
        def failed(values, current, observe, begin):
            self.assertNotIn('browserAttempted', current)
            begin()
            self.assertTrue(saved[-1]['browserAttempted'])
            raise RuntimeError('private error')
        with patch.object(proof, 'run', side_effect=failed):
            with self.assertRaises(RuntimeError): live_acceptance.execute('browser', {}, state, lambda: saved.append(copy.deepcopy(state)))
        self.assertTrue(saved[-1]['browserAttempted']); self.assertTrue(state['browserFailed'])
        self.assertIsNone(state['intent'])
        with self.assertRaises(ValueError): live_acceptance.execute('browser', {}, state, Mock())
        live_acceptance.prerequisites('offboard-propose', state, None)
        self.assertNotIn('offboarding', state)

    def test_pre_enrollment_failure_does_not_consume_attempt_and_can_retry(self):
        state, _, _, _ = self.fixture()
        state.update(baseline={}, intent=None)
        with patch.object(proof, 'run', side_effect=OSError('private preflight error')):
            with self.assertRaises(OSError): live_acceptance.execute('browser', {}, state, lambda: None)
        self.assertNotIn('browserAttempted', state)
        self.assertIsNone(state['intent'])
        def success(values, current, observe, begin):
            begin()
            return {'origins': True}
        with patch.object(proof, 'run', side_effect=success):
            live_acceptance.execute('browser', {}, state, lambda: None)
        self.assertTrue(state['browserAttempted'])
        self.assertEqual(state['browserProof'], {'origins': True})

    def test_persisted_consumed_browser_crash_can_only_enter_owned_offboarding(self):
        state, _, _, _ = self.fixture()
        nonce = state['viewer']['nonce']
        state.update(format=1, nonce=nonce, platform='c'*40, baseline={}, provisioned=True, staged=True,
                     browserAttempted=True, intent={'action': 'browser', 'slot': None})
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(live_acceptance.fixture, 'JOURNALS', Path(directory)), \
                patch('playbooks.argocd.files.render.committed_payload', return_value={'revision': 'c'*40}), \
                patch.object(live_acceptance, 'dotenv_values', return_value={}), \
                patch.object(live_acceptance.session, 'private_context'), \
                patch.dict('os.environ'):
            path = Path(directory) / nonce / 'journal.json'
            live_acceptance.fixture.journal(path, state)
            def publication(api, values, current, save, *, offboard):
                persisted = json.loads(path.read_text())
                self.assertEqual(persisted['intent'], {'action': 'offboard-propose', 'slot': None})
                self.assertIs(persisted['browserAttempted'], True)
                self.assertTrue(persisted['browserFailed'])
                self.assertTrue(offboard)
                current['offboarding'] = {'number': 99, 'head': 'f'*40}
                save()
            with patch.object(live_acceptance, 'publication', side_effect=publication) as publish:
                live_acceptance.main(['offboard-propose', '--nonce', nonce, '--live'])
                publish.assert_called_once()
            persisted = json.loads(path.read_text())
            self.assertIs(persisted['browserAttempted'], True)
            self.assertIsNone(persisted['intent'])
            self.assertEqual(persisted['offboarding'], {'number': 99, 'head': 'f'*40})
        for intent, attempted, action, slot in (
                ({'action': 'browser', 'slot': 'a'}, True, 'offboard-propose', None),
                ({'action': 'viewer-stage', 'slot': None}, True, 'offboard-propose', None),
                ({'action': 'browser', 'slot': None}, False, 'offboard-propose', None),
                ({'action': 'browser', 'slot': None}, 1, 'offboard-propose', None),
                ({'action': 'browser', 'slot': None}, True, 'offboard-propose', 'a'),
                ({'action': 'browser', 'slot': None}, True, 'viewer-observe', None),
                ({'action': 'browser', 'slot': None}, True, 'browser', None)):
            current = copy.deepcopy(state)
            current.update(intent=intent, browserAttempted=attempted)
            save = Mock()
            with self.assertRaises(ValueError): live_acceptance.execute(action, {}, current, save, slot)
            save.assert_not_called()

    def test_enrollment_begin_is_after_preflight_and_connection_before_credential_frame(self):
        state, settings, identity, runtime = self.fixture()
        rows = settings['approvals']
        events = []
        def credentials(*arguments):
            events.append('credentials')
            return dict(username=identity['username'], email=identity['email'], password='synthetic', ownership_id=state['viewer']['nonce'])
        def send(value):
            self.assertEqual(value['action'], 'enroll')
            events.append('frame')
            raise RuntimeError('stop before browser operation')
        def connect(*arguments, **keywords):
            events.append('connection')
            return connection
        from unittest.mock import MagicMock
        connection = MagicMock()
        with patch('playbooks.keycloak.tests.scoped_session.private_context'), \
                patch('playbooks.previews.tests.catalog_fixture.inspect', return_value={'catalog': settings}), \
                patch('playbooks.previews.tests.catalog_fixture.verified_pull', side_effect=lambda api,receipt,*args:
                      fixtures.pull(next(row for row in rows if row['pullRequest'] == receipt['number']))), \
                patch('playbooks.previews.files.github.GitHub.blob', side_effect=lambda reader,row: contract.canonical(row['definition'])), \
                patch('playbooks.access.files.verify.remote', return_value=runtime), \
                patch.object(proof, 'bindings', return_value=(rows, '100.64.0.1')), patch.object(proof, 'active'), \
                patch('playbooks.previews.tests.probe_transport.handoff', side_effect=lambda *args: events.append('probe-preflight')), \
                patch('playbooks.access.files.traffic.https',side_effect=lambda *args,**kwargs:
                    events.append('callback') or {'status':200,'body':b'{"callback":true}'}), \
                patch.object(proof.time, 'time', return_value=1200), \
                patch('playbooks.secrets.files.vault.fields', side_effect=credentials) as vault, \
                patch('playbooks.keycloak.files.health.json_get', return_value={}), \
                patch.object(proof.socket, 'create_connection', side_effect=connect), \
                patch.object(proof, 'Channel') as channel:
            channel.return_value.send.side_effect = send
            values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
            with self.assertRaises(RuntimeError):
                proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, ['probe-preflight', 'callback', 'callback', 'credentials', 'connection', 'begin', 'frame'])
            events.clear()
            with patch.object(proof.time, 'time', return_value=1700):
                with self.assertRaises(ValueError): proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, [])
            self.assertEqual(vault.call_count, 1)
            with patch.object(proof.time, 'time', side_effect=[1200, 1200, 1200, 1700]):
                with self.assertRaises(ValueError): proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, ['probe-preflight', 'callback', 'callback', 'credentials', 'connection'])
            self.assertEqual(vault.call_count, 2)
            events.clear()
            with patch.object(proof.time,'time',side_effect=[1200,1200,1700]):
                with self.assertRaises(ValueError):proof.run(values,state,lambda *args:identity,lambda:events.append('begin'))
            self.assertEqual(events,['probe-preflight','callback','callback'])
            self.assertEqual(vault.call_count,2)
            events.clear()
            with patch('playbooks.previews.tests.probe_transport.handoff',side_effect=ValueError('insufficient readiness margin')):
                with self.assertRaises(ValueError):proof.run(values,state,lambda *args:identity,lambda:events.append('begin'))
            self.assertEqual(events,[])
            self.assertEqual(vault.call_count,2)

    def test_runtime_requires_active_current_owned_controller_and_identity_records(self):
        _, settings, _, _ = self.fixture()
        rows = settings['approvals']
        cluster = {'states': {}}
        for name, owner in ((contract.STATE, contract.OWNER), (contract.IDENTITY_STATE, 'cloudlab-preview-identity')):
            entries = {row['instance']: {'approval': row, 'approvalDigest': contract.digest(contract.canonical(row)),
                'phase': 'active', 'originVersion': contract.ORIGIN_VERSION, 'verifiedAt': 1200} for row in rows}
            cluster['states'][name] = {'metadata': {'labels': {'cloudlab.io/owner': owner}},
                                      'data': {'state.json': json.dumps({'entries': entries})}}
        proof.active(rows, cluster, 1250)
        for name in (contract.STATE, contract.IDENTITY_STATE):
            changed = copy.deepcopy(cluster)
            state = json.loads(changed['states'][name]['data']['state.json'])
            state['entries'][rows[0]['instance']]['phase'] = 'retiring'
            changed['states'][name]['data']['state.json'] = json.dumps(state)
            with self.assertRaises(ValueError): proof.active(rows, changed, 1250)

    def test_access_probe_uses_same_browser_budget_and_never_sends_tokens_to_browser(self):
        from unittest.mock import MagicMock
        state,settings,identity,runtime=self.fixture();rows=settings['approvals'];events=[]
        tokens=['synthetic-access-a','synthetic-access-b'];preflight_context={'approved':True}
        wire=MagicMock();wire.deadline=proof.time.monotonic()+240
        wire.read.side_effect=[{'ready':True},{'callback':'synthetic'},{'callback':'synthetic'},
            {'rejected':True},{'rejected':True},dict.fromkeys(('origins','storage','dom','cors'),True)]
        def handoff(*args,**kwargs):
            if not args[2]:events.append('preflight');return preflight_context
            events.append('access');self.assertEqual(args[2],tokens);self.assertIs(args[3],preflight_context)
            self.assertEqual(kwargs,{'browser_deadline':wire.deadline})
            return {'result':{'protected':True}}
        def credentials(*args):
            events.append('credentials')
            return dict(username=identity['username'],email=identity['email'],password='synthetic-password',ownership_id=state['viewer']['nonce'])
        with patch('playbooks.keycloak.tests.scoped_session.private_context'), \
                patch('playbooks.previews.tests.catalog_fixture.inspect',return_value={'catalog':settings}), \
                patch('playbooks.previews.tests.catalog_fixture.verified_pull',side_effect=lambda api,receipt,*args:
                      fixtures.pull(next(row for row in rows if row['pullRequest']==receipt['number']))), \
                patch('playbooks.previews.files.github.GitHub.blob',side_effect=lambda reader,row:contract.canonical(row['definition'])), \
                patch('playbooks.access.files.verify.remote',return_value=runtime),patch.object(proof,'bindings',return_value=(rows,'100.64.0.1')), \
                patch.object(proof,'active'),patch.object(proof.time,'time',return_value=1200), \
                patch('playbooks.previews.tests.probe_transport.handoff',side_effect=handoff), \
                patch('playbooks.access.files.traffic.https',return_value={'status':200,'body':b'{"callback":true}'}), \
                patch('playbooks.secrets.files.vault.fields',side_effect=credentials),patch('playbooks.keycloak.files.health.json_get',return_value={}), \
                patch.object(proof.socket,'create_connection'),patch.object(proof,'Channel',return_value=wire), \
                patch.object(proof,'callback',return_value='synthetic-code'),patch.object(proof,'claims',side_effect=tokens), \
                patch.object(proof,'protected'):
            result=proof.run({'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'},state,lambda *args:identity,lambda:None)
        self.assertEqual(events,['preflight','credentials','access'])
        for token in tokens:
            self.assertNotIn(token,str(wire.send.call_args_list));self.assertNotIn(token,json.dumps(result))
