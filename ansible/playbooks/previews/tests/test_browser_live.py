import copy
import base64
import json
import socket
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from urllib.parse import urlencode

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

from playbooks.previews.tests import browser_live as proof, fixtures, live_acceptance
from playbooks.previews.files import contract


class BrowserTests(unittest.TestCase):
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
                patch.object(proof.time, 'time', return_value=1200), \
                patch('playbooks.secrets.files.vault.fields', side_effect=credentials) as vault, \
                patch('playbooks.keycloak.files.health.json_get', return_value={}), \
                patch.object(proof.socket, 'create_connection', side_effect=connect), \
                patch.object(proof, 'Channel') as channel:
            channel.return_value.send.side_effect = send
            values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
            with self.assertRaises(RuntimeError):
                proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, ['credentials', 'connection', 'begin', 'frame'])
            events.clear()
            with patch.object(proof.time, 'time', return_value=1700):
                with self.assertRaises(ValueError): proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, [])
            self.assertEqual(vault.call_count, 1)
            with patch.object(proof.time, 'time', side_effect=[1200, 1200, 1700]):
                with self.assertRaises(ValueError): proof.run(values, state, lambda *args: identity, lambda: events.append('begin'))
            self.assertEqual(events, ['credentials', 'connection'])
            self.assertEqual(vault.call_count, 2)

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
