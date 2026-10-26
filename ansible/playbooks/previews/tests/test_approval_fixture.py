import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from playbooks.previews.files import command, contract
from playbooks.previews.tests import approval_fixture as approval, catalog_fixture, fixtures, live_acceptance as live


class ApprovalTests(unittest.TestCase):
    def state(self):
        return {'nonce': 'e' * 32, 'viewer': {'nonce': 'e' * 32, 'realm': 'applications'}, 'enrolled': True,
            'identity': {'enabled': True}, 'executionPlatform': 'c' * 40, 'approvals': {},
            'pulls': {slot: {'repository': 'example/private', 'repositoryId': 123, 'head': 'b' * 40, 'number': number,
                'closed': False, 'deleted': False, 'pending': None} for slot, number in (('a', 7), ('b', 8))}}

    def request(self):
        return {'repository': 'example/private', 'pullRequest': 7, 'image': contract.IMAGE,
            'platformRevision': 'c' * 40, 'lifetimeSeconds': 600, 'private': True}

    def test_verified_builder_has_no_clock_randomness_or_writes_and_preserves_default_caller(self):
        row = fixtures.approval(); row.update(repository='example/private', expiresAt=1600)
        api = Mock()
        api.request.return_value = fixtures.pull(row)
        api.blob.return_value = contract.canonical(row['definition'])
        api.allows.return_value = True
        with patch.object(command.time, 'time', side_effect=AssertionError('clock')), \
                patch.object(command.secrets, 'token_hex', side_effect=AssertionError('random')), \
                patch.object(command.Path, 'open', side_effect=AssertionError('write')):
            self.assertEqual(command.verified_row(self.request(), api, instance='a'*32, created_at=1000, verification_time=1100), row)
        api.verified.assert_not_called()
        stream = io.StringIO()
        class Output(io.StringIO):
            def close(self): pass
        stream = Output()
        with patch.object(command.time, 'time', return_value=1000), patch.object(command.secrets, 'token_hex', return_value='a'*32), \
                patch.object(command.Path, 'open', return_value=stream), patch.object(command.Path, 'chmod'):
            result = command.prepare_source(self.request(), api)
        self.assertEqual(json.loads(stream.getvalue()), row)
        self.assertEqual(result['private_output'], '/recovery/preview-approval-'+'a'*32+'.json')
        api.verified.assert_called_once_with(row)
        for created, checked in ((1000, 1600), (1000, 999), (True, 1000)):
            with self.assertRaises(ValueError): command.verified_row(self.request(), api, instance='a'*32, created_at=created, verification_time=checked)

    def test_full_row_saved_before_artifact_and_lost_write_reuses_exact_identity(self):
        state = self.state(); saved = []
        lease = {'token': 'synthetic', 'repository': 'example/private', 'repositoryId': 123,
            'permissions': {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}, 'expiresAt': 5000}
        def builder(request, api, *, instance, created_at, verification_time):
            row = fixtures.approval(instance); row.update(repository=request['repository'], pullRequest=request['pullRequest'],
                createdAt=created_at, expiresAt=created_at+request['lifetimeSeconds'])
            return row
        def before_write(current, record):
            self.assertEqual(saved[-1]['approvals'], current['approvals'])
            self.assertIn('row', saved[-1]['approvals']['a'])
            raise RuntimeError('lost local artifact reply')
        with patch.object(approval.time, 'time', return_value=1000), \
                patch.object(approval.repository_tokens, 'issue', return_value=lease), patch.object(approval.repository_tokens, 'revoke') as revoke, \
                patch.object(catalog_fixture, 'verified_pull', side_effect=lambda api,receipt,*args: fixtures.pull(dict(fixtures.approval(),repository='example/private',pullRequest=receipt['number']))), \
                patch.object(command, 'verified_row', side_effect=builder), patch.object(approval, 'artifact', side_effect=before_write):
            with self.assertRaises(RuntimeError): approval.prepare({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, state, lambda:saved.append(copy.deepcopy(state)), 'ab', 600)
        row = copy.deepcopy(state['approvals']['a']['row'])
        with tempfile.TemporaryDirectory() as directory, patch.object(catalog_fixture, 'JOURNALS', Path(directory)):
            root = Path(directory) / state['nonce']; root.mkdir(mode=0o700)
            approval.artifact(state, state['approvals']['a'])
            approval.artifact(state, state['approvals']['a'])
            target = root / 'approvals' / (row['instance'] + '.json')
            self.assertEqual(json.loads(target.read_text()), row)
            target.write_text('{}')
            with self.assertRaises(ValueError): approval.artifact(state, state['approvals']['a'])
            target.unlink(); target.symlink_to(root / 'foreign')
            with self.assertRaises(ValueError): approval.artifact(state, state['approvals']['a'])
        revoke.assert_called_once()
        with patch.object(approval.repository_tokens, 'issue') as issue:
            with self.assertRaises(ValueError): approval.prepare({'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}, state, Mock(), 'ab', 601)
        issue.assert_not_called()

    def test_actual_cli_journals_pair_before_artifacts_and_retries_without_renewal(self):
        state=self.state(); nonce=state['nonce']
        state.update(format=1,platform='c'*40,baseline={},intent=None)
        for slot, receipt in state['pulls'].items():
            receipt.update(base='1'*40,branch='cloudlab-preview-fixture/'+nonce+'/'+slot)
        lease={'token':'synthetic','repository':'example/private','repositoryId':123,
            'permissions':{'contents':'read','pull_requests':'read','metadata':'read'},'expiresAt':5000}
        reader=Mock(); reader.allows.return_value=True
        def pull(path):
            number=int(path.rsplit('/',1)[1]); slot=next(slot for slot,receipt in state['pulls'].items() if receipt['number']==number)
            row=fixtures.approval(); row.update(repository='example/private',pullRequest=number)
            value=fixtures.pull(row); value['head']['ref']=state['pulls'][slot]['branch'];value['base']['ref']='main'
            return value
        reader.request.side_effect=pull
        reader.blob.return_value=contract.canonical(fixtures.approval()['definition'])
        values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        with tempfile.TemporaryDirectory() as directory,patch.object(catalog_fixture,'JOURNALS',Path(directory)), \
                patch('playbooks.argocd.files.render.committed_payload',return_value={'revision':'c'*40}), \
                patch.object(live,'dotenv_values',return_value=values),patch.object(live,'remote',return_value=state['identity']), \
                patch.object(approval.time,'time',return_value=1000),patch.object(approval.repository_tokens,'issue',return_value=lease), \
                patch.object(approval.repository_tokens,'revoke'),patch('playbooks.previews.files.github.GitHub',return_value=reader):
            path=Path(directory)/nonce/'journal.json';catalog_fixture.journal(path,state)
            original=approval.artifact
            def write(current,record):
                persisted=json.loads(path.read_text())
                self.assertEqual(persisted['approvals'][next(slot for slot,r in current['approvals'].items() if r['instance']==record['instance'])]['row'],record['row'])
                original(current,record)
            with patch.object(approval,'artifact',side_effect=write):
                live.main(['approval-prepare','--nonce',nonce,'--batch','ab','--lifetime','600','--live'])
            first=json.loads(path.read_text());self.assertEqual(len(first['instances']),2);self.assertIsNone(first['intent'])
            with patch.object(approval.time,'time',return_value=1100):
                live.main(['approval-prepare','--nonce',nonce,'--batch','ab','--lifetime','600','--live'])
            second=json.loads(path.read_text());self.assertEqual(second['approvals'],first['approvals'])
            self.assertEqual(set(second['browserApprovals']),{'a','b'})

    def test_catalog_stale_intent_can_only_reprepare_after_actual_base_change(self):
        api=fixtures.CatalogGit();state=self.proposal(api);values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        state.update(viewer={'nonce':'e'*32,'realm':'applications'},baseline={},intent=None)
        with patch.object(approval.time,'time',return_value=1200):approval.catalog_prepare(api,values,state,Mock(),'ab','approve')
        state['intent']={'action':'catalog-propose','slot':None}
        with patch.object(approval.session,'private_context') as context:
            context.return_value.__enter__.return_value=api
            with self.assertRaises(ValueError):live.execute('catalog-reprepare',values,state,Mock())
            api.main='f'*40;api.documents[api.main]=api.documents['1'*40]
            with patch.object(approval.time,'time',return_value=1200):live.execute('catalog-reprepare',values,state,Mock())
        self.assertEqual(len(state['catalogProposals']),2);self.assertIsNone(state['intent'])

    def test_proposal_cleanup_requires_owned_creation_and_exact_current_head(self):
        api=fixtures.CatalogGit();state=self.proposal(api);values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        with patch.object(approval.time,'time',return_value=1200):approval.catalog_prepare(api,values,state,Mock(),'ab','approve')
        approval.propose(api,values,state,Mock());record=approval.current(state)
        state['evidence']={instance:{'absent':True} for instance in approval.rows(state)}
        # Proposal is unmerged: current catalog stays empty; close/delete only our ref.
        api.main='f'*40;api.documents[api.main]=api.documents['1'*40]
        approval.retire_proposals(api,values,state,Mock())
        self.assertEqual(record['stage'],'retired');self.assertIsNone(api.head)
        graphql=[body for method,path,body in api.writes if path=='graphql']
        self.assertEqual(graphql[0]['variables']['input']['refUpdates'][0]['beforeOid'],record['head'])

    def proposal(self, api):
        row = fixtures.approval(); row.update(repository='example/private', expiresAt=3000)
        state = {'nonce': 'e'*32, 'approvals': {'a': {'row': row}, 'b': {'row': dict(row, instance='d'*32, pullRequest=8)}}}
        return state

    def test_native_publication_loss_review_merge_and_exact_proposal_cleanup(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        for failure in ('ref', 'pull', 'merge'):
            api = fixtures.CatalogGit(); state = self.proposal(api); save = Mock()
            with patch.object(approval.time, 'time', return_value=1200): approval.catalog_prepare(api, values, state, save, 'ab', 'approve')
            api.fail = failure
            if failure in ('ref', 'pull'):
                with self.assertRaises(RuntimeError): approval.propose(api, values, state, save)
            approval.propose(api, values, state, save)
            record = approval.current(state)
            self.assertEqual(record['refIntent']['sha'], record['head'])
            with self.assertRaises(ValueError): approval.merge(api, values, state, save)
            approval.review(api, values, state, save)
            if failure == 'merge':
                with self.assertRaises(RuntimeError): approval.merge(api, values, state, save)
            approval.merge(api, values, state, save)
            self.assertEqual(record['stage'], 'merged')
            self.assertTrue(json.loads(api.documents[api.main])['catalog']['privateDiscovery'])

    def test_preexisting_matching_proposal_ref_is_not_adopted(self):
        api = fixtures.CatalogGit(); values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        state = self.proposal(api)
        with patch.object(approval.time, 'time', return_value=1200): approval.catalog_prepare(api, values, state, Mock(), 'ab', 'approve')
        record = approval.current(state); api.head='b'*40
        with self.assertRaises(ValueError): approval.propose(api, values, state, Mock())
        self.assertFalse(any(method != 'GET' for method, _, _ in api.writes))
        self.assertNotIn('refIntent', record)

    def test_definitive_creation_conflicts_never_adopt_or_remove_foreign_resources(self):
        from playbooks.argocd.files.github_setup import GitHub, GitHubHTTPError
        import urllib.error
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        for resource in ('pulls', 'git/refs'):
            with self.subTest(resource=resource):
                api = fixtures.CatalogGit(); state = self.proposal(api)
                with patch.object(approval.time, 'time', return_value=1200):
                    approval.catalog_prepare(api, values, state, Mock(), 'ab', 'approve')
                native = api.request
                transport = GitHub('synthetic-token')
                def conflict(method, path, body=None, missing=False):
                    if method == 'POST' and path == 'repos/example/private/' + resource:
                        if resource == 'git/refs':
                            api.head, api.branch = body['sha'], body['ref'].removeprefix('refs/heads/')
                        else:
                            api.number, api.pull_body = 77, 'Foreign request'
                        with patch.object(transport.opener, 'open', side_effect=urllib.error.HTTPError(
                                'https://api.github.com/fixture', 422, 'synthetic', {}, None)):
                            return transport.request(method, path, body)
                    return native(method, path, body, missing=missing)
                with patch.object(api, 'request', side_effect=conflict):
                    with self.assertRaises(GitHubHTTPError): approval.propose(api, values, state, Mock())
                    record = approval.current(state)
                    self.assertNotIn('number', record)
                    writes, head = copy.deepcopy(api.writes), api.head
                    with self.assertRaises(ValueError): approval.propose(api, values, state, Mock())
                    state['evidence'] = {instance: {'absent': True} for instance in approval.rows(state)}
                    with self.assertRaises(ValueError): approval.retire_proposals(api, values, state, Mock())
                    self.assertEqual(api.head, head)
                    self.assertEqual(api.writes, writes)
                    self.assertFalse(api.closed)
                    if resource == 'pulls': self.assertEqual(api.number, 77)

    def test_lost_pull_reply_requires_saved_marker_and_cleanup_checks_closed_associations(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        api = fixtures.CatalogGit(); state = self.proposal(api)
        with patch.object(approval.time, 'time', return_value=1200):
            approval.catalog_prepare(api, values, state, Mock(), 'ab', 'approve')
        api.fail = 'pull'
        with self.assertRaises(RuntimeError): approval.propose(api, values, state, Mock())
        record = approval.current(state)
        marker = record['pullBody']
        del record['pullBody']
        with self.assertRaises(ValueError): approval.propose(api, values, state, Mock())
        record['pullBody'] = marker
        approval.propose(api, values, state, Mock())
        self.assertEqual(record['pullBody'], marker)
        self.assertEqual(record['number'], 9)
        api.number, api.pull_body, api.closed = 77, 'Foreign request', True
        writes, head = copy.deepcopy(api.writes), api.head
        with self.assertRaises(ValueError): approval.propose(api, values, state, Mock())
        state['evidence'] = {instance: {'absent': True} for instance in approval.rows(state)}
        with self.assertRaises(ValueError): approval.retire_proposals(api, values, state, Mock())
        self.assertEqual(api.head, head); self.assertEqual(api.writes, writes)
        self.assertEqual(record['number'], 9)

    def test_catalog_concurrency_and_retained_authorization_require_real_absence(self):
        api=fixtures.CatalogGit(); state=self.proposal(api); values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        with patch.object(approval.time, 'time', return_value=1200): approval.catalog_prepare(api,values,state,Mock(),'ab','approve')
        old=approval.current(state); api.main='f'*40; api.documents[api.main]=api.documents['1'*40]
        with self.assertRaises(ValueError): approval.propose(api,values,state,Mock())
        with patch.object(approval.time, 'time', return_value=1200): approval.reprepare(api,values,state,Mock())
        self.assertEqual(old['stage'],'abandoned')
        self.assertEqual(approval.current(state)['snapshot']['revision'],'f'*40)
        with self.assertRaises(ValueError): approval.catalog_prepare(api,values,state,Mock(),'ab','cleanup')

    def test_expired_interrupted_cli_preparation_can_only_abandon_into_owned_cleanup(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        for interruption in ('partial', 'full'):
            with self.subTest(interruption=interruption):
                state = self.state(); nonce = state['nonce']; apis = {}
                state.update(format=1, platform='c'*40, baseline={}, intent=None, provisioned=True, staged=True)
                for slot in ('a', 'b'):
                    api = apis[slot] = fixtures.PrivatePreviewGit()
                    receipt = catalog_fixture.pull_receipt(api, 'example/private', nonce, slot)
                    catalog_fixture.commit_pull(api, receipt, nonce, slot, Mock())
                    catalog_fixture.open_pull(api, receipt, nonce, slot, Mock())
                    if slot == 'b': api.number = receipt['number'] = 8
                    state['pulls'][slot] = receipt
                lease = {'token': 'synthetic', 'repository': 'example/private', 'repositoryId': 123,
                    'permissions': {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}, 'expiresAt': 5000}
                reader = Mock(); reader.allows.return_value = True
                def inspect_pull(path):
                    pull = next(api.pull() for api in apis.values() if api.number == int(path.rsplit('/', 1)[1]))
                    for side in ('base', 'head'): pull[side]['repo']['full_name'] = 'example/private'
                    return pull
                reader.request.side_effect = inspect_pull
                reader.blob.return_value = contract.canonical(fixtures.approval()['definition'])
                with tempfile.TemporaryDirectory() as directory, patch.object(catalog_fixture, 'JOURNALS', Path(directory)), \
                        patch('playbooks.argocd.files.render.committed_payload', return_value={'revision': 'c'*40}), \
                        patch.object(live, 'dotenv_values', return_value=values), patch.object(live, 'remote', return_value=state['identity']), \
                        patch.object(approval.time, 'time', return_value=1000), \
                        patch.object(approval.repository_tokens, 'issue', return_value=lease), patch.object(approval.repository_tokens, 'revoke'), \
                        patch('playbooks.previews.files.github.GitHub', return_value=reader):
                    path = Path(directory)/nonce/'journal.json'; catalog_fixture.journal(path, state)
                    args = ['approval-prepare', '--nonce', nonce, '--batch', 'ab', '--lifetime', '600', '--live']
                    original = approval.artifact
                    def interrupt(current, record):
                        original(current, record)
                        if len(current['approvals']) == 2: raise RuntimeError('lost preparation reply')
                    boundary = patch.object(command, 'verified_row', side_effect=RuntimeError('lost verification')) if interruption == 'partial' else patch.object(approval, 'artifact', side_effect=interrupt)
                    with boundary, self.assertRaises(RuntimeError): live.main(args)
                    before = json.loads(path.read_text())
                    self.assertEqual(before['intent']['action'], 'approval-prepare')
                    self.assertEqual(len(before['approvals']), 1 if interruption == 'partial' else 2)
                    with self.assertRaises(ValueError): live.main(['approval-abandon', '--nonce', nonce, '--live'])
                    with patch.object(approval.time, 'time', return_value=2000):
                        with self.assertRaises(ValueError): live.main(args)
                        live.main(['approval-abandon', '--nonce', nonce, '--live'])
                    abandoned = json.loads(path.read_text())
                    self.assertEqual(abandoned['approvals'], before['approvals'])
                    self.assertIsNone(abandoned['intent']); self.assertTrue(abandoned['abandonedPreparation'])
                    for action in ('approval-prepare', 'viewer-provision', 'viewer-enroll', 'browser', 'pr-create', 'pr-advance'):
                        with self.assertRaises(ValueError): live.main([action, '--nonce', nonce, '--slot', 'a', '--live'])
                    abandoned['catalogProposals'] = [{'mode': 'approve'}]
                    for action in ('catalog-propose', 'catalog-review', 'catalog-merge', 'catalog-reprepare'):
                        with self.assertRaises(ValueError): live.execute(action, values, abandoned, Mock())
                    for operation in (approval.propose, approval.review, approval.merge, approval.reprepare):
                        api = Mock()
                        with self.assertRaises(ValueError): operation(api, values, abandoned, Mock())
                        api.request.assert_not_called()
                    with self.assertRaises(ValueError): live.execute('catalog-prepare', values, abandoned, Mock())
                    with patch.object(live.session, 'private_context') as context, patch.object(live, 'publication') as publication:
                        context.return_value.__enter__.return_value = apis['a']
                        live.main(['offboard-propose', '--nonce', nonce, '--live'])
                        self.assertTrue(publication.call_args.kwargs['offboard'])
                        for slot, api in apis.items():
                            context.return_value.__enter__.return_value = api
                            live.main(['pr-cleanup', '--nonce', nonce, '--slot', slot, '--live'])
                            self.assertTrue(api.closed); self.assertIsNone(api.head)
                    after = json.loads(path.read_text())
                    self.assertEqual(after['approvals'], before['approvals'])
                    self.assertNotIn('evidence', after); self.assertNotIn('browserProof', after)
                    self.assertTrue(all(receipt['closed'] and receipt['deleted'] for receipt in after['pulls'].values()))
        for intent in ({'action': 'browser', 'slot': None}, {'action': 'viewer-stage', 'slot': None}):
            state = {'intent': intent}
            with self.assertRaises(ValueError): approval.abandon_preparation(state, Mock())
            self.assertEqual(state['intent'], intent)
        state = {'intent': {'action': 'approval-prepare', 'slot': None, 'batch': 'ab', 'lifetime': 600}}
        approval.abandon_preparation(state, Mock())
        self.assertIsNone(state['intent']); self.assertNotIn('approvals', state)

    def test_retirement_evidence_requires_captured_uuid_real_disable_and_full_grace(self):
        row=fixtures.approval(); state={'approvals':{'a':{'row':row}}}; instance=row['instance']
        value={'approvalDigest':contract.digest(contract.canonical(row)), 'observedAt':1200,
               'active':True,'uids':{'namespace':'n'},'client':{'id':'uuid','enabled':True}}
        approval.remember(state, {'entries':{instance:value}}, Mock())
        disabled=dict(value,active=False,disabled=True,disabledAt=1250,observedAt=1260,client={'id':'uuid','enabled':False})
        approval.remember(state, {'entries':{instance:disabled}}, Mock())
        absent=dict(value,active=False,absent=True,observedAt=1849)
        with self.assertRaises(ValueError): approval.remember(state,{'entries':{instance:absent}},Mock())
        absent['observedAt']=1850
        approval.remember(state,{'entries':{instance:absent}},Mock())
        self.assertTrue(state['evidence'][instance]['absent'])
        with self.assertRaises(ValueError): approval.remember(state,{'entries':{}},Mock())

    def test_existing_baseline_is_subset_and_foreign_identity_loss_fails(self):
        baseline={'persistent':{'apps':{'identities':{'one':'uid'}}},'clients':{'applications':{'identities':{'one':'uuid'}}}}
        state={'baseline':{'cluster':baseline}}; observed=copy.deepcopy(baseline)
        observed['persistent']['apps']['identities']['new']='known-addition'
        approval.preserve_baseline(state,observed)
        observed['clients']['applications']['identities']['one']='foreign'
        with self.assertRaises(ValueError): approval.preserve_baseline(state,observed)
