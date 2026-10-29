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
    def expired_orphan_proposal(self, batch='cd'):
        api=fixtures.CatalogGit();state=fixtures.orphan_pair(api,batch)
        values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        with patch.object(approval.time,'time',return_value=1200):
            approval.catalog_prepare(api,values,state,Mock(),batch,'orphan-'+batch[-1])
            approval.propose(api,values,state,Mock())
        state.update(viewer={'nonce':state['nonce'],'realm':'applications'},baseline={},
                     intent={'action':'catalog-review','slot':None})
        api.writes.clear()
        return api,state,values

    def test_catalog_abandon_local_and_remote_negatives_never_close_or_delete(self):
        cases=('intent','slot','mode','batch','stage','unexpired','malformed','ref-rejected','pull-rejected',
               'ref-created','pull-intent','head','body','bytes','parent','repository','foreign','merged')
        for case in cases:
            with self.subTest(case=case):
                api,state,values=self.expired_orphan_proposal();record=state['catalogProposals'][-1]
                if case=='intent':state['intent']={'action':'catalog-merge','slot':None}
                elif case=='mode':record['mode']='approve'
                elif case=='batch':record['batch']='ab'
                elif case=='stage':record['stage']='merging'
                elif case=='malformed':state['approvals']['d']['row']['expiresAt']=True
                elif case=='ref-rejected':record['refRejected']=422
                elif case=='pull-rejected':record['pullRejected']=422
                elif case=='ref-created':record['refCreated']=False
                elif case=='pull-intent':record['pullIntent']=False
                elif case=='head':api.head='f'*40
                elif case=='body':api.pull_body+=' changed'
                elif case=='bytes':api.documents[api.head]=b'{"changed":true}'
                elif case=='parent':api.commits[api.head]['parents']=[{'sha':'f'*40}]
                elif case=='repository':record['source']['nodeId']='foreign'
                elif case=='merged':api.merged=True
                request=api.request
                def foreign(method,path,body=None,**kwargs):
                    result=request(method,path,body,**kwargs)
                    if case=='foreign' and '/pulls?state=all' in path:return result+[dict(result[0],number=99)]
                    return result
                save=Mock()
                with patch.object(approval.time,'time',return_value=1200 if case=='unexpired' else 3000), \
                        patch.object(api,'request',side_effect=foreign),patch.object(live.session,'private_context') as context:
                    context.return_value.__enter__.return_value=api
                    with self.assertRaises(ValueError):live.execute('catalog-abandon',values,state,save,'d' if case=='slot' else None)
                self.assertEqual(api.writes,[]);self.assertNotIn('cancellation',record)
                self.assertEqual(state['intent'],{'action':'catalog-merge' if case=='intent' else 'catalog-review','slot':None})

    def test_catalog_cancellation_durable_intents_lost_replies_and_global_guard(self):
        for failure in ('before-close','close','delete'):
            with self.subTest(failure=failure):
                api,state,values=self.expired_orphan_proposal();saved=[]
                def save():saved.append(copy.deepcopy(state))
                request=api.request;first=[True]
                def boundary(method,path,body=None,**kwargs):
                    if method in ('PATCH','POST'):
                        self.assertEqual(saved[-1]['intent'],{'action':'catalog-abandon','slot':None})
                        self.assertEqual(saved[-1]['catalogProposals'][-1]['cancellation']['prior'],{'action':'catalog-review','slot':None})
                        self.assertTrue(saved[-1]['catalogProposals'][-1]['closeIntent'])
                        if path=='graphql':self.assertTrue(saved[-1]['catalogProposals'][-1]['deleteIntent'])
                    if failure=='before-close' and method=='PATCH' and first[0]:first[0]=False;raise RuntimeError('synthetic interruption')
                    return request(method,path,body,**kwargs)
                api.fail=failure if failure!='before-close' else None
                with patch.object(approval.time,'time',return_value=3000),patch.object(api,'request',side_effect=boundary):
                    with self.assertRaises(RuntimeError):approval.abandon_catalog(api,values,state,save)
                    # Resume a real serialized cancellation, preserving original proposal binding.
                    state=json.loads(json.dumps(state));approval.abandon_catalog(api,values,state,save)
                    self.assertIsNone(state['intent']);self.assertTrue(state['catalogProposals'][-1]['catalogAbandoned'])
                    self.assertIsNone(api.head);self.assertFalse(api.merged)
                    with self.assertRaisesRegex(ValueError,'execution must be absent'):
                        approval.retire_proposals(api,values,state,save)
                    state['evidence']={key:{'cleanupOnlyAbsent':True} for key in approval.rows(state)}
                    approval.catalog_prepare(api,values,state,save,'cd','cleanup')
                    self.assertEqual(len(state['catalogProposals']),2)
                    self.assertEqual(state['catalogProposals'][0]['stage'],'abandoned')
                    self.assertEqual(state['catalogProposals'][1]['stage'],'prepared')

    def test_catalog_cancellation_close_and_cas_races_quarantine_branch(self):
        for race in ('head','merge','delete'):
            with self.subTest(race=race):
                api,state,values=self.expired_orphan_proposal();request=api.request
                def boundary(method,path,body=None,**kwargs):
                    if race=='delete' and path=='graphql':api.head='f'*40
                    result=request(method,path,body,**kwargs)
                    if method=='PATCH':
                        if race=='head':api.head='f'*40
                        elif race=='merge':api.merged=True
                    return result
                with patch.object(approval.time,'time',return_value=3000),patch.object(api,'request',side_effect=boundary):
                    with self.assertRaises((ValueError,RuntimeError)):approval.abandon_catalog(api,values,state,Mock())
                self.assertIsNotNone(api.head);self.assertNotIn('catalogAbandoned',state['catalogProposals'][-1])
                self.assertEqual(state['intent'],{'action':'catalog-abandon','slot':None})
                if race!='delete':self.assertFalse(any(path=='graphql' for _,path,_ in api.writes))

    def test_cancellation_binds_original_browser_source_and_keeps_later_proposals_independent(self):
        api,state,values=self.expired_orphan_proposal('ab')
        original=copy.deepcopy(state)
        state['executionPlatform']='f'*40
        with patch.object(approval.time,'time',return_value=3000):
            approval.abandon_catalog(api,values,state,Mock())
            canceled=copy.deepcopy(state['catalogProposals'][0])
            for key in ('approvals','pulls','browserProof','browserApprovals'):
                self.assertEqual(state[key],original[key])
            for operation in (approval.propose,approval.review,approval.merge,approval.reprepare):
                with self.assertRaises(ValueError):operation(api,values,state,Mock())
            state['intent']={'action':'lifecycle-observe','slot':None}
            with self.assertRaises(ValueError):approval.abandon_catalog(api,values,state,Mock())
            self.assertEqual(state['intent'],{'action':'lifecycle-observe','slot':None})
            state['intent']=None
            state['evidence']={key:{'cleanupOnlyAbsent':True} for key in approval.rows(state)}
            approval.catalog_prepare(api,values,state,Mock(),'ab','cleanup')
            self.assertNotIn('cancellation',approval.current(state))
            self.assertEqual(state['catalogProposals'][0],canceled)
            approval.propose(api,values,state,Mock());approval.review(api,values,state,Mock());approval.merge(api,values,state,Mock())
            # A later proposal gets its own cancellation binding, preserving the previous terminal receipt.
            later_api,later,unused=self.expired_orphan_proposal('cd')
            state['approvals'].update(later['approvals']);state['pulls'].update(later['pulls'])
            state['catalogProposals'].append(later['catalogProposals'][-1])
            state['intent']={'action':'catalog-review','slot':None}
            approval.abandon_catalog(later_api,values,state,Mock())
            self.assertEqual(state['catalogProposals'][0],canceled)
            self.assertEqual(state['catalogProposals'][-1]['cancellation']['index'],2)

    def test_fixed_orphan_pairs_preserve_survivor_ownership_and_unrelated_catalog(self):
        values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        for batch in ('ab','cd'):
            with self.subTest(batch=batch),patch.object(approval.time,'time',return_value=1200):
                api=fixtures.CatalogGit();state=fixtures.orphan_pair(api,batch)
                document=json.loads(api.documents[api.main]);original=copy.deepcopy(document['catalog'])
                extra=fixtures.approval('f'*32);extra['repository']='example/private'
                original['approvals'].insert(1,extra)
                original['ownership'][contract.names(extra)['namespace']]=extra['instance']+':'+contract.digest(contract.canonical(extra))
                api.documents[api.main]=json.dumps({'catalog':original}).encode()
                saved=copy.deepcopy(state)
                approval.catalog_prepare(api,values,state,Mock(),batch,'orphan-'+batch[-1])
                expected=copy.deepcopy(original)
                victim=state['approvals'][batch[-1]]['row']['instance']
                expected['approvals']=[row for row in original['approvals'] if row['instance']!=victim]
                self.assertEqual(approval.current(state)['document']['catalog'],expected)
                approval.propose(api,values,state,Mock());approval.review(api,values,state,Mock());approval.merge(api,values,state,Mock())
                self.assertEqual(json.loads(api.documents[api.main])['catalog'],expected)
                for key in saved:self.assertEqual(state[key],saved[key],key)

    def test_orphan_b_refuses_missing_failed_mismatched_or_stale_browser_proof_before_writes(self):
        cases=('missing','failed','attempt','platform','instance','digest','callback','audience','origin','authentication',
               'dataplane','dataplane-source','dataplane-digests','saved-binding','crossed','expired','head','branch','definition')
        values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        for case in cases:
            with self.subTest(case=case):
                api=fixtures.CatalogGit();state=fixtures.orphan_pair(api,'ab');proof=state['browserProof']
                if case=='missing':state.pop('browserProof')
                elif case=='failed':state['browserFailed']=True
                elif case=='attempt':state['browserAttempted']=False
                elif case=='platform':state['executionPlatform']='f'*40
                elif case=='instance':proof['approvals']['b']['instance']='f'*32
                elif case=='digest':proof['approvals']['b']['approvalDigest']='f'*64
                elif case in ('callback','audience','origin','authentication'):proof[{'callback':'callbacks','audience':'audiences','origin':'origins'}.get(case,case)]=False
                elif case=='dataplane':proof['dataplane']['result']['targets'][0]['podProtected']=False
                elif case=='dataplane-source':proof['dataplane']['revision']='f'*40
                elif case=='dataplane-digests':proof['dataplane']['digests'].reverse()
                elif case=='saved-binding':state['browserApprovals']['a']['approvalDigest']='f'*64
                elif case=='head':api.source_pulls['repos/example/private/pulls/18']['head']['sha']='f'*40
                elif case=='branch':state['pulls']['b']['branch']+='-foreign'
                elif case=='definition':state['approvals']['b']['row']['definition']['message']='foreign'
                with patch.object(approval.time,'time',return_value=3000 if case=='expired' else 1200),self.assertRaises(ValueError):
                    approval.catalog_prepare(api,values,state,Mock(),'ab','orphan-d' if case=='crossed' else 'orphan-b')
                self.assertEqual(api.writes,[]);self.assertNotIn('catalogProposals',state)

    def test_orphan_b_rechecks_browser_and_source_on_all_publication_stages(self):
        values={'PRIVATE_CONFIG_REPOSITORY':'https://github.com/example/private.git'}
        for operation in (approval.propose,approval.review,approval.merge):
            for failure in ('browser','source'):
                with self.subTest(operation=operation.__name__,failure=failure),patch.object(approval.time,'time',return_value=1200):
                    api=fixtures.CatalogGit();state=fixtures.orphan_pair(api,'ab')
                    approval.catalog_prepare(api,values,state,Mock(),'ab','orphan-b')
                    if operation!=approval.propose:approval.propose(api,values,state,Mock())
                    if operation==approval.merge:approval.review(api,values,state,Mock())
                    if failure=='browser':state['browserProof']['audiences']=False
                    else:api.source_pulls['repos/example/private/pulls/18']['head']['sha']='f'*40
                    writes=copy.deepcopy(api.writes)
                    with self.assertRaises(ValueError):operation(api,values,state,Mock())
                    self.assertEqual(api.writes,writes)

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
                patch.object(live,'host_readiness'),patch.object(live,'dotenv_values',return_value=values),patch.object(live,'remote',return_value=state['identity']), \
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
                        patch.object(live, 'host_readiness'),patch.object(live, 'dotenv_values', return_value=values), patch.object(live, 'remote', return_value=state['identity']), \
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

    def test_cleanup_only_absence_removes_owned_catalog_but_never_becomes_acceptance(self):
        api = fixtures.CatalogGit(); state = self.proposal(api)
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        api.documents[api.main] = json.dumps({'catalog': fixtures.catalog(list(approval.rows(state).values()))}).encode()
        observed = {'entries': {instance: {'approvalDigest': contract.digest(contract.canonical(row)),
            'observedAt': 3000, 'phase': 'retired', 'identityPhase': 'retired', 'uids': {},
            'active': False, 'disabled': False, 'absent': False, 'cleanupOnlyAbsent': True}
            for instance, row in approval.rows(state).items()}}
        approval.remember(state, observed, Mock())
        for evidence in state['evidence'].values():
            self.assertNotIn('active', evidence); self.assertNotIn('disabled', evidence); self.assertNotIn('absent', evidence)
            self.assertTrue(evidence['cleanupOnlyAbsent'])
        with self.assertRaises(ValueError): approval.catalog_prepare(api, values, state, Mock(), 'ab', 'approve')
        state.update(enrolled=True, identity={'enabled': True})
        with self.assertRaisesRegex(ValueError, 'Prior preview pair'):
            approval.prepare(values, state, Mock(), 'cd', 600)
        approval.catalog_prepare(api, values, state, Mock(), 'ab', 'cleanup')
        document = approval.current(state)['document']['catalog']
        self.assertEqual(document['approvals'], []); self.assertEqual(document['ownership'], {})
        with self.assertRaises(ValueError):
            approval.remember({'approvals': state['approvals']}, {'entries': {
                instance: dict(value, absent=True) for instance, value in observed['entries'].items()}}, Mock())

    def test_orphan_d_native_prepare_reprepare_review_merge_preserves_c_and_unrelated_state(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        api = fixtures.CatalogGit(); state = fixtures.orphan_pair(api)
        original = json.loads(api.documents[api.main])['catalog']
        unrelated = fixtures.approval('f'*32)
        unrelated['repository'] = 'example/private'
        original['approvals'].insert(1, unrelated)
        original['ownership'][contract.names(unrelated)['namespace']] = unrelated['instance'] + ':' + contract.digest(contract.canonical(unrelated))
        original['artifacts']['ghcr.io/example/app'] = {'public': True, 'sourceRepository': 'example/platform',
            'issuer': 'https://token.actions.githubusercontent.com',
            'subject': 'https://github.com/example/platform/.github/workflows/build.yml@refs/heads/main'}
        api.documents[api.main] = json.dumps({'catalog': original}).encode()
        saved = copy.deepcopy(state)
        with patch.object(approval.time, 'time', return_value=1200):
            approval.catalog_prepare(api, values, state, Mock(), 'cd', 'orphan-d')
            old = approval.current(state)
            expected = copy.deepcopy(original)
            expected['approvals'] = [row for row in original['approvals'] if row['instance'] != 'd'*32]
            self.assertEqual(old['document']['catalog'], expected)
            api.main = 'f'*40; api.documents[api.main] = api.documents['1'*40]
            approval.reprepare(api, values, state, Mock())
        self.assertEqual(old['stage'], 'abandoned')
        with patch.object(approval.time, 'time', return_value=1200):
            approval.propose(api, values, state, Mock()); approval.review(api, values, state, Mock()); approval.merge(api, values, state, Mock())
        self.assertEqual(json.loads(api.documents[api.main])['catalog'], expected)
        self.assertEqual(state['approvals'], saved['approvals']); self.assertEqual(state['pulls'], saved['pulls'])
        # The existing pair withdrawal still removes both approvals and retains ownership.
        api = fixtures.CatalogGit(); state = fixtures.orphan_pair(api)
        approval.catalog_prepare(api, values, state, Mock(), 'cd', 'withdraw')
        withdrawn = approval.current(state)['document']['catalog']
        self.assertEqual(withdrawn['approvals'], []); self.assertEqual(len(withdrawn['ownership']), 2)

    def test_orphan_d_refuses_catalog_and_remote_source_drift_without_writes(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        for change in ('c-row', 'c-ownership', 'd-missing', 'd-ownership', 'head', 'repository', 'expired'):
            with self.subTest(change=change):
                api = fixtures.CatalogGit(); state = fixtures.orphan_pair(api)
                settings = json.loads(api.documents[api.main])['catalog']
                if change == 'c-row':
                    settings['approvals'][0]['expiresAt'] += 1
                    settings['ownership']['cloudlab-preview-'+'c'*32] = 'c'*32 + ':' + contract.digest(contract.canonical(settings['approvals'][0]))
                elif change == 'c-ownership': settings['ownership'].pop('cloudlab-preview-'+'c'*32)
                elif change == 'd-missing': settings['approvals'].pop()
                elif change == 'd-ownership': settings['ownership'].pop('cloudlab-preview-'+'d'*32)
                elif change == 'head': api.source_pulls['repos/example/private/pulls/18']['head']['sha'] = 'f'*40
                elif change == 'repository': values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/foreign/private.git'}
                api.documents[api.main] = json.dumps({'catalog': settings}).encode()
                save = Mock()
                with patch.object(approval.time, 'time', return_value=2000 if change == 'expired' else 1200), self.assertRaises(ValueError):
                    approval.catalog_prepare(api, values, state, save, 'cd', 'orphan-d')
                self.assertEqual(api.writes, []); save.assert_not_called(); self.assertNotIn('catalogProposals', state)
                values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}

    def test_orphan_d_rechecks_exact_source_before_publication_and_merge(self):
        values = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}
        for operation in (approval.propose, approval.review, approval.merge):
            with self.subTest(operation=operation.__name__), patch.object(approval.time, 'time', return_value=1200):
                api = fixtures.CatalogGit(); state = fixtures.orphan_pair(api)
                approval.catalog_prepare(api, values, state, Mock(), 'cd', 'orphan-d')
                if operation != approval.propose: approval.propose(api, values, state, Mock())
                if operation == approval.merge: approval.review(api, values, state, Mock())
                api.source_pulls['repos/example/private/pulls/18']['head']['sha'] = 'f'*40
                writes = copy.deepcopy(api.writes); before = copy.deepcopy(state); save = Mock()
                with self.assertRaises(ValueError): operation(api, values, state, save)
                self.assertEqual(api.writes, writes); self.assertEqual(state, before); save.assert_not_called()

    def test_existing_baseline_is_subset_and_foreign_identity_loss_fails(self):
        baseline={'persistent':{'apps':{'identities':{'one':'uid'}}},'clients':{'applications':{'identities':{'one':'uuid'}}}}
        state={'baseline':{'cluster':baseline}}; observed=copy.deepcopy(baseline)
        observed['persistent']['apps']['identities']['new']='known-addition'
        approval.preserve_baseline(state,observed)
        observed['clients']['applications']['identities']['one']='foreign'
        with self.assertRaises(ValueError): approval.preserve_baseline(state,observed)
