"""Offline safety checks for the disposable native controller fixture."""
import functools
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import subprocess
import sys
import time
import urllib.error
import urllib.request

import yaml

import permissions_proof as proof


class SourceBoundaryTests(unittest.TestCase):
    def test_active_operation_conflict_rebuilds_from_fresh_object_before_named_denial(self):
        import copy
        current = {'metadata': {'uid': 'child', 'resourceVersion': '1'}, 'spec': {'source': {'targetRevision': 'b' * 40}},
            'operation': {'sync': {'revision': 'a' * 40}}, 'status': {'operationState': {'phase': 'Running', 'retryCount': 1}}}
        latest = copy.deepcopy(current)
        latest['metadata']['resourceVersion'] = '2'
        latest['status']['operationState']['retryCount'] = 2
        identity = {'uid': 'child', 'spec': copy.deepcopy(current['spec']), 'operation': copy.deepcopy(current['operation'])}
        denial = {'reason': 'Invalid', 'message': "ValidatingAdmissionPolicy 'cloudlab-permissions-input' with binding 'cloudlab-permissions-input' denied request: Only the native application controller can clear an existing permission operation."}
        fetch, submit = Mock(side_effect=[current, latest]), Mock(side_effect=[(409, {'reason': 'Conflict'}), (422, denial)])
        conflicts = []
        code, body = proof.probe_active_operation(fetch, submit, lambda row: row.pop('operation'), identity,
            conflicts.append, 30, clock=lambda: 0, pause=Mock())
        self.assertEqual((code, body), (422, denial))
        self.assertEqual([call.args[0]['metadata']['resourceVersion'] for call in submit.call_args_list], ['1', '2'])
        self.assertEqual(submit.call_args_list[1].args[0]['status']['operationState']['retryCount'], 2)
        self.assertNotIn('operation', submit.call_args.args[0])
        self.assertIn('operation', current)
        self.assertIn('operation', latest)
        self.assertEqual([row['code'] for row in conflicts], [409])

    def test_active_operation_probe_rejects_identity_spec_command_and_activity_drift(self):
        import copy
        current = {'metadata': {'uid': 'child'}, 'spec': {'source': {'targetRevision': 'b' * 40}},
            'operation': {'sync': {'revision': 'a' * 40}}, 'status': {'operationState': {'phase': 'Running', 'retryCount': 1}}}
        identity = {'uid': 'child', 'spec': copy.deepcopy(current['spec']), 'operation': copy.deepcopy(current['operation'])}
        for case in ('uid', 'spec', 'operation', 'completed'):
            changed = copy.deepcopy(current)
            if case == 'uid': changed['metadata']['uid'] = 'foreign'
            if case == 'spec': changed['spec']['source']['targetRevision'] = 'c' * 40
            if case == 'operation': changed['operation']['sync']['revision'] = 'c' * 40
            if case == 'completed': changed['status']['operationState']['phase'] = 'Succeeded'
            submit = Mock()
            with self.subTest(case=case), self.assertRaisesRegex(RuntimeError, 'pending command changed'):
                proof.probe_active_operation(lambda: changed, submit, Mock(), identity, Mock(), 30, clock=lambda: 0)
            submit.assert_not_called()

    def test_active_operation_conflicts_exhaust_and_unrelated_errors_never_retry(self):
        current = {'metadata': {'uid': 'child'}, 'spec': {}, 'operation': {'sync': {}},
            'status': {'operationState': {'phase': 'Running', 'retryCount': 1}}}
        identity = {'uid': 'child', 'spec': {}, 'operation': {'sync': {}}}
        submit, conflicts = Mock(return_value=(409, {'reason': 'Conflict'})), []
        with self.assertRaisesRegex(RuntimeError, 'exhausted'):
            proof.probe_active_operation(lambda: current, submit, Mock(), identity, conflicts.append, 30, clock=lambda: 0, pause=Mock())
        self.assertEqual(submit.call_count, 5)
        self.assertEqual(len(conflicts), 5)
        submit = Mock(return_value=(403, {'reason': 'Forbidden'}))
        with self.assertRaisesRegex(RuntimeError, 'Unexpected'):
            proof.probe_active_operation(lambda: current, submit, Mock(), identity, Mock(), 30, clock=lambda: 0)
        self.assertEqual(submit.call_count, 1)
        now = [0]
        def late_denial(row):
            now[0] = 31
            return 422, {'reason': 'Invalid'}
        with self.assertRaisesRegex(RuntimeError, 'bounded deadline'):
            proof.probe_active_operation(lambda: current, late_denial, Mock(), identity, Mock(), 30, clock=lambda: now[0])

    def test_receipt_publication_precedes_profile_and_superseded_proposals_cannot_advance(self):
        receipt, commitment = proof.consumer_receipt('a' * 40, '1' * 64)
        prepared = {'revision': 'a' * 40, 'receipt': receipt, 'commitment': commitment}
        events = []
        def commit(files):
            self.assertEqual(list(files), ['platform/acceptance/permissions.yaml'])
            self.assertTrue(yaml.safe_load(next(iter(files.values()))) == receipt)
            events.append('commit')
            return 'b' * 40
        result = proof.publish_profile_approval(prepared, commit, lambda: events.append('profile'), events.append)
        self.assertEqual(events, ['commit', 'receipt-published', 'profile', 'profile-prepared'])
        self.assertEqual(result['proposalRevision'], 'b' * 40)
        self.assertEqual(result['revision'], 'a' * 40)
        proof.require_current_proposal(result, 'b' * 40)
        with self.assertRaisesRegex(RuntimeError, 'superseded'):
            proof.require_current_proposal(result, 'c' * 40)

    def test_failed_receipt_publication_cannot_change_profile(self):
        profile, record = Mock(), Mock()
        with self.assertRaises(OSError):
            proof.publish_profile_approval({'receipt': {}, 'revision': 'a' * 40}, Mock(side_effect=OSError()), profile, record)
        profile.assert_not_called()
        record.assert_not_called()

    def test_failure_journal_uses_five_fixed_gets_and_never_copies_sensitive_fields(self):
        import copy
        marker = 'WITHHELD-SYNTHETIC-DIAGNOSTIC'
        gate, commitment = 'gate ' + json.dumps('1' * 64) + marker, '1' * 64
        parent = {'metadata': {'uid': 'parent', 'generation': 2, 'resourceVersion': '3', 'annotations': {'private': marker}},
            'spec': {'generators': [{'matrix': {'generators': [{'git': {'revision': 'main'}}, {'git': {'revision': gate}}]}}]},
            'status': {'conditions': [{'type': 'ErrorOccurred', 'status': 'True', 'reason': marker,
                'message': 'Consumer source acceptance refused ' + marker}]}}
        app = {'metadata': {'uid': 'child'}, 'spec': {'source': {'repoURL': marker, 'targetRevision': 'a' * 40},
            'destination': {'namespace': 'argocd'}}, 'status': {'sync': {'status': 'Synced'}, 'health': {'status': 'Healthy'}}}
        app['status']['sync']['comparedTo'] = {'source': copy.deepcopy(app['spec']['source']), 'destination': copy.deepcopy(app['spec']['destination'])}
        deployment = {'metadata': {'uid': 'repository'}, 'spec': {'template': {'spec': {'containers': [{
            'args': ['repo-server', '--revision-cache-expiration=5s', '--password=' + marker],
            'env': [{'name': 'ARGOCD_RECONCILIATION_TIMEOUT', 'value': marker, 'valueFrom': {
                'configMapKeyRef': {'name': 'argocd-cm', 'key': 'timeout.reconciliation', 'optional': True}}},
                {'name': 'OTHER', 'value': marker}]}]}}}}
        cm = {'metadata': {'uid': 'configuration'}, 'data': {'timeout.reconciliation': '5s', 'timeout.reconciliation.jitter': '0s', 'private': marker}}
        api = Mock()
        api.request.side_effect = [parent, app, copy.deepcopy(app), deployment, cm]
        result = proof.failure_journal(api, {'gate': gate, 'commitment': commitment})
        self.assertEqual([call.args[0] for call in api.request.call_args_list], [proof.PARENT, proof.APPLICATION, proof.PROFILES,
            '/apis/apps/v1/namespaces/argocd/deployments/argocd-repo-server', '/api/v1/namespaces/argocd/configmaps/argocd-cm'])
        self.assertNotIn(marker, json.dumps(result))
        self.assertTrue(result['parent']['gateMatchesPrepared'] and result['parent']['gateContainsPreparedCommitment'])
        self.assertEqual(result['parent']['conditions'][0]['classification'], 'receipt-gate')
        self.assertEqual(result['repository']['timingArgs'], ['--revision-cache-expiration=5s'])
        self.assertEqual(set(result['reconciliation']['settings']), {'timeout.reconciliation', 'timeout.reconciliation.jitter'})
        self.assertTrue(result['roles']['comparedSourceMatches'] and result['roles']['comparedDestinationMatches'])

    def test_failure_journal_errors_never_mask_original_failure_or_retry_gets(self):
        api = Mock()
        api.request.side_effect = OSError('withheld synthetic detail')
        state = {'phase': 'proposal-transition'}
        original = RuntimeError('original fixture failure')
        try:
            raise original
        except RuntimeError:
            proof.record_failure_journal(api, state, {}, Mock(side_effect=OSError()))
            self.assertIs(sys.exception(), original)
        self.assertEqual(api.request.call_count, 5)
        self.assertEqual(state['failureJournalError'], 'OSError')
        self.assertTrue(all(row == {'errorType': 'OSError'} for row in state['failureJournal'].values()))

    def test_initial_projection_dispatch_retries_only_allow_and_records_named_denial(self):
        now, observations = [0], []
        denial = {'reason': 'Invalid', 'message': "ValidatingAdmissionPolicy 'cloudlab-permissions-profiles' with binding 'cloudlab-permissions-profiles' denied request: implicit adoption is refused"}
        probe = Mock(side_effect=[(200, {}), (422, denial)])
        unchanged = Mock()
        proof.qualify_initial_projection(probe, unchanged, observations.append, 30,
            clock=lambda: now[0], pause=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual([row['code'] for row in observations], [200, 422])
        self.assertEqual([row['elapsedSeconds'] for row in observations], [0, 2])
        self.assertTrue(observations[-1]['policyAndBinding'] and observations[-1]['expectedMessage'])
        self.assertEqual(unchanged.call_count, 4)

    def test_initial_projection_dispatch_does_not_retry_other_denials_or_transport_errors(self):
        for response in ((403, {'reason': 'Forbidden'}), (422, {'reason': 'Invalid', 'message': 'unrelated denial'})):
            probe, pause = Mock(return_value=response), Mock()
            observations = []
            with self.subTest(response=response), self.assertRaisesRegex(RuntimeError, 'Unexpected response'):
                proof.qualify_initial_projection(probe, Mock(), observations.append, 30, clock=lambda: 0, pause=pause)
            self.assertEqual(probe.call_count, 1)
            self.assertEqual(len(observations), 1)
            pause.assert_not_called()
        probe = Mock(side_effect=urllib.error.URLError('synthetic transport failure'))
        with self.assertRaises(urllib.error.URLError):
            proof.qualify_initial_projection(probe, Mock(), Mock(), 30, clock=lambda: 0, pause=Mock())
        self.assertEqual(probe.call_count, 1)

    def test_initial_projection_dispatch_stops_immediately_on_identity_drift(self):
        probe, pause, record = Mock(return_value=(200, {})), Mock(), Mock()
        unchanged = Mock(side_effect=[None, RuntimeError('identity drift')])
        with self.assertRaisesRegex(RuntimeError, 'identity drift'):
            proof.qualify_initial_projection(probe, unchanged, record, 30, clock=lambda: 0, pause=pause)
        self.assertEqual(probe.call_count, 1)
        record.assert_called_once()
        pause.assert_not_called()

    def test_initial_projection_dispatch_persistent_allow_exhausts_bounded_deadline(self):
        now, observations = [0], []
        probe = Mock(return_value=(200, {}))
        with self.assertRaisesRegex(RuntimeError, 'bounded deadline'):
            proof.qualify_initial_projection(probe, Mock(), observations.append, 30,
                clock=lambda: now[0], pause=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(now[0], 30)
        self.assertEqual(len(observations), 15)
        self.assertEqual(probe.call_count, 15)

    def test_initial_projection_dispatch_rejects_denial_returned_after_deadline(self):
        now, observations = [0], []
        def late_denial():
            now[0] = 31
            return 422, {'reason': 'Invalid', 'message': "ValidatingAdmissionPolicy 'cloudlab-permissions-profiles' with binding 'cloudlab-permissions-profiles' denied request: implicit adoption is refused"}
        unchanged = Mock()
        with self.assertRaisesRegex(RuntimeError, 'bounded deadline'):
            proof.qualify_initial_projection(late_denial, unchanged, observations.append, 30, clock=lambda: now[0], pause=Mock())
        self.assertEqual(unchanged.call_count, 2)
        self.assertEqual(observations[0]['elapsedSeconds'], 31)

    def test_real_public_projection_render_uses_canonical_context_and_catalog(self):
        context = {'repository': proof.SOURCE + 'public.git', 'revision': 'a' * 40, 'commitment': '1' * 64, 'namespace': 'argocd'}
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            chart = directory / 'chart'
            for name, raw in proof.catalog_files().items():
                path = chart / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(raw)
            projection = proof.render_projection(directory, chart, {'mode': 'profiles', 'context': context})
        self.assertEqual(projection['kind'], 'ConfigMap')
        self.assertEqual(projection['metadata']['name'], 'cloudlab-permissions-profiles')
        self.assertEqual(projection['data']['viewer.namespace'], 'true')
        for key, value in context.items():
            self.assertEqual(projection['data'][key], value)

    def test_git_http_exposes_only_bare_sources_without_write_or_path_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            public = proof.GitSource(root, 'public', {'chart/' + name: value for name, value in proof.catalog_files().items()})
            proof.GitSource(root, 'private', {'permissions.yaml': proof.values()})
            (root / 'private-key').write_text('synthetic-private-material')
            (root / 'public.git/escape').symlink_to(root / 'private-key')
            server = proof.GitServer(('127.0.0.1', 0),
                functools.partial(proof.ReadOnlyGit, directory=str(root)))
            server.block_private = False
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            url = 'http://127.0.0.1:' + str(server.server_port)
            try:
                clone = root / 'clone'
                proof.command(['git', 'clone', '--branch', 'main', url + '/public.git', str(clone)])
                self.assertEqual(proof.command(['git', 'rev-parse', 'HEAD'], clone).strip(), public.revision)
                public.commit({'new.yaml': 'synthetic: true\n'})
                proof.command(['git', 'fetch', 'origin', 'main'], clone)
                self.assertEqual(proof.command(['git', 'rev-parse', 'FETCH_HEAD'], clone).strip(), public.revision)
                for path in ('/private-key', '/public.git/../private-key', '/public.git/%2e%2e/private-key',
                             '/public.git/escape', '/public.git/', '/public.git/git-receive-pack',
                             '/public.git/info/refs?service=git-receive-pack', '/public.git/HEAD'):
                    with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError):
                        urllib.request.urlopen(url + path)
                for headers in ({'Content-Type': 'application/x-git-upload-pack-request', 'Content-Length': '1048577'},
                                {'Content-Type': 'application/x-git-upload-pack-request', 'Content-Encoding': 'gzip'},
                                {'Content-Type': 'application/x-git-upload-pack-request', 'Transfer-Encoding': 'chunked'},
                                {'Content-Type': 'application/json'}):
                    with self.subTest(headers=headers), self.assertRaises(urllib.error.HTTPError):
                        urllib.request.urlopen(urllib.request.Request(url + '/public.git/git-upload-pack',
                                                                       data=b'write', headers=headers))
            finally:
                server.shutdown()
                server.server_close()
                thread.join()

    def test_backend_timeout_and_output_cap_kill_owned_process(self):
        popen = subprocess.Popen
        for program, timeout in [('import time; time.sleep(10)', 0.05), ('import sys; sys.stdout.buffer.write(b"x" * 5000000)', 2)]:
            created = []
            def start(*args, **kwargs):
                process = popen([sys.executable, '-c', program], **kwargs)
                created.append(process)
                return process
            with self.subTest(program=program), patch.object(proof.subprocess, 'Popen', side_effect=start):
                with self.assertRaises(RuntimeError): proof.git_backend(b'', {'PATH': '/usr/bin:/bin'}, timeout)
                self.assertIsNotNone(created[0].poll())

    def test_backend_keeps_leader_unreaped_until_owned_group_cleanup(self):
        popen = subprocess.Popen
        killpg = proof.os.killpg
        calls = []
        def start(*args, **kwargs):
            process = popen([sys.executable, '-c', 'pass'], **kwargs)
            original_wait = process.wait
            def wait(*args, **kwargs):
                calls.append('reap')
                return original_wait(*args, **kwargs)
            process.wait = wait
            return process
        def kill(*args):
            calls.append('group-cleanup')
            return killpg(*args)
        with patch.object(proof.subprocess, 'Popen', side_effect=start), patch.object(proof.os, 'killpg', side_effect=kill):
            self.assertEqual(proof.git_backend(b'', {'PATH': '/usr/bin:/bin'}), b'')
        self.assertEqual(calls, ['group-cleanup', 'reap'])

    def test_native_git_transport_reads_exact_committed_chart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = proof.GitSource(root, 'public', {'chart/' + name: value for name, value in proof.catalog_files().items()})
            self.assertEqual(len(source.revision), 40)
            for name, value in proof.catalog_files().items():
                actual = proof.command(['git', '--git-dir', str(source.bare), 'show', source.revision + ':chart/' + name])
                self.assertEqual(actual, value)
            with self.assertRaises(RuntimeError): source.commit({'../escape': 'unsafe'})

    def test_chart_modes_separate_public_projection_from_binding_rendering(self):
        # Native admission owns private semantics; Helm validates public profiles.
        rows = self.render_catalog({'mode': 'profiles', 'context': {'repository': 'https://github.com/example/public.git',
            'revision': 'a' * 40, 'commitment': '1' * 64, 'namespace': 'argocd'}})
        self.assertEqual([row['kind'] for row in rows], ['ConfigMap'])
        self.assertEqual(rows[0]['data']['inputVersion'], 'cloudlab-permissions-input/v2')
        self.assertEqual(rows[0]['data']['viewer.namespace'], 'true')
        self.assertEqual(rows[0]['data']['viewer.cluster'], 'false')
        self.assertEqual(rows[0]['data']['commitment'], '1' * 64)
        rows = self.render_catalog(proof.values(assignments=False, state='retired'))
        self.assertTrue(rows)
        self.assertTrue(all(row['kind'] == 'ClusterRole' for row in rows))

    def render_catalog(self, values, files=None, success=True):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in (files or proof.catalog_files()).items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(value)
            path = root / 'input.yaml'
            path.write_text(values if isinstance(values, str) else yaml.safe_dump(values))
            if not success:
                with self.assertRaises(RuntimeError): proof.command(['helm', 'template', 'fixture', str(root), '-f', str(path)])
                return []
            return [row for row in yaml.safe_load_all(proof.command(['helm', 'template', 'fixture', str(root), '-f', str(path)])) if row]

    def test_exact_namespace_and_cluster_assignments_keep_rule_sets_separate(self):
        rows = self.render_catalog(proof.values(cluster=True))
        bindings = [row for row in rows if row['kind'].endswith('Binding')]
        self.assertEqual({row['kind'] for row in bindings}, {'RoleBinding', 'ClusterRoleBinding'})
        namespace = next(row for row in bindings if row['kind'] == 'RoleBinding')
        cluster = next(row for row in bindings if row['kind'] == 'ClusterRoleBinding')
        self.assertEqual(namespace['metadata']['namespace'], proof.NAMESPACE)
        self.assertTrue(namespace['roleRef']['name'].endswith('-namespace'))
        self.assertTrue(cluster['roleRef']['name'].endswith('-cluster'))
        self.assertNotIn('namespace', cluster['metadata'])
        roles = {row['metadata']['name']: row['rules'] for row in rows if row['kind'] == 'ClusterRole'}
        self.assertEqual(roles[cluster['roleRef']['name']], [{'apiGroups': [''], 'resources': ['nodes'], 'verbs': ['get', 'list']}])

    def test_chart_rejects_profile_overrides_and_unsupported_trusted_modes(self):
        original = yaml.safe_load(proof.values())
        for change in ({'profiles': {}}, {'mode': 'untrusted'}):
            with self.subTest(change=change): self.render_catalog(original | change, success=False)

    def test_presets_have_no_implicit_grants_or_sensitive_runtime_verbs(self):
        rows = self.render_catalog(proof.values(assignments=False))
        self.assertTrue(all(row['kind'] == 'ClusterRole' for row in rows))
        forbidden = {'*', 'secrets', 'configmaps', 'pods/log', 'pods/exec', 'pods/attach', 'pods/proxy'}
        for row in rows:
            for rule in row['rules']:
                self.assertEqual(rule['verbs'], ['get', 'list'])
                self.assertFalse(set(rule['resources']) & forbidden)

    def test_entire_public_profile_document_is_validated_even_if_unassigned(self):
        files = proof.catalog_files()
        profiles = yaml.safe_load(files['profiles.yaml'])
        profiles['profiles']['unassigned'] = {'namespaceRules': [{'apiGroups': [''], 'resources': ['pods'],
            'verbs': ['get'], 'aggregationRule': {}}], 'clusterRules': []}
        self.render_catalog(proof.values(assignments=False), files | {'profiles.yaml': yaml.safe_dump(profiles)}, success=False)

    def test_source_convergence_requires_full_values_destination_and_idle_current_health(self):
        import copy
        source = {'repoURL': 'fixture', 'targetRevision': 'a' * 40, 'helm': {'valuesObject': {'permissions': {'state': 'active', 'assignments': []}}}}
        destination = {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
        app = {'spec': {'source': source, 'destination': destination}, 'status': {
            'sync': {'status': 'Synced', 'revision': 'a' * 40, 'comparedTo': {'source': copy.deepcopy(source), 'destination': copy.deepcopy(destination)}},
            'health': {'status': 'Healthy'}, 'operationState': {'phase': 'Succeeded'}}}
        self.assertTrue(proof.source_converged(app, source))
        for case in ('values', 'destination', 'revision', 'error', 'operation'):
            changed = copy.deepcopy(app)
            if case == 'values': changed['status']['sync']['comparedTo']['source']['helm']['valuesObject']['permissions']['state'] = 'retired'
            if case == 'destination': changed['status']['sync']['comparedTo']['destination']['namespace'] = 'other'
            if case == 'revision': changed['status']['sync']['revision'] = 'b' * 40
            if case == 'error': changed['status']['conditions'] = [{'type': 'ComparisonError'}]
            if case == 'operation': changed['operation'] = {'sync': {}}
            with self.subTest(case=case): self.assertFalse(proof.source_converged(changed, source))

    def test_existing_native_api_creates_namespaced_application_sets(self):
        api = object.__new__(proof.API)
        api.field_manager = 'fixture'
        api.absent = Mock(return_value=True)
        api.request = Mock(return_value={'metadata': {'uid': 'parent'}})
        obj = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'metadata': {'name': 'cloudlab-permissions'}, 'spec': {}}
        api.apply(obj)
        self.assertEqual(api.request.call_args.args[:2], (
            '/apis/argoproj.io/v1alpha1/namespaces/argocd/applicationsets/cloudlab-permissions?fieldManager=fixture&force=false', 'PATCH'))
        self.assertEqual(api.request.call_args.kwargs['expected'], 201)

    def test_actual_root_transport_fixture_keeps_the_exact_consumer_gate(self):
        receipt, commitment = proof.consumer_receipt('b' * 40, '1' * 64)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            rows, record = proof.rendered_owner(root, 'a' * 40, commitment)
            parent = next(row for row in rows if row['kind'] == 'ApplicationSet')
            generators = parent['spec']['generators'][0]['matrix']['generators']
            self.assertTrue(all(row['git']['repoURL'] == proof.SOURCE + 'private.git' and row['git']['requeueAfterSeconds'] == 2 for row in generators))
            gate = generators[1]['git']['revision']
            self.assertIn(proof.PRIVATE_COORDINATE, gate)
            self.assertNotIn(proof.SOURCE + 'private.git', gate)
            self.assertNotEqual(record['rawSelectedSHA256'], record['fixtureSelectedSHA256'])
            chart = root / 'gate'
            (chart / 'templates').mkdir(parents=True)
            (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: gate-fixture\nversion: 1.0.0\n')
            (chart / 'templates/gate.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: gate}\ndata:\n  revision: {{ tpl .Values.gate .Values.params | quote }}\n')
            values = root / 'gate-input.yaml'
            values.write_text(yaml.safe_dump({'gate': gate, 'params': receipt | {'path': {}}}))
            rendered = proof.command(['helm', 'template', 'gate', str(chart), '-f', str(values)])
            self.assertEqual(yaml.safe_load(rendered)['data']['revision'], receipt['revision'])

    def test_processor_changes_preserve_other_arguments_and_refuse_foreign_owners(self):
        import copy
        original = {'metadata': {'uid': 'controller', 'resourceVersion': '1'}, 'spec': {'template': {'spec': {'containers': [{
            'name': 'application-controller', 'args': ['argocd-application-controller', '--operation-processors=10', '--status-processors', '20', '--app-resync-jitter', '0']}]}}}}
        api = Mock()
        api.request.return_value = copy.deepcopy(original)
        journal = {}
        processors = proof.Processors(api, journal, Mock(), Mock())
        processors.set(operation=0)
        patch = api.request.call_args.args[2]
        self.assertEqual(patch[0], {'op': 'test', 'path': '/metadata/uid', 'value': 'controller'})
        self.assertEqual(patch[1], {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '1'})
        self.assertEqual(patch[2], {'op': 'test', 'path': '/spec', 'value': original['spec']})
        self.assertEqual(patch[3]['value']['template']['spec']['containers'][0]['args'], [
            'argocd-application-controller', '--status-processors', '20', '--app-resync-jitter', '0', '--operation-processors=0'])
        self.assertFalse(journal['processorJournal']['restored'])
        api.request.return_value = {'metadata': {'uid': 'controller', 'resourceVersion': '2'}, 'spec': copy.deepcopy(processors.expected)}
        processors.set(status=0, jitter=1)
        patch = api.request.call_args.args[2]
        self.assertEqual(patch[1], {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '2'})
        self.assertEqual(patch[3]['value']['template']['spec']['containers'][0]['args'], [
            'argocd-application-controller', '--operation-processors=10', '--status-processors=0', '--app-resync-jitter=1'])
        held_spec = copy.deepcopy(processors.expected)
        api.request.return_value = {'metadata': {'uid': 'controller', 'resourceVersion': '3'}, 'spec': held_spec}
        processors.set()
        patch = api.request.call_args.args[2]
        self.assertEqual(patch[2], {'op': 'test', 'path': '/spec', 'value': held_spec})
        self.assertEqual(patch[3]['value'], original['spec'])
        self.assertTrue(journal['processorJournal']['restored'])
        api.request.return_value = {'metadata': {'uid': 'foreign', 'resourceVersion': '2'}, 'spec': copy.deepcopy(processors.expected)}
        calls = api.request.call_count
        with self.assertRaisesRegex(RuntimeError, 'owner or specification changed'): processors.set()
        self.assertEqual(api.request.call_count, calls + 1)


if __name__ == '__main__':
    unittest.main()
