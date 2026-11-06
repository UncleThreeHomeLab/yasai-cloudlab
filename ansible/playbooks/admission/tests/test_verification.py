import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import jinja2
import yaml

from playbooks.admission.files import verify
from playbooks.admission.tests.fixtures import namespace as namespace_document


class VerificationTests(unittest.TestCase):
    def test_native_namespace_create_probe_requires_exact_denial_without_settling(self):
        message = verify.namespace_guard_desired()[0]['spec']['validations'][0]['message']
        diagnostic = ("ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native' with binding "
                      "'cloudlab-workload-namespace-native' denied request: " + message)
        with patch.object(verify, 'kube', return_value=subprocess.CompletedProcess([], 1, '', diagnostic)) as kube:
            verify.namespace_guard_create_probe()
            self.assertEqual(kube.call_args.args, ('create', '--dry-run=server', '-f', '-'))
            self.assertEqual(kube.call_args.kwargs['document'], {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
                'name': 'cloudlab-app-native-guard-probe', 'labels': {'cloudlab.io/owner': 'foreign'}}})
        for code, text in ((0, diagnostic), (1, 'unrelated'), (1, diagnostic.replace(message, 'unrelated')),
                           (1, diagnostic.replace("with binding 'cloudlab-workload-namespace-native'", "with binding 'foreign'")),
                           (1, diagnostic.replace("ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native'", "ValidatingAdmissionPolicy 'foreign'"))):
            with self.subTest(code=code, text=text), patch.object(verify, 'kube',
                    side_effect=[subprocess.CompletedProcess([], code, '', text), subprocess.CompletedProcess([], 1, '', diagnostic)]) as kube:
                with self.assertRaises(RuntimeError): verify.namespace_guard_create_probe()
                self.assertEqual(kube.call_count, 1)

    def test_checkout_preload_replaces_stale_composition_code_without_executing_catalog_data(self):
        from playbooks.services import files
        name = 'playbooks.services.files.composition_verify'
        paths = ('/workspace/ansible/playbooks/services/files/composition_verify.py',
                 '/workspace/ansible/playbooks/admission/files/verify.py')
        sources = {paths[0]: "assert __package__ == 'playbooks.services.files'\nassert __file__ == '/opt/cloudlab/playbooks/services/files/composition_verify.py'\nmarker = 'fresh'\n",
                   paths[1]: "from playbooks.services.files import composition_verify\nassert composition_verify.marker == 'fresh'\nimport json,sys\nassert json.load(sys.stdin)['verificationSources'] == 'raise RuntimeError()'\n"}
        playbook = yaml.safe_load((Path(__file__).parents[1] / 'verify.yml').read_text())
        task = next(row for row in playbook[0]['tasks'] if row.get('register') == 'admission_verified')
        script = task['ansible.builtin.command']['argv'][2]
        environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
        environment.filters['to_json'] = json.dumps
        looked_up = []
        def lookup(kind, path):
            self.assertEqual(kind, 'file')
            self.assertIn(path, paths)
            looked_up.append(path)
            return sources[path]
        for broken in (False, True):
            if broken: sources[paths[0]] = 'invalid python source !'
            rendered = environment.from_string(script).render(lookup=lookup)
            stale = types.ModuleType(name)
            stale.marker = 'stale'
            with patch.dict(sys.modules, {name: stale}), patch.object(files, 'composition_verify', stale, create=True), \
                    patch.object(sys, 'stdin', io.StringIO('{"verificationSources":"raise RuntimeError()"}')), \
                    patch.object(sys, 'path', list(sys.path)):
                if broken:
                    with self.assertRaises(SyntaxError): exec(compile(rendered, '<verification-operation>', 'exec'), {})
                else:
                    exec(compile(rendered, '<verification-operation>', 'exec'), {})
        self.assertEqual(looked_up, list(paths) * 2)

    def test_global_composition_guard_requires_native_ready_owner_and_real_dry_run_denial(self):
        policy = {'metadata': {'generation': 1, 'annotations': {
            'argocd.argoproj.io/tracking-id': 'cloudlab-workload-policy:owned'}},
            'status': {'conditionStatus': {'ready': True, 'conditions': [{'status': 'True'}]}},
            'spec': {'validationActions': ['Deny'], 'failurePolicy': 'Fail', 'evaluation': {'admission': {'enabled': True}},
                'matchConstraints': {'resourceRules': [{'apiGroups': [''], 'apiVersions': ['v1'],
                    'operations': ['CREATE', 'UPDATE'], 'resources': ['namespaces']}]}}}
        def get(kind, name): return policy if name == 'cloudlab-composition-namespace' else None
        with patch.object(verify, 'get', side_effect=get), patch.object(verify, 'wait'), patch.object(verify, 'kube',
                return_value=subprocess.CompletedProcess([], 1, '', 'cloudlab-composition-namespace')) as kube:
            verify.composition_guard()
            self.assertIn('--dry-run=server', kube.call_args.args)
            for result in (subprocess.CompletedProcess([], 0, '', ''), subprocess.CompletedProcess([], 1, '', 'unrelated')):
                kube.return_value = result
                with self.assertRaises(RuntimeError): verify.composition_guard()
            policy['spec']['failurePolicy'] = 'Ignore'
            with self.assertRaises(RuntimeError): verify.composition_guard()
            policy.clear()
            with self.assertRaises(RuntimeError): verify.composition_guard()

    def test_privileged_namespace_needs_catalog_and_real_composition_verification(self):
        namespace = namespace_document('cloudlab-app-composition', composition=True)
        entry = {'publication': 'ready', 'approval': {'namespace': namespace['metadata']['name'], 'composition': {'approved': True}}}
        with self.assertRaises(RuntimeError): verify.namespaces([namespace], True, [])
        with patch.object(verify, 'namespace_admission'), patch('playbooks.services.files.composition_verify.admission', return_value={'ephemeral_denied': True}) as proof:
            self.assertEqual(verify.namespaces([namespace], True, [entry]), (1, 1, 0))
            self.assertEqual(proof.call_args.args[0], entry)
        with patch.object(verify, 'namespace_admission'), patch('playbooks.services.files.composition_verify.admission', side_effect=RuntimeError('missing guard')):
            with self.assertRaises(RuntimeError): verify.namespaces([namespace], True, [entry])
        with self.assertRaises(RuntimeError): verify.namespaces([], True, [entry])
        with self.assertRaises(RuntimeError): verify.namespaces([namespace], True, [entry, entry])
        with self.assertRaises(RuntimeError): verify.namespaces([namespace_document(namespace['metadata']['name'])], True, [entry])

    def test_ordinary_restricted_namespaces_keep_existing_admission_proof(self):
        namespace = namespace_document('cloudlab-app-notes')
        with patch.object(verify, 'namespace_admission') as guard, patch.object(verify, 'admission') as admit, patch.object(verify, 'ephemeral_admission', return_value=True):
            self.assertEqual(verify.namespaces([namespace], True, []), (1, 0, 1))
            admit.assert_called_once_with('cloudlab-app-notes', True)
            guard.assert_called_once_with(namespace)
        namespace['metadata']['labels']['pod-security.kubernetes.io/enforce'] = 'privileged'
        with self.assertRaises(RuntimeError): verify.namespaces([namespace], True, [])

    def test_namespace_candidates_cannot_hide_by_removing_owner_labels(self):
        resource = namespace_document()
        for labels in ({}, {'cloudlab.io/owner': 'foreign'}):
            changed = copy.deepcopy(resource)
            changed['metadata']['labels'] = labels
            self.assertTrue(verify.namespace_candidate(changed))
            with self.assertRaises(RuntimeError): verify.namespace_profile(changed)
        unrelated = namespace_document('external-secrets')
        unrelated['metadata']['labels'] = {'cloudlab.io/service-secrets': 'approved'}
        self.assertFalse(verify.namespace_candidate(unrelated))
        for labels in ({'cloudlab.io/owner': 'service-platform'}, {'cloudlab.io/composition': 'approved'}):
            unrelated['metadata']['labels'] = labels
            self.assertTrue(verify.namespace_candidate(unrelated))
            with self.assertRaises(RuntimeError): verify.namespace_profile(unrelated)

    def test_namespace_dry_runs_require_real_native_denial_and_preserve_input(self):
        resource = namespace_document()
        original = copy.deepcopy(resource)
        accepted = subprocess.CompletedProcess([], 0, '', '')
        denial = ("ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native' with binding "
                  "'cloudlab-workload-namespace-native' denied request: Application namespaces must retain their platform owner, "
                  'ambient capture, secret eligibility and pinned Pod Security labels.')
        denied = subprocess.CompletedProcess([], 1, '', denial)
        with patch.object(verify, 'kube', side_effect=[accepted, denied, denied]) as kube:
            verify.namespace_admission(resource)
            self.assertEqual(resource, original)
            self.assertEqual(len(kube.call_args_list), 3)
            for call in kube.call_args_list:
                self.assertEqual(call.args[:2], ('replace', '--dry-run=server'))
            self.assertEqual(kube.call_args_list[1].kwargs['document']['metadata']['labels'], {})
        for results in ([denied], [accepted, accepted],
                        [accepted, subprocess.CompletedProcess([], 1, '', denial.replace("with binding 'cloudlab-workload-namespace-native'", "with binding 'foreign'"))],
                        [accepted, subprocess.CompletedProcess([], 1, '', denial.replace("ValidatingAdmissionPolicy 'cloudlab-workload-namespace-native'", "ValidatingAdmissionPolicy 'foreign'"))],
                        [accepted, subprocess.CompletedProcess([], 1, '', 'cloudlab-workload-namespace: ' + denial.split('denied request: ')[1])],
                        [accepted, subprocess.CompletedProcess([], 1, '', 'cloudlab-workload-namespace')],
                        [accepted, subprocess.CompletedProcess([], 1, '', 'unrelated rejection')]):
            with self.subTest(results=results), patch.object(verify, 'kube', side_effect=results):
                with self.assertRaises(RuntimeError): verify.namespace_admission(resource)

    def test_native_namespace_guard_requires_exact_source_binding_and_current_typing(self):
        expected = verify.namespace_guard_desired()
        documents = copy.deepcopy(expected)
        for row in documents:
            row['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-workload-policy:admissionregistration.k8s.io/' + row['kind'] + ':cloudlab-policy/' + verify.NAMESPACE_GUARD_NAME)
        documents[0]['metadata']['generation'] = 1
        documents[0]['status'] = {'observedGeneration': 1, 'typeChecking': {}}
        self.assertTrue(verify.namespace_guard_validate(documents))
        for change in ('missing', 'tracking', 'retention', 'selection', 'failure', 'actions', 'stale', 'warning', 'predicate'):
            altered = copy.deepcopy(documents)
            if change == 'missing': altered[1] = None
            elif change == 'tracking': altered[0]['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
            elif change == 'retention': altered[0]['metadata']['annotations'].pop('argocd.argoproj.io/sync-options')
            elif change == 'selection': altered[0]['spec']['matchConstraints']['namespaceSelector'] = {'matchLabels': {'selected': 'true'}}
            elif change == 'failure': altered[0]['spec']['failurePolicy'] = 'Ignore'
            elif change == 'actions': altered[1]['spec']['validationActions'] = ['Warn']
            elif change == 'stale': altered[0]['status']['observedGeneration'] = 0
            elif change == 'warning': altered[0]['status']['typeChecking']['expressionWarnings'] = [{'warning': 'invalid'}]
            else: altered[0]['spec']['validations'][0]['expression'] = 'true'
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                verify.namespace_guard_validate(altered)

    def test_layered_repository_denial_requires_the_exact_policy_rule_and_message(self):
        parts = ('application-artifacts', 'approved-repositories',
                 'Images require the approved application repository or retained bootstrap digest.')
        message = ' '.join(parts)
        self.assertTrue(verify.digest_result(subprocess.CompletedProcess([], 1, '', message), True))
        for stderr in ('unrelated rejection', *(message.replace(part, '') for part in parts)):
            with self.subTest(stderr=stderr):
                self.assertFalse(verify.digest_result(subprocess.CompletedProcess([], 1, '', stderr), True))
        for code, enforce in ((0, True), (1, False), (0, False)):
            with self.subTest(code=code, enforce=enforce):
                self.assertFalse(verify.digest_result(subprocess.CompletedProcess([], code, '', message), enforce))

    def test_audit_proof_requires_real_warning_and_existing_pod_security_denial(self):
        accepted = subprocess.CompletedProcess([], 0, '', '')
        warned = subprocess.CompletedProcess([], 0, '', 'Warning: Workload images must use an immutable SHA-256 digest.')
        unbounded = subprocess.CompletedProcess([], 0, '',
            'Warning: Every workload container requires positive CPU and memory requests and limits.')
        token = subprocess.CompletedProcess([], 0, '', 'Warning: Workloads must not project Kubernetes service account tokens.')
        denied = subprocess.CompletedProcess([], 1, '', 'violates PodSecurity "restricted:v1.36"')
        with patch.object(verify, 'dry_run', side_effect=[accepted, warned, unbounded, token, denied]) as run:
            verify.admission('cloudlab-app-proof', False)
        self.assertEqual(run.call_args_list[0].args[0]['spec']['automountServiceAccountToken'], False)
        self.assertTrue(run.call_args_list[-1].args[0]['spec']['containers'][0]['securityContext']['privileged'])
        self.assertTrue(run.call_args_list[-1].args[0]['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])
        for results in ([accepted, accepted], [accepted, warned, accepted], [accepted, warned, unbounded, accepted],
                        [accepted, warned, unbounded, token, accepted],
                        [accepted, warned, unbounded, token, subprocess.CompletedProcess([], 1, '', 'unrelated error')]):
            with self.subTest(results=results), patch.object(verify, 'dry_run', side_effect=results):
                with self.assertRaises(RuntimeError):
                    verify.admission('cloudlab-app-proof', False)

    def test_enforcement_requires_policy_denials_and_never_accepts_a_warning(self):
        accepted = subprocess.CompletedProcess([], 0, '', '')
        messages = ('Workload images must use an immutable SHA-256 digest.',
                    'Every workload container requires positive CPU and memory requests and limits.',
                    'Workloads must not project Kubernetes service account tokens.',
                    'violates PodSecurity "restricted:v1.36"')
        denied = [subprocess.CompletedProcess([], 1, '', message) for message in messages]
        with patch.object(verify, 'dry_run', side_effect=[accepted, *denied]):
            verify.admission('cloudlab-app-proof', True)
        for index in range(4):
            for result in (subprocess.CompletedProcess([], 0, '', messages[index]),
                           subprocess.CompletedProcess([], 1, '', 'unrelated rejection')):
                results = [accepted, *denied]
                results[index + 1] = result
                with self.subTest(index=index, result=result), patch.object(verify, 'dry_run', side_effect=results):
                    with self.assertRaises(RuntimeError):
                        verify.admission('cloudlab-app-proof', True)

    def test_server_admission_probe_never_creates_a_running_workload(self):
        with patch.object(verify, 'kube') as kube:
            verify.dry_run(verify.probe('cloudlab-app-proof'))
        self.assertEqual(kube.call_args.args, ('create', '--dry-run=server', '-f', '-', '-o', 'json'))

    def test_unpublished_or_invalid_revision_never_contacts_cluster(self):
        for revision in ('main', '', 'a' * 39, 'a' * 40 + '; command'):
            with self.subTest(revision=revision), patch.object(verify, 'get') as get:
                with self.assertRaises(ValueError):
                    verify.run(revision, ['Deny'])
                get.assert_not_called()

    def test_invalid_policy_actions_never_contact_cluster(self):
        for actions in ([], ['Warn'], ['Deny', 'Warn'], 'Deny', None):
            with self.subTest(actions=actions), patch.object(verify, 'wait') as wait:
                with self.assertRaises(ValueError):
                    verify.run('a' * 40, actions)
                wait.assert_not_called()

    def test_policy_readiness_uses_native_conditions_and_rejects_stale_generation(self):
        policy = {'metadata': {'generation': 2}, 'status': {'conditionStatus': {
            'ready': True, 'conditions': [{'type': 'WebhookConfigured', 'status': 'True'},
                                        {'type': 'RBACPermissionsGranted', 'status': 'True'}]}}}
        self.assertTrue(verify.policy_ready(policy))
        for value in ({'ready': False}, {'conditions': []},
                      {'conditions': [{'type': 'RBACPermissionsGranted', 'status': 'False'}]},
                      {'conditions': [{'type': 'WebhookConfigured', 'status': 'True', 'observedGeneration': 1}]}):
            changed = copy.deepcopy(policy)
            changed['status']['conditionStatus'].update(value)
            self.assertFalse(verify.policy_ready(changed))
        self.assertFalse(verify.policy_ready(None))

    def test_ephemeral_probe_binds_existing_pod_and_always_uses_server_dry_run(self):
        target = verify.probe('cloudlab-app-proof')
        target['metadata'].update(uid='original-uid', resourceVersion='17', generation=1)
        target['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        accepted = subprocess.CompletedProcess([], 0, '', '')
        warned = subprocess.CompletedProcess([], 0, '', 'Warning: Workload images must use an immutable SHA-256 digest.')
        with patch.object(verify, 'get', return_value={'items': [target]}), \
                patch.object(verify, 'kube', side_effect=[accepted, warned]) as kube:
            self.assertTrue(verify.ephemeral_admission('cloudlab-app-proof', False))
        self.assertNotIn('ephemeralContainers', target['spec'])
        for call in kube.call_args_list:
            self.assertEqual(call.args[0], 'replace')
            self.assertTrue(call.args[2].endswith('/ephemeralcontainers?dryRun=All'))
            self.assertEqual(call.kwargs['document']['metadata']['uid'], 'original-uid')
            self.assertEqual(call.kwargs['document']['metadata']['resourceVersion'], '17')
            self.assertNotIn('resources', call.kwargs['document']['spec']['ephemeralContainers'][-1])

    def test_ephemeral_enforcement_rejects_mutable_image_with_the_exact_rule(self):
        target = verify.probe('cloudlab-app-proof')
        target['status'] = {'conditions': [{'type': 'Ready', 'status': 'True'}]}
        accepted = subprocess.CompletedProcess([], 0, '', '')
        message = 'Workload images must use an immutable SHA-256 digest.'
        for result, passes in ((subprocess.CompletedProcess([], 1, '', message), True),
                               (subprocess.CompletedProcess([], 0, '', message), False),
                               (subprocess.CompletedProcess([], 1, '', 'unrelated rejection'), False)):
            with self.subTest(result=result), patch.object(verify, 'get', return_value={'items': [target]}), \
                    patch.object(verify, 'kube', side_effect=[accepted, result]):
                if passes:
                    self.assertTrue(verify.ephemeral_admission('cloudlab-app-proof', True))
                else:
                    with self.assertRaises(RuntimeError):
                        verify.ephemeral_admission('cloudlab-app-proof', True)

    def test_retained_empty_namespace_does_not_create_a_pod_for_the_ephemeral_probe(self):
        for document in (None, {'items': []}):
            with self.subTest(document=document), patch.object(verify, 'get', return_value=document), \
                    patch.object(verify, 'kube') as kube:
                self.assertFalse(verify.ephemeral_admission('cloudlab-app-proof', True))
                kube.assert_not_called()
