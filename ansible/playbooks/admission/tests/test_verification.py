import copy
import subprocess
import unittest
from unittest.mock import patch

from playbooks.admission.files import verify


class VerificationTests(unittest.TestCase):
    def test_audit_proof_requires_real_warning_and_existing_pod_security_denial(self):
        accepted = subprocess.CompletedProcess([], 0, '', '')
        warned = subprocess.CompletedProcess([], 0, '', 'Warning: Workload images must use an immutable SHA-256 digest.')
        unbounded = subprocess.CompletedProcess([], 0, '',
            'Warning: Every workload container requires positive CPU and memory requests and limits.')
        token = subprocess.CompletedProcess([], 0, '', 'Warning: Workloads must not project Kubernetes service account tokens.')
        denied = subprocess.CompletedProcess([], 1, '', 'violates PodSecurity "restricted:v1.36"')
        with patch.object(verify, 'dry_run', side_effect=[accepted, warned, unbounded, token, denied]) as run:
            verify.admission('cloudlab-app-proof')
        self.assertEqual(run.call_args_list[0].args[0]['spec']['automountServiceAccountToken'], False)
        self.assertTrue(run.call_args_list[-1].args[0]['spec']['containers'][0]['securityContext']['privileged'])
        self.assertTrue(run.call_args_list[-1].args[0]['spec']['containers'][0]['securityContext']['allowPrivilegeEscalation'])
        for results in ([accepted, accepted], [accepted, warned, accepted], [accepted, warned, unbounded, accepted],
                        [accepted, warned, unbounded, token, accepted],
                        [accepted, warned, unbounded, token, subprocess.CompletedProcess([], 1, '', 'unrelated error')]):
            with self.subTest(results=results), patch.object(verify, 'dry_run', side_effect=results):
                with self.assertRaises(RuntimeError):
                    verify.admission('cloudlab-app-proof')

    def test_server_admission_probe_never_creates_a_running_workload(self):
        with patch.object(verify, 'kube') as kube:
            verify.dry_run(verify.probe('cloudlab-app-proof'))
        self.assertEqual(kube.call_args.args, ('create', '--dry-run=server', '-f', '-', '-o', 'json'))

    def test_unpublished_or_invalid_revision_never_contacts_cluster(self):
        for revision in ('main', '', 'a' * 39, 'a' * 40 + '; command'):
            with self.subTest(revision=revision), patch.object(verify, 'get') as get:
                with self.assertRaises(ValueError):
                    verify.run(revision)
                get.assert_not_called()

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
            self.assertTrue(verify.ephemeral_admission('cloudlab-app-proof'))
        self.assertNotIn('ephemeralContainers', target['spec'])
        for call in kube.call_args_list:
            self.assertEqual(call.args[0], 'replace')
            self.assertTrue(call.args[2].endswith('/ephemeralcontainers?dryRun=All'))
            self.assertEqual(call.kwargs['document']['metadata']['uid'], 'original-uid')
            self.assertEqual(call.kwargs['document']['metadata']['resourceVersion'], '17')
            self.assertNotIn('resources', call.kwargs['document']['spec']['ephemeralContainers'][-1])

    def test_retained_empty_namespace_does_not_create_a_pod_for_the_ephemeral_probe(self):
        for document in (None, {'items': []}):
            with self.subTest(document=document), patch.object(verify, 'get', return_value=document), \
                    patch.object(verify, 'kube') as kube:
                self.assertFalse(verify.ephemeral_admission('cloudlab-app-proof'))
                kube.assert_not_called()
