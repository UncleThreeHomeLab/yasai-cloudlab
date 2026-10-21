"""Keep runner proof fail-closed and free of cluster mutations."""
import copy
import json
import subprocess
import unittest
from unittest.mock import patch

from playbooks.admission.files import ci_verify
from playbooks.admission.tests.fixtures import runner


class RunnerVerificationTests(unittest.TestCase):
    def test_dry_run_impersonates_only_the_assigned_controller(self):
        good, _ = runner()
        identity = 'system:serviceaccount:cloudlab-ci-system:assigned-controller'
        with patch.object(ci_verify, 'kube') as kube:
            ci_verify.dry_run(good, identity)
        self.assertEqual(kube.call_args.args, ('create', '--dry-run=server', '-f', '-', '-o', 'json', '--as', identity))
        self.assertTrue(kube.call_args.kwargs['allow_failure'])

    def test_declared_outcome_requires_the_correct_policy_and_exit_code(self):
        for enforce in (False, True):
            result = subprocess.CompletedProcess([], int(enforce), '', 'cloudlab-ci-runner: exact denial')
            ci_verify.outcome(result, enforce, 'cloudlab-ci-runner')
            for bad in (subprocess.CompletedProcess([], int(not enforce), '', result.stderr),
                        subprocess.CompletedProcess([], int(enforce), '', 'unrelated failure')):
                with self.subTest(enforce=enforce), self.assertRaises(RuntimeError):
                    ci_verify.outcome(bad, enforce, 'cloudlab-ci-runner')

    def test_invalid_mode_never_contacts_cluster(self):
        for actions in ([], ['Warn'], ['Deny', 'Warn'], None):
            with self.subTest(actions=actions), patch.object(ci_verify, 'get') as get:
                with self.assertRaises(ValueError):
                    ci_verify.run(actions)
                get.assert_not_called()

    def test_api_permission_proof_rejects_unexpected_grants_and_transport_errors(self):
        for result in (subprocess.CompletedProcess([], 0, 'yes\n', ''),
                       subprocess.CompletedProcess([], 1, '', 'connection failed')):
            with self.subTest(result=result), patch.object(ci_verify, 'kube', return_value=result):
                with self.assertRaises(RuntimeError):
                    ci_verify.api_boundary('cloudlab-ci-public-example', 'assigned')
        with patch.object(ci_verify, 'kube', return_value=subprocess.CompletedProcess([], 1, 'no\n', '')) as kube:
            ci_verify.api_boundary('cloudlab-ci-public-example', 'assigned')
        self.assertEqual(kube.call_count, 9)
        self.assertTrue(all(call.args[:2] == ('auth', 'can-i') for call in kube.call_args_list))

    def test_probe_preserves_profile_and_does_not_supply_a_real_registration_token(self):
        _, config = runner()
        profile = json.loads(config['data']['admission.json'])
        original = copy.deepcopy(profile)
        document = ci_verify.runner_pod('cloudlab-ci-public-new', profile)
        self.assertEqual(profile, original)
        registration = document['spec']['containers'][0]['env'][-3]
        self.assertEqual(registration['valueFrom']['secretKeyRef']['name'], document['metadata']['name'])
        self.assertNotIn('value', registration)
        cases = list(ci_verify.violations(document))
        self.assertEqual(len(cases), 12)
        self.assertEqual(profile, original)
        self.assertEqual(document['spec']['containers'][0]['args'], profile['spec']['containers'][0]['args'])
