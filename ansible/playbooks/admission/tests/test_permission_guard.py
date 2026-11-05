"""Native permission guard qualification rejects incomplete or unrelated evidence."""
import copy
import unittest
from unittest.mock import patch

from playbooks.admission.files import verify


def qualified():
    expected = verify.permission_guard_desired()
    documents = copy.deepcopy(expected)
    for row in documents:
        row['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
            'cloudlab-workload-policy:admissionregistration.k8s.io/' + row['kind'] + ':cloudlab-policy/' + row['metadata']['name'])
        if row['kind'] == 'ValidatingAdmissionPolicy':
            row['metadata']['generation'] = 2
            row['status'] = {'observedGeneration': 2, 'typeChecking': {}}
    return documents, expected


class PermissionGuardTests(unittest.TestCase):
    def test_production_wait_retries_missing_or_stale_guard_until_current(self):
        current, expected = qualified()
        stale = copy.deepcopy(current)
        stale[0]['status']['observedGeneration'] = 1
        for incomplete in ([None] * 4, stale):
            with self.subTest(incomplete=incomplete), \
                    patch.object(verify, 'application_ready', return_value=True), \
                    patch.object(verify, 'get', side_effect=[*incomplete, *current]) as get, \
                    patch.object(verify.time, 'monotonic', side_effect=range(10)), \
                    patch.object(verify.time, 'sleep'), \
                    patch.object(verify, 'permission_guard_probes', side_effect=StopIteration('qualified')) as probes:
                with self.assertRaisesRegex(StopIteration, 'qualified'):
                    verify.run('a' * 40, ['Deny'], guard_expected=expected)
                self.assertEqual(get.call_count, 8)
                probes.assert_called_once()

    def test_production_wait_times_out_without_probing_persistently_incomplete_guard(self):
        _, expected = qualified()
        with patch.object(verify, 'application_ready', return_value=True), \
                patch.object(verify, 'get', return_value=None), \
                patch.object(verify.time, 'monotonic', side_effect=[0, 1, 2, 3, 182]), \
                patch.object(verify.time, 'sleep'), patch.object(verify, 'permission_guard_probes') as probes:
            with self.assertRaisesRegex(RuntimeError, 'timed out: native permission guard qualification'):
                verify.run('a' * 40, ['Deny'], guard_expected=expected)
            probes.assert_not_called()

    def test_exact_current_policy_binding_and_native_owner_are_required(self):
        self.assertTrue(verify.permission_guard_validate(*qualified()))
        documents, expected = qualified()
        documents[0]['status'].pop('typeChecking')
        self.assertTrue(verify.permission_guard_validate(documents, expected))
        for field in ('missing', 'generation', 'pending', 'warnings', 'actions', 'tracking', 'matching'):
            documents, expected = qualified()
            policy, binding = documents[:2]
            if field == 'missing': documents[1] = None
            elif field == 'generation': policy['status']['observedGeneration'] = 1
            elif field == 'pending': policy['status'].pop('observedGeneration')
            elif field == 'warnings': policy['status']['typeChecking']['expressionWarnings'] = [{'warning': 'unknown variable'}]
            elif field == 'actions': binding['spec']['validationActions'] = ['Warn']
            elif field == 'tracking': policy['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
            elif field == 'matching': policy['spec']['matchConstraints']['resourceRules'][0]['resources'] = ['pods']
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                verify.permission_guard_validate(documents, expected)

    def test_rbac_denial_cannot_substitute_for_specific_native_guard_denial(self):
        def probe(document, caller):
            good = caller == verify.PERMISSIONS_CONTROLLER and document['metadata'].get('annotations', {}).get(
                'argocd.argoproj.io/tracking-id', '').startswith('cloudlab-permissions:') and document['metadata'].get('labels')
            if document['metadata']['name'] == 'cloudlab-foreign-permission-proof': good = False
            name = verify.PERMISSIONS_GUARD_NAME + ('-roles' if document['kind'] == 'ClusterRole' else '-bindings')
            return (0, '') if good else (403, name + ': ' + verify.PERMISSIONS_GUARD_MESSAGE)
        self.assertTrue(verify.permission_guard_probes(probe))
        with self.assertRaises(RuntimeError):
            verify.permission_guard_probes(lambda row, caller: (0, '') if caller else (403, 'RBAC forbidden'))

    def test_source_edits_cannot_weaken_the_required_failure_mode_or_scope(self):
        for field in ('failurePolicy', 'selection', 'actions'):
            documents, expected = qualified()
            if field == 'failurePolicy': expected[0]['spec']['failurePolicy'] = 'Ignore'
            elif field == 'selection': expected[0]['spec']['matchConstraints']['namespaceSelector'] = {'matchLabels': {'chosen': 'only'}}
            else: expected[1]['spec']['validationActions'] = ['Warn']
            documents = copy.deepcopy(expected)
            with self.subTest(field=field), self.assertRaises(RuntimeError): verify.permission_guard_validate(documents, expected)
