import copy
import unittest

from playbooks.admission.files import namespace_guard as guard


class NamespaceGuardTests(unittest.TestCase):
    def setUp(self):
        self.declaration = None
        self.documents = guard.namespace_guard_desired()
        for obj in self.documents:
            obj['metadata'].update(uid=obj['kind'], generation=1)
            obj['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
                'cloudlab-workload-policy:admissionregistration.k8s.io/' + obj['kind'] +
                ':cloudlab-policy/' + guard.NAMESPACE_GUARD_NAME)
        self.documents[0]['status'] = {'observedGeneration': 1, 'typeChecking': {}}
        self.message = self.documents[0]['spec']['validations'][0]['message']
        self.denial = ("ValidatingAdmissionPolicy '" + guard.NAMESPACE_GUARD_NAME + "' with binding '" +
                       guard.NAMESPACE_GUARD_NAME + "' denied request: " + self.message)
        self.calls = []

    def read(self, kind, name):
        if kind == 'namespace':
            return None
        return self.documents[1 if kind.startswith('validatingadmissionpolicybinding.') else 0]

    def probe(self, document):
        self.calls.append(copy.deepcopy(document))
        return (0, '') if document['metadata']['labels']['cloudlab.io/owner'] == 'service-platform' else (1, self.denial)

    def test_qualifies_exact_owner_with_fenced_positive_and_negative_dry_runs(self):
        captured = guard.qualify(None, self.read, self.probe)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(captured, guard.qualify(None, self.read, self.probe, captured))
        self.assertEqual(self.calls[0]['metadata']['labels']['pod-security.kubernetes.io/enforce'], 'restricted')

    def test_missing_foreign_stale_or_deleting_guard_stops_before_probes(self):
        for change in ('missing', 'foreign', 'stale', 'deleting', 'uid'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.documents)
                if change == 'missing': self.documents[1] = {}
                elif change == 'foreign': self.documents[0]['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = 'foreign'
                elif change == 'stale': self.documents[0]['status']['observedGeneration'] = 0
                elif change == 'deleting': self.documents[1]['metadata']['deletionTimestamp'] = 'now'
                else: self.documents[0]['metadata']['uid'] = ''
                with self.assertRaises(RuntimeError): guard.qualify(None, self.read, self.probe)
                self.documents = original
        self.assertEqual(self.calls, [])

    def test_admitted_negative_generic_failure_and_failed_positive_are_not_qualification(self):
        for code, diagnostics in ((0, ''), (1, 'RBAC denied'), (1, self.denial.replace(self.message, 'other'))):
            with self.subTest(code=code, diagnostics=diagnostics), self.assertRaises(RuntimeError):
                guard.qualify(None, self.read, lambda obj: (0, '') if
                    obj['metadata']['labels']['cloudlab.io/owner'] == 'service-platform' else (code, diagnostics))
        with self.assertRaisesRegex(RuntimeError, 'positive control'):
            guard.qualify(None, self.read, lambda obj: (1, 'transport unavailable'))
        for result in (None, (None, ''), (False, ''), (0, None), [0, '']):
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                guard.qualify(None, self.read, lambda obj: result)

    def test_snapshot_change_and_previously_captured_identity_are_rejected(self):
        captured = guard.qualify(None, self.read, self.probe)
        self.documents[0]['metadata']['uid'] = 'replaced'
        with self.assertRaisesRegex(RuntimeError, 'authority changed'):
            guard.qualify(None, self.read, self.probe, captured)
        def changing(document):
            result = self.probe(document)
            self.documents[1]['metadata']['labels'] = {'changed': 'yes'}
            return result
        with self.assertRaisesRegex(RuntimeError, 'changed during'):
            guard.qualify(None, self.read, changing)


if __name__ == '__main__':
    unittest.main()
