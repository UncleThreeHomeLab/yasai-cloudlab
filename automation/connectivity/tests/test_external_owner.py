import copy
import unittest

from automation.connectivity.external import accepted


class ExternalOwnerTests(unittest.TestCase):
    def test_only_accepted_exact_scope_can_run_native_verification(self):
        objects = {'app:fixture.example.invalid': {'id': 'retained'}}
        state = {'binding': 'fixture', 'objects': objects, 'infra_owner': {
            'phase': 'accepted', 'binding': 'fixture', 'objects': copy.deepcopy(objects)}}
        accepted(state)
        for owner in (None, {}, False, dict(state['infra_owner'], phase='suspended'),
                      dict(state['infra_owner'], objects={}), dict(state['infra_owner'], binding='foreign'),
                      dict(state['infra_owner'], objects={'app:fixture.example.invalid': {'id': 'foreign'}})):
            with self.subTest(owner=owner), self.assertRaises(RuntimeError):
                accepted(dict(state, infra_owner=owner))
        with self.assertRaises(RuntimeError):
            accepted({'binding': 'legacy', 'objects': objects})
