"""Issuance must resume safely and never skip staging or overwrite another owner."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import configuration as config
from kube import ready


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        for name, value in [('BASE', self.base), ('zone', lambda: 'example.invalid'),
                            ('wait', lambda *args, **kwargs: True), ('kube', lambda *args, **kwargs: ''),
                            ('get', lambda *args, **kwargs: None)]:
            mocked = patch.object(config, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.payload = {'repository': 'https://github.com/example/platform.git', 'branch': 'main', 'revision': 'reviewed'}
        self.identity = {'certificate_uid': 'certificate', 'secret_uid': 'secret'}

    def test_failed_staging_never_enables_production_and_resumes(self):
        stages = []
        with patch.object(config, 'configure', side_effect=lambda p, z, prod, s: stages.append(prod) or False), \
                patch.object(config, 'certificate', side_effect=RuntimeError('not issued')):
            with self.assertRaisesRegex(RuntimeError, 'not issued'):
                config.run(self.payload)
        self.assertEqual(stages, [False])
        self.assertEqual(json.loads((self.base / 'ownership.json').read_text())['phase'], 'staging')
        with patch.object(config, 'configure', side_effect=lambda p, z, prod, s: stages.append(prod) or False), \
                patch.object(config, 'certificate', return_value=self.identity), \
                patch.object(config, 'get', return_value={'metadata': {'uid': 'account'}, 'data': {'tls.key': 'fixture'}}):
            self.assertTrue(config.run(self.payload)['changed'])
            self.assertFalse(config.run(self.payload)['changed'])
        self.assertEqual(stages, [False, False, True, True])

    def test_selected_zone_change_is_rejected_before_writes(self):
        config.record({'phase': 'accepted', 'zone_hash': 'different'})
        with patch.object(config, 'configure') as writer:
            with self.assertRaisesRegex(RuntimeError, 'DNS zone'):
                config.run(self.payload)
            writer.assert_not_called()

    def test_foreign_application_and_replaced_identity_are_rejected(self):
        for metadata in [{'uid': 'existing', 'labels': {'cloudlab.io/owner': 'foreign'}},
                         {'uid': 'replaced', 'labels': {'cloudlab.io/owner': config.OWNER}},
                         {'uid': 'existing', 'labels': {'cloudlab.io/owner': config.OWNER}, 'finalizers': ['cascade']}]:
            with patch.object(config, 'get', return_value={'metadata': metadata}), patch.object(config, 'kube') as writer:
                with self.assertRaisesRegex(RuntimeError, 'conflicting owner'):
                    config.configure(self.payload, 'example.invalid', False, {'application_uid': 'existing'})
                writer.assert_not_called()

    def test_missing_checkpoint_cannot_adopt_an_existing_application(self):
        with patch.object(config, 'get', return_value={'metadata': {'uid': 'existing'}}), \
                patch.object(config, 'configure') as writer:
            with self.assertRaisesRegex(RuntimeError, 'without its durable'):
                config.run(self.payload)
            writer.assert_not_called()

    def test_readiness_must_match_current_generation(self):
        resource = {'metadata': {'generation': 2}, 'status': {'conditions': [
            {'type': 'Ready', 'status': 'True', 'observedGeneration': 1}]}}
        self.assertFalse(ready(resource))
        resource['status']['conditions'][0]['observedGeneration'] = 2
        self.assertTrue(ready(resource))

    def test_runtime_application_preserves_secret_ownership_and_private_values(self):
        app = config.application(self.payload, 'example.invalid', False)
        self.assertNotIn('finalizers', app['metadata'])
        self.assertEqual(app['spec']['source']['helm']['valuesObject'], {'zone': 'example.invalid', 'production': False})
        self.assertFalse(app['spec']['syncPolicy']['automated']['prune'])
        self.assertFalse(any('Force' in x or 'Replace' in x for x in app['spec']['syncPolicy']['syncOptions']))


if __name__ == '__main__':
    unittest.main()
