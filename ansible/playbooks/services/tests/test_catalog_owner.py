import copy
from contextlib import nullcontext
from pathlib import Path
import unittest
from unittest.mock import patch

import yaml
from playbooks.services.files import catalog, payload
from playbooks.services.tests.fixtures import catalog_payload, catalog_application


class CatalogOwnerTests(unittest.TestCase):
    def test_payload_uses_declared_catalog_pin_not_checkout_revision(self):
        public = yaml.safe_load((payload.ROOT / 'gitops/roots/public/values.yaml').read_text())
        with patch.object(payload, 'committed_payload', return_value={'repository': public['repository'], 'revision': 'a' * 40}), \
                patch.object(payload, 'dotenv_values', return_value={'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private.git'}), \
                patch('playbooks.services.files.owner.chart', return_value=nullcontext(payload.ROOT / 'platform/delivery/services')), \
                patch.object(payload, 'catalog', return_value=({'catalog': [], 'dataApprovals': {}}, 'b' * 40)):
            result = payload.payload()
        self.assertEqual(result['revision'], public['services']['revision'])
        self.assertNotEqual(result['revision'], 'a' * 40)

    def test_observer_rejects_wrong_parent_owner_sources_and_deletion_without_mutating(self):
        value = catalog_payload()
        original = catalog_application(value)
        for change in ('tracking', 'owner', 'pin', 'private', 'deleting', 'pruning', 'operation', 'progressing', 'comparison-error'):
            app = copy.deepcopy(original)
            if change == 'tracking': app['metadata']['annotations'] = {}
            if change == 'owner': app['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
            if change == 'pin': app['spec']['sources'][0]['targetRevision'] = 'main'
            if change == 'private': app['status']['sync']['revisions'][1] = 'c' * 40
            if change == 'deleting': app['metadata']['deletionTimestamp'] = 'synthetic'
            if change == 'pruning': app['spec']['syncPolicy']['automated']['prune'] = True
            if change == 'operation': app['operation'] = {'sync': {}}
            if change == 'progressing': app['status'].update(health={'status': 'Progressing'}, sync={'status': 'OutOfSync'})
            if change == 'comparison-error': app['status']['conditions'] = [{'type': 'ComparisonError'}]
            with self.subTest(change=change), patch.object(catalog, 'get', return_value=app):
                self.assertFalse(catalog.converged(value))

    def test_retirement_cannot_reinstall_writer_and_only_follows_observation(self):
        root = Path(__file__).resolve().parents[4]
        tasks = yaml.safe_load((root / 'ansible/playbooks/services/tasks/bootstrap.yml').read_text())
        commands = [(index, task['ansible.builtin.command']) for index, task in enumerate(tasks)
                    if 'ansible.builtin.command' in task]
        observe = next(index for index, command in commands if 'files/catalog.py' in str(command))
        retirement = next(index for index, task in enumerate(tasks) if task.get('ansible.builtin.file', {}).get('state') == 'absent')
        self.assertLess(observe, retirement)
        self.assertEqual(tasks[retirement]['loop'], ['bootstrap.py', 'repair_source_owner.py'])
        for task in tasks:
            if 'ansible.builtin.copy' in task:
                self.assertNotIn('bootstrap.py', task.get('loop', []))
                self.assertNotIn('repair_source_owner.py', task.get('loop', []))
        self.assertFalse((root / 'ansible/playbooks/services/files/bootstrap.py').exists())
        self.assertFalse((root / 'ansible/playbooks/services/repair-source-owner.yml').exists())
