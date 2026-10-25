"""Identity pin changes cannot retain qualification or bypass native proof evidence."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.dependencies.files import keycloak
from playbooks.dependencies.files.inventory import ROOT
from playbooks.dependencies.files.workspace import tree


class IdentityUpdateTests(unittest.TestCase):
    def test_operator_cpu_burst_preserves_requests_memory_and_upstream_probes(self):
        import yaml
        from playbooks.keycloak.files.chart import BASE, render
        deployment = next(row for row in render({'enabled': True, 'serverEnabled': False}) if row['kind'] == 'Deployment')
        actual, = deployment['spec']['template']['spec']['containers']
        upstream = next(row for row in yaml.safe_load_all((BASE / 'upstream/kubernetes.yml').read_bytes())
                        if row and row['kind'] == 'Deployment')
        original, = upstream['spec']['template']['spec']['containers']
        self.assertEqual(actual['resources'], {'requests': {'cpu': '100m', 'memory': '256Mi'},
                                               'limits': {'cpu': '700m', 'memory': '450Mi'}})
        self.assertEqual(actual['resources']['limits']['cpu'], original['resources']['limits']['cpu'])
        for name in ('startupProbe', 'readinessProbe', 'livenessProbe'):
            self.assertEqual(actual[name], original[name])

    def test_complete_component_update_resets_qualification_and_downloads_all_raw_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / keycloak.LOCK
            target.parent.mkdir(parents=True)
            (target.parent / 'upstream').mkdir()
            original = json.loads((ROOT / keycloak.LOCK).read_bytes())
            target.write_text(json.dumps(original))
            requested = []

            def fetch(url, *, prefix):
                self.assertTrue(url.startswith(prefix))
                requested.append(url)
                return b'apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: public-fixture\n'

            versions = {'operator': '26.6.5', 'server': '26.8.1', 'configCli': '6.5.2', 'configCliServer': '26.5.6'}
            with patch.object(keycloak.images, 'image_digest', side_effect=lambda value: value + '@sha256:' + 'a' * 64):
                result = keycloak.update(root, versions, fetch=fetch)
            updated = json.loads(target.read_bytes())
            self.assertIs(updated['operator_install_verified'], False)
            self.assertEqual(len(requested), 3)
            self.assertEqual(result['status'], 'pending-qualification')
            self.assertEqual(updated['server_version'], '26.8.1')
            self.assertIn('6.5.2-26.5.6@sha256:', updated['images']['config_cli'])
            plan = {'baseFiles': {keycloak.LOCK: base64.b64encode(json.dumps(original).encode()).decode()}}
            self.assertTrue(keycloak.required(root, plan))
            updated['operator_install_verified'] = True
            target.write_text(json.dumps(updated))
            self.assertTrue(keycloak.required(root, plan), 'A manually set flag must never waive qualification')
            with self.assertRaises(ValueError):
                keycloak.update(root, dict(versions, server='26.9.0'), fetch=fetch)

    def test_python_runtime_pin_does_not_requalify_unchanged_identity_components(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / keycloak.LOCK
            target.parent.mkdir(parents=True)
            original = json.loads((ROOT / keycloak.LOCK).read_bytes())
            updated = copy.deepcopy(original)
            updated['images']['python'] = 'python:3.13-slim-bookworm@sha256:' + 'a' * 64
            target.write_text(json.dumps(updated))
            plan = {'baseFiles': {keycloak.LOCK: base64.b64encode(json.dumps(original).encode()).decode()}}
            self.assertFalse(keycloak.required(root, plan))

    def test_official_raw_source_provenance_rejects_alternate_component_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / keycloak.LOCK
            target.parent.mkdir(parents=True)
            lock = json.loads((ROOT / keycloak.LOCK).read_bytes())
            first = next(iter(lock['sources']))
            lock['sources'][first]['url'] = lock['sources'][first]['url'].replace('/keycloak/', '/attacker/')
            target.write_text(json.dumps(lock))
            with self.assertRaises(ValueError):
                keycloak.provenance(root, fetch=lambda *args, **kwargs: self.fail('Unexpected source download'))
