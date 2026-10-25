"""Raw updates preserve fixed resource ownership and reject unchecked archives."""
import json
import base64
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.dependencies.files import artifacts
from playbooks.dependencies.files.security import digest
from playbooks.dependencies.files import control, inventory, workspace, check
from playbooks.dependencies.files.gate import Gate, branch_prefix
from playbooks.dependencies.tests.fixtures import MaintenanceAPI, gateway_artifact


class ArtifactTests(unittest.TestCase):
    def test_gateway_full_export_repair_scope_and_official_provenance(self):
        prefix = 'platform/connectivity/gateway-api/'
        owners = inventory.selected(['chart:connectivity/gateway-api'])
        paths = control.allowed(owners)
        self.assertIn(prefix + 'upstream.yaml', paths)
        base = {name: (inventory.ROOT / name).read_bytes() for name in paths}
        version = json.loads(base[prefix + 'artifact.lock.json'])['version']
        major, minor, value = version.split('.')
        version = major + '.' + minor + '.' + str(int(value) + 1)
        raw = gateway_artifact()
        with tempfile.TemporaryDirectory() as temporary:
            root, store = Path(temporary) / 'candidate', Path(temporary) / 'control'
            store.mkdir()
            head = dict(base)
            metadata = json.loads(head[prefix + 'artifact.lock.json'])
            metadata['version'] = version
            head[prefix + 'artifact.lock.json'] = json.dumps(metadata).encode()
            api = MaintenanceAPI(base, head)
            gate = Gate(api, {'repository': 'example/platform', 'repositoryId': 1,
                             'requester': 'release[bot]', 'base': 'main', 'branchPrefix': branch_prefix('main')}, store)
            with patch.object(control, 'CANDIDATE', root), patch.object(control, 'CONTROL', store), \
                    patch.object(control, 'snapshot', side_effect=api.snapshot), \
                    patch.object(workspace, 'snapshot', side_effect=api.snapshot):
                control.export_pr(gate, 7, ['chart:connectivity/gateway-api'])
                artifacts.update(root, 'connectivity/gateway-api', version, fetch=lambda *args, **kwargs: raw)
                plan = control.load('check-plan.json')
                check.source(root, plan)
                artifacts.provenance(root, plan, fetch=lambda *args, **kwargs: raw)
                repairs = workspace.changes(root, control.load('baseline.json'), paths)
                self.assertEqual(set(repairs), {prefix + 'artifact.lock.json', prefix + 'upstream.yaml'})
                gate.publish(7, api.head, api.base, repairs, paths, modes={name: '100644' for name in paths})
                control.export_pr(gate, 7, ['chart:connectivity/gateway-api'])
                artifacts.provenance(root, control.load('check-plan.json'), fetch=lambda *args, **kwargs: raw)
                (root / prefix / 'upstream.yaml').write_bytes(raw + b'---\nkind: ClusterRole\n')
                with self.assertRaises(ValueError):
                    artifacts.provenance(root, control.load('check-plan.json'), fetch=lambda *args, **kwargs: raw)

    def test_gateway_update_binds_raw_bytes_url_version_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'platform/connectivity/gateway-api/artifact.lock.json'
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({'version': '1.6.1', 'channel': 'standard', 'url': 'old',
                                          'sha256': 'a' * 64, 'existing_owner': 'traefik-crd'}))
            raw = gateway_artifact()
            artifacts.update(root, 'connectivity/gateway-api', '1.6.2', fetch=lambda *args, **kwargs: raw)
            lock = json.loads(target.read_bytes())
            self.assertEqual(lock['sha256'], digest(raw))
            self.assertEqual(lock['existing_owner'], 'traefik-crd')
            self.assertIn('/v1.6.2/standard-install.yaml', lock['url'])
            self.assertEqual((target.parent / 'upstream.yaml').read_bytes(), raw)
            with self.assertRaises(ValueError):
                artifacts.update(root, 'connectivity/gateway-api', '1.7.0', fetch=lambda *args, **kwargs: raw)
            with self.assertRaises(ValueError):
                artifacts.update(root, 'connectivity/gateway-api', '1.6.3',
                                 fetch=lambda *args, **kwargs: b'kind: Secret\n')
