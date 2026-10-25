"""Initial and re-exported drafts retain the original reviewed compatibility bounds."""
import base64
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from playbooks.dependencies.files import compatibility, control, check, inventory, workspace
from playbooks.dependencies.files.gate import Gate, branch_prefix
from playbooks.dependencies.tests.fixtures import MaintenanceAPI


class CompatibilityTests(unittest.TestCase):
    def test_consistent_initial_postgresql_draft_cannot_attest_another_major_or_distribution(self):
        owners = inventory.selected(['image:postgresql'])
        paths = set().union(*(set(owner['sources'] + owner['companions']) for owner in owners.values()))
        base = {name: (inventory.ROOT / name).read_bytes() for name in paths}
        for tag in ('19.0-standard-trixie', '18.5-standard-bookworm', '18.5-standard-trixie'):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                root, store = Path(temporary) / 'candidate', Path(temporary) / 'control'
                store.mkdir()
                head = {name: raw.replace(b'18.4-standard-trixie', tag.encode()) for name, raw in base.items()}
                self.assertNotEqual(head, base)
                api = MaintenanceAPI(base, head)
                gate = Gate(api, {'repository': 'example/platform', 'repositoryId': 1,
                                 'requester': 'release[bot]', 'base': 'main', 'branchPrefix': branch_prefix('main')}, store)
                with patch.object(control, 'CANDIDATE', root), patch.object(control, 'CONTROL', store), \
                        patch.object(control, 'snapshot', side_effect=api.snapshot), \
                        patch.object(workspace, 'snapshot', side_effect=api.snapshot):
                    control.export_pr(gate, 7, ['image:postgresql'])
                    plan = control.load('check-plan.json')
                    check.source(root, plan)
                    if tag == '18.5-standard-trixie':
                        compatibility.verify(root, plan)
                        # Re-export must retain PR BASE, even when its local patch is empty.
                        control.export_pr(gate, 7, ['image:postgresql'])
                        self.assertEqual(control.load('check-plan.json')['baseFiles'], plan['baseFiles'])
                    else:
                        with patch.object(check, 'embedded') as execution:
                            with self.assertRaises(ValueError):
                                check.validated(root, plan)
                            execution.assert_not_called()

    def test_native_tool_chart_and_python_minor_bounds_use_base(self):
        examples = {
            'infra/github/versions.tf': (b'required_version = "= 1.13.1"\nversion = "= 6.12.0"',
                                        b'required_version = "= 1.14.0"\nversion = "= 6.12.0"'),
            'infra/github/.terraform.lock.hcl': (b'provider "registry.opentofu.org/a/b" {\nversion = "6.12.0"',
                                               b'provider "registry.opentofu.org/a/b" {\nversion = "7.0.0"'),
            'ansible/runner/helm.lock.json': (b'{"version":"v4.3.0"}', b'{"version":"v4.4.0"}'),
            'platform/example/artifact.lock.json': (b'{"version":"1.2.3"}', b'{"version":"1.3.0"}'),
            'apps/notes/requirements.txt': (b'example==1.2.3 --hash=sha256:' + b'a' * 64,
                                             b'example==1.3.0 --hash=sha256:' + b'b' * 64),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, (old, new) in examples.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(new)
                with self.subTest(path=name), self.assertRaises(ValueError):
                    compatibility.verify(root, {'baseFiles': {name: base64.b64encode(old).decode()}})

    def test_shared_github_origin_does_not_authorize_another_path(self):
        old = {'version': '1.2.3', 'url': 'https://github.com/example/tool/releases/download/v1.2.3/tool-1.2.3.zip'}
        compatibility.origins(old, dict(old, version='1.2.4', url=old['url'].replace('1.2.3', '1.2.4')))
        for url in ('https://github.com/example/evil/releases/download/v1.2.4/tool-1.2.4.zip',
                    'https://github.com/example/tool/releases/download/v1.2.4/evil.zip'):
            with self.assertRaises(ValueError):
                compatibility.origins(old, dict(old, version='1.2.4', url=url))
        old = {'version': 'gha-runner-scale-set-0.15.0',
               'source': 'https://codeload.github.com/actions/actions-runner-controller/tar.gz/refs/tags/gha-runner-scale-set-0.15.0'}
        compatibility.origins(old, {key: value.replace('0.15.0', '0.15.1') for key, value in old.items()})

    def test_derivative_provider_cannot_reuse_content_version_or_accept_malformed_semver(self):
        relative = 'ansible/runner/cloudflare-provider.lock.json'
        original = (inventory.ROOT / relative).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / relative
            target.parent.mkdir(parents=True)
            plan = {'baseFiles': {relative: base64.b64encode(original).decode()}}
            for version in ('5.27.0-cloudlab.1', '5.27.invalid'):
                candidate = json.loads(original)
                candidate['version'] = version
                candidate['package_sha256'] = 'b' * 64
                target.write_text(json.dumps(candidate))
                with self.subTest(version=version), self.assertRaises(ValueError):
                    compatibility.verify(root, plan)

    def test_inventory_refuses_unregistered_or_joined_writable_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ('source.json', 'companion.json', 'unregistered.json'):
                (root / name).write_text('{}')
            owner = {'sources': ['source.json'], 'companions': ['companion.json'],
                     'writePaths': ['source.json', 'companion.json'], 'checks': ['native:github'], 'updater': 'native'}
            policy = root / 'inventory.json'
            with patch.object(inventory, 'INVENTORY', policy):
                for writes in (['source.json', 'companion.json'], ['source.json companion.json'], ['unregistered.json']):
                    owner['writePaths'] = writes
                    policy.write_text(json.dumps({'schema': 1, 'owners': {'fixture': owner}}))
                    if len(writes) == 2:
                        inventory.load(root)
                    else:
                        with self.assertRaises(ValueError):
                            inventory.load(root)

    def test_native_provider_export_accepts_exact_constraint_and_lock_repairs(self):
        policy = inventory.load()['owners']
        for provider in ('github', 'keycloak', 'postgresql', 's3', 'grafana', 'tailscale'):
            owner_name = next(name for name, row in policy.items()
                              if row['updater'] == 'native' and 'native:' + provider in row['checks'])
            owners = inventory.selected([owner_name])
            paths = set().union(*(set(owner['writePaths']) for owner in owners.values()))
            self.assertEqual(len(paths), 2)
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as temporary:
                root, store = Path(temporary) / 'candidate', Path(temporary) / 'control'
                store.mkdir()
                base = {name: (inventory.ROOT / name).read_bytes() for name in paths}
                locked = next(raw for name, raw in base.items() if name.endswith('.terraform.lock.hcl'))
                version = re.search(rb'version\s*=\s*"([^"]+)"', locked)[1]
                major, minor, value = version.decode().split('.')
                updated = (major + '.' + minor + '.' + str(int(value) + 1)).encode()
                head = {name: raw.replace(version, updated) if name.endswith('versions.tf') else raw for name, raw in base.items()}
                api = MaintenanceAPI(base, head)
                gate = Gate(api, {'repository': 'example/platform', 'repositoryId': 1,
                                 'requester': 'release[bot]', 'base': 'main', 'branchPrefix': branch_prefix('main')}, store)
                with patch.object(control, 'CANDIDATE', root), patch.object(control, 'CONTROL', store), \
                        patch.object(control, 'snapshot', side_effect=api.snapshot), \
                        patch.object(workspace, 'snapshot', side_effect=api.snapshot):
                    control.export_pr(gate, 7, [owner_name])
                    for name in paths:
                        (root / name).write_bytes(base[name].replace(version, updated))
                    check.source(root, control.load('check-plan.json'))
                    repair = workspace.changes(root, control.load('baseline.json'), control.allowed(owners))
                    self.assertEqual(set(repair), {name for name in paths if name.endswith('.terraform.lock.hcl')})
                    gate.publish(7, api.head, api.base, repair, control.allowed(owners),
                                 modes={name: '100644' for name in paths})
