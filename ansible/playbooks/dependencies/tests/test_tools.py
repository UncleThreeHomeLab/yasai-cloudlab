"""Tool updates include URL, checksum and every native caller constraint."""
import hashlib
import base64
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

import yaml

from playbooks.dependencies.files import tools


class ToolTests(unittest.TestCase):
    def test_final_helm_provenance_checks_both_architectures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relative = 'ansible/runner/helm.lock.json'
            target = root / relative
            target.parent.mkdir(parents=True)
            old = {'version': 'v4.3.0', 'sha256': {'amd64': 'a' * 64, 'arm64': 'b' * 64}}
            raw = {'amd64': b'official amd64 archive', 'arm64': b'official arm64 archive'}
            new = {'version': 'v4.3.1', 'sha256': {arch: tools.digest(value) for arch, value in raw.items()}}
            target.write_text(json.dumps(new))
            plan = {'baseFiles': {relative: base64.b64encode(json.dumps(old).encode()).decode()}}
            fetch = lambda url, **kwargs: raw['arm64' if 'arm64' in url else 'amd64']
            tools.provenance(root, plan, fetch=fetch)
            new['sha256']['arm64'] = 'c' * 64
            target.write_text(json.dumps(new))
            with self.assertRaisesRegex(ValueError, 'architecture checksum'):
                tools.provenance(root, plan, fetch=fetch)

    def test_helm_finalization_updates_all_eight_native_metadata_companions(self):
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root / 'ansible/runner/helm.lock.json'
            pin.parent.mkdir(parents=True)
            pin.write_text(json.dumps({'version': 'v4.3.1'}))
            owners = ('certificates/cert-manager', 'storage/longhorn', 'secrets/external-secrets', 'delivery/argocd',
                      'connectivity/istio/base', 'connectivity/istio/istiod', 'connectivity/istio/cni', 'connectivity/istio/ztunnel')
            for owner in owners:
                path = root / 'platform' / owner / 'artifact.lock.json'
                path.parent.mkdir(parents=True)
                path.write_text(json.dumps({'helm_version': '4.3.0' if owner == 'delivery/argocd' else 'v4.3.0+gold'}))
            with patch('playbooks.dependencies.files.toolchain.embedded'), \
                    patch('subprocess.run', return_value=Mock(returncode=0, stdout='v4.3.1+gnew\n')):
                result = tools.finalize_helm(root)
            self.assertEqual(len(result['metadataUpdated']), 8)
            for owner in owners:
                expected = '4.3.1' if owner == 'delivery/argocd' else 'v4.3.1+gnew'
                self.assertEqual(json.loads((root / 'platform' / owner / 'artifact.lock.json').read_bytes())['helm_version'], expected)

    def test_cmctl_rejects_bad_source_or_stale_checksum_before_execution(self):
        pin = {'version': '2.6.1', 'url': 'https://github.com/cert-manager/cmctl/releases/download/v2.6.1/cmctl_linux_amd64',
               'sha256': 'a' * 64}
        with patch('subprocess.run') as execute:
            with self.assertRaises(ValueError):
                tools.check_cmctl('/unused', pin=pin, raw=b'\x7fELFfixture')
            with self.assertRaises(ValueError):
                tools.check_cmctl('/unused', pin=dict(pin, url='https://github.com/attacker/cmctl'), raw=b'\x7fELFfixture')
            execute.assert_not_called()
    def test_gateway_plugin_repairs_url_checksum_and_only_owned_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / 'platform/delivery/rollouts/artifact.lock.json'
            lock.parent.mkdir(parents=True)
            lock.write_text(json.dumps({'plugin': {'version': 'v0.17.0'}}))
            values = lock.parent / 'values.yaml'
            values.write_text('argo-rollouts:\n  controller:\n    trafficRouterPlugins:\n      - name: argoproj-labs/gatewayAPI\n')
            tools.update(root, 'gateway-api-plugin', '0.17.1', fetch=lambda *args, **kwargs: b'\x7fELFfixture')
            current = json.loads(lock.read_bytes())['plugin']
            plugin = yaml.safe_load(values.read_bytes())['argo-rollouts']['controller']['trafficRouterPlugins'][0]
            self.assertEqual(plugin['location'], current['url'])
            self.assertEqual(plugin['sha256'], current['sha256'])
            with self.assertRaises(ValueError):
                tools.update(root, 'gateway-api-plugin', '0.18.0', fetch=lambda *args, **kwargs: self.fail('download'))
    def test_tofu_update_changes_complete_pin_and_all_required_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = root / 'ansible/runner'
            runner.mkdir(parents=True)
            (runner / 'tools.lock.json').write_text(json.dumps({'tofu': {'version': '1.13.1'}}))
            callers = ('infra/github/versions.tf', 'infra/cloudflare/versions.tf',
                       'ansible/playbooks/data/tests/provider-fixture/versions.tf')
            for relative in callers:
                path = root / relative
                path.parent.mkdir(parents=True)
                path.write_text('terraform { required_version = "= 1.13.1" }')
            stream = io.BytesIO()
            with zipfile.ZipFile(stream, 'w') as archive:
                archive.writestr('tofu', b'fixed test executable')
            raw = stream.getvalue()
            requested = []

            def fetch(url, *, prefix):
                requested.append((url, prefix))
                return raw

            result = tools.update(root, 'tofu', '1.13.2', fetch=fetch)
            pin = json.loads((runner / 'tools.lock.json').read_text())['tofu']
            self.assertEqual(pin['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(pin['version'], '1.13.2')
            self.assertTrue(pin['url'].endswith('/v1.13.2/tofu_1.13.2_linux_amd64.zip'))
            self.assertTrue(all('1.13.2' in (root / path).read_text() for path in callers))
            self.assertEqual(result['requiresBuild'], ['candidate-runner'])
            self.assertEqual(len(requested), 1)

    def test_helm_requires_both_archives_and_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'ansible/runner/helm.lock.json'
            target.parent.mkdir(parents=True)
            target.write_text(json.dumps({'version': 'v4.3.0', 'sha256': {}}))
            from playbooks.dependencies.files.security import archive_files
            import tarfile

            def fetch(url, *, prefix):
                arch = 'arm64' if 'arm64' in url else 'amd64'
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                    member = tarfile.TarInfo('linux-' + arch + '/helm')
                    member.size = 4
                    archive.addfile(member, io.BytesIO(b'helm'))
                return stream.getvalue()

            tools.update(root, 'helm', '4.3.1', fetch=fetch)
            lock = json.loads(target.read_text())
            self.assertEqual(set(lock['sha256']), {'amd64', 'arm64'})
            self.assertEqual(lock['version'], 'v4.3.1')

    def test_unknown_tool_or_command_in_version_is_rejected_before_download(self):
        for name, version in (('unknown', '1.0.0'), ('tofu', '1.13.1; echo secret'), ('op', '../../escape')):
            with self.assertRaises(ValueError):
                tools.update('/unused', name, version, fetch=lambda *args, **kwargs: self.fail('unexpected download'))

    def test_k3s_updates_both_binaries_installer_and_isolated_proof_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'ansible/playbooks/k3s/vars.yml'
            target.parent.mkdir(parents=True)
            target.write_text('k3s_version: v1.36.5+k3s1\nk3s_binaries: {}\nk3s_installer_checksum: old\n')
            original = target.read_bytes()
            proof = root / 'ansible/playbooks/keycloak/tests/compose.identity-operator-proof.yaml'
            proof.parent.mkdir(parents=True)
            proof.write_text('services:\n  cluster:\n    image: rancher/k3s:v1.36.5-k3s1@sha256:' + 'a' * 64 + '\n')
            binaries = {'k3s': b'\x7fELFamd64', 'k3s-arm64': b'\x7fELFarm64'}

            def fetch(url, *, prefix):
                if url.endswith('install.sh'):
                    return b'#!/bin/sh\nfixed installer'
                asset = 'k3s-arm64' if 'arm64' in url else 'k3s'
                if 'sha256sum-' in url:
                    return (tools.digest(binaries[asset]) + '  ' + asset + '\n').encode()
                return binaries[asset]

            reference = 'rancher/k3s:v1.36.6-k3s1@sha256:' + 'b' * 64
            with patch('playbooks.dependencies.files.ci_tools.image_digest', return_value=reference):
                tools.update(root, 'k3s', '1.36.6+k3s1', fetch=fetch)
            lock = yaml.safe_load(target.read_bytes())
            self.assertEqual(lock['k3s_version'], 'v1.36.6+k3s1')
            self.assertEqual(lock['k3s_binaries']['aarch64']['sha256'], tools.digest(binaries['k3s-arm64']))
            self.assertIn(reference, proof.read_text())
            plan = {'baseFiles': {'ansible/playbooks/k3s/vars.yml': base64.b64encode(original).decode()}}
            tools.provenance(root, plan, fetch=fetch)
            lock['k3s_binaries']['aarch64']['sha256'] = 'c' * 64
            target.write_text(yaml.safe_dump(lock))
            with self.assertRaisesRegex(ValueError, 'official release manifest'):
                tools.provenance(root, plan, fetch=fetch)
            with self.assertRaises(ValueError):
                tools.update(root, 'k3s', '1.37.1+k3s1', fetch=fetch)
