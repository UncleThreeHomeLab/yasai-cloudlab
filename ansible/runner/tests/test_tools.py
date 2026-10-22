import json
import hashlib
import re
import subprocess
import unittest
from pathlib import Path

import yaml


class BootstrapToolTests(unittest.TestCase):
    def test_kubernetes_collection_matches_checked_archive(self):
        dockerfile = (Path(__file__).resolve().parents[1] / 'Dockerfile').read_text()
        archive = next(line for line in dockerfile.splitlines() if line.startswith('ADD ') and 'kubernetes-core-' in line)
        self.assertRegex(archive, r'^ADD --checksum=sha256:[a-f0-9]{64} https://galaxy.ansible.com/')
        version = re.search(r'kubernetes-core-([0-9.]+).tar.gz', archive).group(1)
        packaged = Path('/opt/runner/kubernetes-core.tar.gz')
        expected = re.search(r'--checksum=sha256:([a-f0-9]{64})', archive).group(1)
        self.assertEqual(hashlib.sha256(packaged.read_bytes()).hexdigest(), expected)
        manifest = Path('/usr/share/ansible/collections/ansible_collections/kubernetes/core/MANIFEST.json')
        self.assertEqual(json.loads(manifest.read_text())['collection_info']['version'], version)
        documentation = subprocess.check_output(['ansible-doc', '-j', 'kubernetes.core.k8s'], text=True, timeout=30)
        self.assertIn('server_side_apply', json.loads(documentation)['kubernetes.core.k8s']['doc']['options'])

    def test_bootstrap_crane_reuses_the_reviewed_source_and_module_locks(self):
        root = Path(__file__).resolve().parents[3]
        dockerfile = (root / 'ansible/runner/Dockerfile').read_text()
        sources = json.loads((root / 'platform/delivery/ci/tools/source.lock.json').read_text())['sources']
        crane = next(row for row in sources if row['name'] == 'crane')
        self.assertIn(crane['source'], dockerfile)
        self.assertIn(crane['sha256'], dockerfile)
        self.assertIn('COPY --from=ci-source tools/crane/go.mod tools/crane/go.sum ./', dockerfile)
        self.assertIn('GOTOOLCHAIN=local', dockerfile)
        self.assertIn('-mod=readonly', dockerfile)
        services = yaml.safe_load((root / 'compose.yaml').read_text())['services']
        for name in ('lab', 'infra', 'infra-github', 'infra-harbor', 'service'):
            self.assertEqual(services[name]['build']['additional_contexts'],
                             {'ci-source': './platform/delivery/ci'})

    def test_compose_build_contexts_exist_for_every_packaged_fixture(self):
        root = Path(__file__).resolve().parents[3]
        files = [root / 'compose.yaml',
                 *sorted((root / 'ansible/playbooks').rglob('compose*.yaml'))]
        for path in files:
            for name, service in yaml.safe_load(path.read_text()).get('services', {}).items():
                build = service.get('build')
                if not build:
                    continue
                context = build if isinstance(build, str) else build.get('context', '.')
                dockerfile = 'Dockerfile' if isinstance(build, str) else build.get('dockerfile', 'Dockerfile')
                with self.subTest(compose=path.relative_to(root), service=name):
                    self.assertTrue((path.parent / context / dockerfile).is_file())

    def test_installed_bootstrap_tools_match_checked_downloads(self):
        dockerfile = (Path(__file__).resolve().parents[1] / 'Dockerfile').read_text()
        tools = {
            'helm': (r'/helm-v([0-9.]+)-linux-amd64.tar.gz', ['version', '--short']),
            'tofu': (r'/tofu_([0-9.]+)_linux_amd64.zip', ['version']),
            'op': (r'/op_linux_amd64_v([0-9.]+).zip', ['--version']),
            'restic': (r'/restic_([0-9.]+)_linux_amd64.bz2', ['version']),
        }
        for name, (pattern, arguments) in tools.items():
            with self.subTest(tool=name):
                downloads = [line for line in dockerfile.splitlines()
                             if line.startswith('ADD ') and re.search(pattern, line)]
                self.assertEqual(len(downloads), 1)
                self.assertRegex(downloads[0], r'^ADD --checksum=sha256:[a-f0-9]{64} https://')
                expected = re.search(pattern, downloads[0]).group(1)
                actual = subprocess.check_output([name, *arguments], text=True, timeout=15)
                self.assertRegex(actual.splitlines()[0], r'(?<![0-9.])' + re.escape(expected) + r'(?![0-9.])')
