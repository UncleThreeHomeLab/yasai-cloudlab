import bz2
import hashlib
import io
import json
import tarfile
import re
import unittest
import zipfile
from pathlib import Path

import yaml

from install_tools import binary


class BootstrapToolTests(unittest.TestCase):
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
        self.assertNotIn('crane', json.loads((root / 'ansible/runner/tools.lock.json').read_text()))
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
                    # Staged maintenance builds use a public copy of this exact owner context.
                    staged = re.fullmatch(r'\$\{DEPENDENCY_WORK_DIR:-[^}]+\}/candidate/(ansible/runner|platform/delivery/ci|ansible/playbooks/keycloak/tests/browser)', context)
                    directory = root / staged[1] if staged else path.parent / context
                    self.assertTrue(directory.is_dir())
                    if isinstance(build, dict) and 'dockerfile_inline' in build:
                        self.assertTrue(build['dockerfile_inline'].startswith('FROM '))
                    else:
                        self.assertTrue((directory / dockerfile).is_file())

    def test_archive_formats_preserve_exact_checked_binary(self):
        payload = b'synthetic-bootstrap-binary'
        zipped, tarred = io.BytesIO(), io.BytesIO()
        with zipfile.ZipFile(zipped, 'w') as archive:
            archive.writestr('tool', payload)
        with tarfile.open(fileobj=tarred, mode='w:gz') as archive:
            member = tarfile.TarInfo('tool')
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
        for suffix, data in (('.zip', zipped.getvalue()), ('.bz2', bz2.compress(payload)), ('.tar.gz', tarred.getvalue())):
            pin = {'url': 'https://example.invalid/tool' + suffix, 'sha256': hashlib.sha256(data).hexdigest()}
            with self.subTest(suffix=suffix):
                self.assertEqual(binary('tool', pin, data), payload)
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    binary('tool', pin, data + b'changed')

    def test_tar_symlink_cannot_select_an_external_binary(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            member = tarfile.TarInfo('tool')
            member.type, member.linkname = tarfile.SYMTYPE, '/unrelated'
            archive.addfile(member)
        data = output.getvalue()
        with self.assertRaisesRegex(ValueError, 'regular archive member'):
            binary('tool', {'url': 'https://example.invalid/tool.tar.gz', 'sha256': hashlib.sha256(data).hexdigest()}, data)
