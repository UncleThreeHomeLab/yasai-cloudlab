"""Browser package, native lock and image remain one verified update."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from playbooks.dependencies.files import browser
from playbooks.dependencies.files.inventory import ROOT
from playbooks.dependencies.tests.fixtures import browser_registry


class BrowserTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.before = {}
        for name in ('Dockerfile', 'package.json', 'package-lock.json'):
            relative = browser.BASE + name
            self.before[name] = (ROOT / relative).read_bytes()
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(self.before[name])
        locked = json.loads(self.before['package-lock.json'])
        self.version = browser.lock(locked)
        major, minor, patch = self.version.split('.')
        self.updated = major + '.' + minor + '.' + str(int(patch) + 1)
        self.responses = browser_registry(locked, self.updated)

    def fetch(self, url, *, prefix):
        self.assertTrue(url.startswith(prefix))
        return self.responses[url]

    def update(self):
        return browser.update(self.root, {'version': self.updated}, fetch=self.fetch,
                              resolve=lambda reference: reference + '@sha256:' + 'd' * 64)

    def assert_unchanged(self):
        for name, raw in self.before.items():
            self.assertEqual((self.root / browser.BASE / name).read_bytes(), raw)

    def test_complete_patch_update_preserves_install_and_native_lock_graph(self):
        result = self.update()
        self.assertEqual(result['status'], 'pending-build')
        package = (self.root / browser.BASE / 'package.json').read_bytes()
        locked = (self.root / browser.BASE / 'package-lock.json').read_bytes()
        browser.validate_package(self.before['package.json'], package)
        browser.validate_lock(self.before['package-lock.json'], locked)
        self.assertEqual(browser.lock(json.loads(locked)), self.updated)
        dockerfile = (self.root / browser.BASE / 'Dockerfile').read_text()
        self.assertIn('playwright:v' + self.updated + '-noble@sha256:' + 'd' * 64, dockerfile)
        self.assertEqual(dockerfile.splitlines()[1:], self.before['Dockerfile'].decode().splitlines()[1:])
        self.assertEqual(json.loads(package)['dependencies'], {'playwright': self.updated})

    def test_foreign_tarball_changed_graph_and_corrupt_archive_fail_before_writes(self):
        url = browser.REGISTRY + 'playwright/' + self.updated
        original = self.responses[url]
        for change in ('origin', 'graph', 'checksum'):
            with self.subTest(change=change):
                metadata = json.loads(original)
                if change == 'origin':
                    metadata['dist']['tarball'] = 'https://attacker.invalid/package.tgz'
                elif change == 'graph':
                    metadata['dependencies']['unreviewed-package'] = '1.0.0'
                else:
                    self.responses[browser.tarball('playwright', self.updated)] += b'corrupt'
                self.responses[url] = json.dumps(metadata).encode()
                with self.assertRaises(ValueError):
                    self.update()
                self.assert_unchanged()

    def test_native_lock_rejects_wrong_origin_commands_identity_and_integrity(self):
        self.update()
        changed = json.loads((self.root / browser.BASE / 'package-lock.json').read_bytes())
        for change in ('origin', 'commands', 'identity', 'integrity', 'graph'):
            with self.subTest(change=change):
                document = copy.deepcopy(changed)
                entry = document['packages']['node_modules/playwright']
                if change == 'origin':
                    entry['resolved'] = 'https://attacker.invalid/package.tgz'
                elif change == 'commands':
                    entry['bin']['playwright'] = 'unreviewed.js'
                elif change == 'identity':
                    document['name'] = document['packages']['']['name'] = 'different-owner'
                elif change == 'integrity':
                    entry['integrity'] = 'sha512-invalid'
                else:
                    document['packages']['node_modules/unreviewed'] = {}
                with self.assertRaises(ValueError):
                    browser.validate_lock(self.before['package-lock.json'], json.dumps(document).encode())
        package = json.loads(self.before['package.json'])
        package['scripts'] = {'install': 'unreviewed-command'}
        with self.assertRaises(ValueError):
            browser.validate_package(self.before['package.json'], json.dumps(package).encode())

    def test_wrong_version_line_and_replaced_immutable_package_fail(self):
        with self.assertRaises(ValueError):
            browser.update(self.root, {'version': '99.0.0'}, fetch=self.fetch)
        self.assert_unchanged()
        self.responses = browser_registry(json.loads(self.before['package-lock.json']), self.version)
        with self.assertRaises(ValueError):
            browser.update(self.root, {'version': self.version}, fetch=self.fetch)
        self.assert_unchanged()
