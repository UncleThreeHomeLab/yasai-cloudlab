"""Validate the isolated runner's external pins and locked package sources."""
import base64
import hashlib
import json
from pathlib import Path
import re
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[4]
OWNER = ROOT / 'platform/delivery/ci/runner'
CONTEXT = OWNER.parent


class RunnerImageTests(unittest.TestCase):
    def test_external_images_source_and_runtime_are_fixed_and_keep_secret_inputs_out(self):
        lock = json.loads((OWNER / 'source.lock.json').read_text())
        dockerfile = (CONTEXT / 'Dockerfile').read_text()
        tools = json.loads((CONTEXT / 'tools/source.lock.json').read_text())
        external = [image for image in re.findall(r'^FROM (\S+)', dockerfile, re.M)
                    if image not in ('source', 'source-inputs', 'compiler', 'scratch')]
        self.assertEqual(set(external), {lock['sdk'], tools['compiler'],
                                        lock['qualification_builder'], *lock['images'].values(),
                                        *tools['images'].values()})
        self.assertTrue(all(re.fullmatch(r'.+@sha256:[a-f0-9]{64}', image) for image in external))
        self.assertIn(lock['source']['url'], dockerfile)
        self.assertIn(lock['source']['sha256'], dockerfile)
        self.assertIn('RunnerVersion=' + lock['runner_version'], dockerfile)
        self.assertIn('"version": "' + lock['runtime_version'] + '"', dockerfile)
        self.assertIn('--locked-mode', dockerfile)
        self.assertIn('RestoreLockedMode=true', dockerfile)
        self.assertNotIn('NuGetAudit=false', dockerfile)
        bootstrap = (ROOT / 'ansible/runner/Dockerfile').read_text()
        self.assertIn('FROM ' + lock['images']['trivy'] + ' AS trivy', bootstrap)
        self.assertEqual((CONTEXT / '.dockerignore').read_text().splitlines()[0], '**')
        self.assertNotIn('eligibility.json', (CONTEXT / '.dockerignore').read_text())
        compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())['services']['ci-runner-image']
        self.assertEqual(compose['build']['context'], './platform/delivery/ci')
        self.assertEqual(compose['build']['target'], 'runner')
        self.assertEqual(compose['build']['additional_contexts'],
                         {'cloudlab-bootstrap': './ansible/runner'})
        self.assertEqual(compose['platform'], 'linux/amd64')
        self.assertNotIn('volumes', compose)
        self.assertNotIn('env_file', compose)
        self.assertNotIn('environment', compose)
        builder = yaml.safe_load((ROOT / 'platform/delivery/ci/runner.values.yaml').read_text())['template']['spec']
        self.assertEqual(next(row['image'] for row in builder['containers'] if row['name'] == 'builder'),
                         lock['qualification_builder'])

    def test_go_sources_and_dependency_contents_are_locked_for_native_builds(self):
        tools = CONTEXT / 'tools'
        lock = json.loads((tools / 'source.lock.json').read_text())
        dockerfile = (CONTEXT / 'Dockerfile').read_text()
        self.assertIn('GOTOOLCHAIN=local', dockerfile)
        self.assertIn('-mod=readonly', dockerfile)
        self.assertNotIn('GONOSUMDB', dockerfile)
        self.assertNotIn('GOSUMDB=off', dockerfile)
        self.assertEqual({row['name'] for row in lock['sources']},
                         {'buildkit', 'cosign', 'crane', 'runc', 'rootlesskit', 'arc'})
        for source in lock['sources']:
            self.assertIn(source['source'], dockerfile)
            self.assertIn(source['sha256'], dockerfile)
            for name in ('go.mod', 'go.sum'):
                path = tools / source['name'] / name
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), source['modules'][name])
            modules = (tools / source['name'] / 'go.mod').read_text()
            self.assertEqual(re.findall(r'^replace .+$', modules, re.M), source.get('replacements', []))
            if source['name'] != 'crane':
                self.assertRegex(modules, r'golang.org/x/net v0[.]60[.]0\b')
            if source['name'] == 'buildkit':
                self.assertIn('github.com/moby/go-archive v0.3.0', modules)

    def test_all_native_projects_pin_package_contents_and_the_security_fixes(self):
        lock = json.loads((OWNER / 'source.lock.json').read_text())
        projects = list((OWNER / 'nuget').glob('*/packages.lock.json'))
        self.assertEqual(lock['nuget'], {path.parent.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                        for path in projects})
        self.assertEqual(set(lock['overlays']), {'runner.patch', 'TrustedWorkflow.cs', 'TrustedTemplate.cs',
                                                'health.py', 'tests/Fixtures.cs', 'tests/TrustedWorkflowL0.cs'})
        for relative, sha256 in lock['overlays'].items():
            self.assertEqual(hashlib.sha256((OWNER / relative).read_bytes()).hexdigest(), sha256)
        self.assertEqual({path.parent.name for path in projects}, {
            'Sdk', 'Runner.Common', 'Runner.Sdk', 'Runner.Listener', 'Runner.Worker',
            'Runner.PluginHost', 'Runner.Plugins', 'Test'})
        seen = set()
        for path in projects:
            dependencies = json.loads(path.read_text())['dependencies']
            for framework in dependencies.values():
                for name, package in framework.items():
                    if package['type'] == 'Project':
                        continue
                    self.assertNotRegex(package['resolved'], r'[\[\]*(),]')
                    self.assertEqual(len(base64.b64decode(package['contentHash'], validate=True)), 64)
                    if name in lock['security_packages']:
                        self.assertEqual(package['resolved'], lock['security_packages'][name])
                        seen.add(name)
        self.assertEqual(seen, set(lock['security_packages']))
