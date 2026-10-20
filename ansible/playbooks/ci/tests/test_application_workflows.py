"""Shared workflows bind local pools and immutable implementation before application checkout."""
import unittest
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
import yaml

from playbooks.ci.files.chart import ROOT


class ApplicationWorkflowTests(unittest.TestCase):
    def test_shared_application_tests_cannot_select_hosted_runners_or_receive_registry_secrets(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/application-test.yaml').read_text())
        self.assertEqual(set(workflow['on']), {'workflow_call'})
        self.assertNotIn('secrets', workflow['on']['workflow_call'])
        job, = workflow['jobs'].values()
        self.assertEqual(job['runs-on'], "${{ format('cloudlab-{0}', inputs.application) }}")
        self.assertEqual(job['permissions'], {'contents': 'read', 'pull-requests': 'read'})
        self.assertNotIn('container', job)
        self.assertNotIn('services', job)
        checkout, build = job['steps']
        self.assertRegex(checkout['uses'], r'^actions/checkout@[a-f0-9]{40}$')
        self.assertFalse(checkout['with']['persist-credentials'])
        self.assertIn('buildctl --addr tcp://127.0.0.1:1234 build', build['run'])
        self.assertNotIn('secrets.', str(workflow))

    def test_publisher_is_local_main_only_with_pinned_platform_code_before_app_checkout(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/application-publish.yaml').read_text())
        self.assertEqual(set(workflow['on']), {'workflow_call'})
        self.assertEqual(workflow['on']['workflow_call']['inputs'], {'application': {'required': True, 'type': 'string'}})
        self.assertNotIn('secrets', workflow['on']['workflow_call'])
        job, = workflow['jobs'].values()
        self.assertEqual(job['runs-on'], "${{ format('cloudlab-{0}-publish', inputs.application) }}")
        self.assertEqual(job['permissions'], {'contents': 'read', 'pull-requests': 'read', 'id-token': 'write'})
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])
        self.assertIn("github.event_name == 'push'", job['if'])
        self.assertNotIn('container', job)
        self.assertNotIn('services', job)
        revision, platform, app, publish = job['steps']
        self.assertEqual(revision['id'], 'platform')
        self.assertEqual(platform['with']['repository'], 'UncleThreeHomeLab/yasai-cloudlab')
        self.assertEqual(platform['with']['ref'], '${{ steps.platform.outputs.revision }}')
        self.assertEqual(platform['with']['path'], 'platform')
        self.assertEqual(app['with']['path'], 'application')
        for checkout in (platform, app):
            self.assertRegex(checkout['uses'], r'^actions/checkout@[a-f0-9]{40}$')
            self.assertFalse(checkout['with']['persist-credentials'])
        self.assertEqual(publish['run'], 'python3 -I -S platform/ansible/playbooks/ci/files/publisher.py')
        self.assertFalse(workflow['concurrency']['cancel-in-progress'])
        self.assertNotIn('secrets.', str(workflow))
        self.assertFalse((ROOT / '.github/workflows/propose-ci-release.yaml').exists())

    def test_publisher_checkout_uses_only_its_admin_approved_immutable_workflow_revision(self):
        workflow = yaml.safe_load((ROOT / '.github/workflows/application-publish.yaml').read_text())
        step = workflow['jobs']['publish']['steps'][0]
        script = step['run'].split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        prefix = 'https://github.com/UncleThreeHomeLab/yasai-cloudlab/.github/workflows/application-publish.yaml@'
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'output'
            for identity, valid in ((prefix + 'a' * 40, True), (prefix + 'main', False),
                                    (prefix + '../../outside', False),
                                    (prefix.replace('UncleThreeHomeLab', 'other') + 'a' * 40, False)):
                with patch.object(Path, 'read_text', autospec=True, return_value=json.dumps({'workflow_identity': identity})) as read, \
                        patch.dict(os.environ, {'GITHUB_OUTPUT': str(output)}):
                    if valid:
                        exec(compile(script, '<approved revision>', 'exec'), {})
                    else:
                        with self.assertRaises(SystemExit):
                            exec(compile(script, '<approved revision>', 'exec'), {})
                    self.assertEqual(str(read.call_args.args[0]), '/run/cloudlab-publisher/config/config.json')
                if valid:
                    self.assertEqual(output.read_text(), 'revision=' + 'a' * 40 + '\n')
                    output.unlink()
                else:
                    self.assertFalse(output.exists())
