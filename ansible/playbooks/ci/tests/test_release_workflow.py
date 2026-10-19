"""Execute the pinned receiver bootstrap without network or service credentials."""
import io
import os
from pathlib import Path
import re
import unittest
from unittest.mock import patch

import yaml

from playbooks.ci.files.chart import ROOT


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / '.github/workflows/propose-ci-release.yaml').read_text())
        self.step, = self.workflow['jobs']['propose']['steps']
        rows = self.step['run'].splitlines()
        self.assertEqual(rows[0], "python3 -I -S - <<'PY'")
        self.assertEqual(rows[-1], 'PY')
        self.code = compile('\n'.join(rows[1:-1]), 'receiver-bootstrap', 'exec')

    def test_only_hosted_dispatch_or_reusable_receiver_can_get_gitops_write_permission(self):
        self.assertEqual(set(self.workflow['on']), {'workflow_dispatch', 'workflow_call'})
        self.assertEqual(set(self.workflow['on']['workflow_dispatch']['inputs']),
                         {'digest', 'source_revision', 'workflow_run_id'})
        job = self.workflow['jobs']['propose']
        self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        self.assertEqual(job['timeout-minutes'], 5)
        self.assertEqual(job['permissions'], {'contents': 'write', 'pull-requests': 'write'})
        self.assertEqual(self.step['env']['GH_TOKEN'], '${{ github.token }}')
        self.assertEqual(set(self.step['env']), {'GH_TOKEN', 'RELEASE_SCOPE', 'RELEASE_ACTOR'})
        self.assertIn("github.ref == 'refs/heads/main'", job['if'])

    def test_checksum_checked_code_runs_without_vault_or_other_job_secrets(self):
        source = (ROOT / 'ansible/playbooks/ci/files/release.py').read_bytes()
        environment = {key: 'synthetic' for key in (
            'PATH', 'HOME', 'GH_TOKEN', 'GITHUB_EVENT_PATH', 'GITHUB_REPOSITORY',
            'GITHUB_REF', 'GITHUB_ACTOR', 'GITHUB_EVENT_NAME', 'RUNNER_ENVIRONMENT',
            'RELEASE_SCOPE', 'RELEASE_ACTOR')}
        environment.update(OP_PROVISION_SERVICE_ACCOUNT_TOKEN='never-pass-writer',
                           OP_SERVICE_ACCOUNT_TOKEN='never-pass-reader', UNRELATED_SECRET='never-pass-other')
        def execute(command, **kwargs):
            self.assertEqual(command[1:3], ['-I', '-S'])
            self.assertEqual(Path(command[-1]).read_bytes(), source)
            self.assertEqual(kwargs['env']['GH_TOKEN'], 'synthetic')
            self.assertFalse({'OP_PROVISION_SERVICE_ACCOUNT_TOKEN', 'OP_SERVICE_ACCOUNT_TOKEN',
                              'UNRELATED_SECRET'} & set(kwargs['env']))
            self.assertTrue(kwargs['check'])
            self.assertEqual(kwargs['timeout'], 270)
        with patch.dict(os.environ, environment), \
                patch('urllib.request.urlopen', return_value=io.BytesIO(source)) as download, \
                patch('subprocess.run', side_effect=execute) as run:
            exec(self.code, {})
            run.assert_called_once()
            url = download.call_args.args[0]
            self.assertRegex(url, re.compile(r'^https://raw[.]githubusercontent[.]com/'
                r'UncleThreeHomeLab/yasai-cloudlab/[a-f0-9]{40}/ansible/playbooks/ci/files/release[.]py$'))

    def test_changed_download_cannot_execute_or_use_gitops_token(self):
        with patch('urllib.request.urlopen', return_value=io.BytesIO(b'changed source')), \
                patch('subprocess.run') as run, self.assertRaises(SystemExit):
            exec(self.code, {})
        run.assert_not_called()
