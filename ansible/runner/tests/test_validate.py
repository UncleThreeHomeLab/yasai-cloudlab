"""Keep local validation credential-free and lint scope explicit."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import validate


class ValidationTests(unittest.TestCase):
    def test_lint_gates_new_files_after_exclusions_without_consuming_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.example').write_text('\n'.join(
                prefix + suffix + '=' for prefix in ('VM', 'VM2')
                for suffix in ('_HOST', '_USER', '_PASSWORD')))
            playbooks = root / 'ansible/playbooks'
            playbooks.mkdir(parents=True)
            migrated = playbooks / 'setup.yml'
            migrated.write_text('---\n')
            legacy = root / 'ansible/apply.yml'
            legacy.write_text('---\n')
            with patch.object(validate, 'ROOT', root), \
                    patch.object(validate.subprocess, 'run') as run:
                validate.main()
            command = run.call_args_list[1].args[0]
            separator = command.index('--')
            self.assertIn(str(legacy), command[:separator])
            self.assertEqual(command[separator + 1:], [str(migrated)])
            self.assertEqual(run.call_count, 3)

    def test_missing_documented_inputs_fail_before_tool_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.env.example').write_text('VM_HOST=\n')
            with patch.object(validate, 'ROOT', root), \
                    patch.object(validate.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'documented VM bootstrap input names'):
                    validate.main()
            run.assert_not_called()
