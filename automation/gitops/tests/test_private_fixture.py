import base64
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import private_fixture


class PrivateFixtureTests(unittest.TestCase):
    def test_repeat_does_not_write_existing_fixture(self):
        content = (Path(private_fixture.__file__).resolve().parents[2] /
                   'gitops/fixtures/private/configmap.yaml').read_bytes()
        api = Mock()
        api.request.return_value = {'content': base64.b64encode(content).decode()}
        with patch.object(private_fixture, 'inspect', return_value={'private': True}):
            result = private_fixture.prepare(api, {'PRIVATE_TEST_REPOSITORY': 'https://github.com/example/fixture.git'})
        self.assertFalse(result['fixture_published'])
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))

    def test_refuses_to_overwrite_different_content(self):
        api = Mock()
        api.request.return_value = {'content': base64.b64encode(b'unrelated').decode()}
        with patch.object(private_fixture, 'inspect', return_value={'private': True}):
            with self.assertRaisesRegex(RuntimeError, 'overwrite refused'):
                private_fixture.prepare(api, {'PRIVATE_TEST_REPOSITORY': 'https://github.com/example/fixture.git'})
        self.assertTrue(all(call.args[0] == 'GET' for call in api.request.call_args_list))
