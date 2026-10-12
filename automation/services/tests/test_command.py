from contextlib import redirect_stdout
import io
import unittest
from unittest.mock import Mock, patch

from automation.services import command
from automation.services.tests.fixtures import definition


class CommandTests(unittest.TestCase):
    def test_lifecycle_entry_points_reach_their_field_owner_checks(self):
        value = {'definition': definition()}
        owner = Mock()
        for action in ('ready', 'publish', 'retire'):
            with self.subTest(action=action), patch.object(command, 'read', return_value=value), \
                    patch('automation.services.owners.Owners', return_value=owner), \
                    patch.object(command, action) as operation, redirect_stdout(io.StringIO()):
                command.main([action, 'reviewed-bundle.json'])
                operation.assert_called_once_with(value['definition'], owner)
