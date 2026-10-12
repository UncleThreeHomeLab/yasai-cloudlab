import unittest
from unittest.mock import Mock, patch

from automation.data import notes_seed


class NotesSeedTests(unittest.TestCase):
    def test_existing_edited_note_is_preserved_without_object_writes(self):
        values = {'migrationRole':'notes_migration','database':'notes','bucket':'notes'}
        responses = ['', 'attachment_key:text,body:text,id:text,title:text', '1']
        with patch.object(notes_seed.control, 'settings', return_value=values), \
                patch.object(notes_seed.control, 'sql', side_effect=responses) as sql, \
                patch.object(notes_seed.control, 's3') as s3:
            self.assertEqual(notes_seed.run(), {'changed':False,'existing_note_preserved':True})
            s3.assert_not_called()
            self.assertFalse(any('INSERT' in call.args[0] for call in sql.call_args_list))
