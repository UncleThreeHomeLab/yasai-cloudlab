from contextlib import contextmanager, nullcontext
import unittest
from unittest.mock import patch

from apps.notes import seed as notes_seed


class NotesSeedTests(unittest.TestCase):
    def test_existing_edited_note_is_preserved_without_object_writes(self):
        values = {'migrationRole': 'notes_migration', 'database': 'notes', 'bucket': 'notes'}
        responses = ['', 'attachment_key:text,body:text,id:text,title:text', '1']
        with patch.object(notes_seed.control, 'locked', return_value=nullcontext()), \
                patch.object(notes_seed.control, 'settings', return_value=values), \
                patch.object(notes_seed.control, 'sql', side_effect=responses) as sql, \
                patch.object(notes_seed.control, 's3') as s3:
            self.assertEqual(notes_seed.run(), {'changed': False, 'existing_note_preserved': True})
            s3.assert_not_called()
            self.assertFalse(any('INSERT' in call.args[0] for call in sql.call_args_list))

    def test_seed_requires_data_owner_lock_and_releases_it(self):
        events = []
        @contextmanager
        def lock():
            events.append('lock')
            try: yield
            finally: events.append('release')
        def seed():
            events.append('seed')
            return {'changed': False}
        with patch.object(notes_seed.control, 'locked', lock), patch.object(notes_seed, 'seed', seed):
            self.assertEqual(notes_seed.run(), {'changed': False})
        self.assertEqual(events, ['lock', 'seed', 'release'])
        with patch.object(notes_seed.control, 'locked', side_effect=RuntimeError('owner busy')), \
                patch.object(notes_seed, 'seed') as seed:
            with self.assertRaises(RuntimeError): notes_seed.run()
            seed.assert_not_called()
