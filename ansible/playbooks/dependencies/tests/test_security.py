"""Reject unsafe maintenance inputs before they reach downloads or the filesystem."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
import urllib.request

from playbooks.dependencies.files.security import PublicRedirect, archive_files, owned_path, public_url, relative


class SecurityTests(unittest.TestCase):
    def test_only_asset_cdn_redirects_may_include_signed_queries(self):
        handler = PublicRedirect()
        request = urllib.request.Request('https://github.com/approved/releases/download/v1/tool.zip')
        target = 'https://release-assets.githubusercontent.com/asset?signature=abc&expires=1'
        redirected = handler.redirect_request(request, None, 302, '', {}, target)
        self.assertEqual(redirected.full_url, target)
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, '', {}, 'https://github.com/asset?token=x')
    def test_downloads_reject_private_origins_and_ambiguous_urls(self):
        for url in ('http://github.com/a', 'https://127.0.0.1/x', 'https://github.com.evil/x',
                    'https://user:secret@github.com/a', 'https://github.com:8443/a',
                    'https://github.com/a?token=x', 'https://github.com/a/%2e%2e/b',
                    'https://github.com/a/../b', 'https://github.com/a#b'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                public_url(url)
        with self.assertRaises(ValueError):
            public_url('https://github.com/unapproved/release', prefix='https://github.com/approved/')

    def test_paths_reject_traversal_and_links(self):
        for path in ('../file', '/file', 'a/../../file', 'a\\file', 'a//b', 'C:/file', '.env/../file'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                relative(path)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'target').mkdir()
            (root / 'link').symlink_to(root / 'target', target_is_directory=True)
            with self.assertRaises(ValueError):
                owned_path(root, 'link/file')

    def test_archive_rejects_links_traversal_and_duplicates_without_extraction(self):
        for name, kind, duplicate in (('../escape', tarfile.REGTYPE, False),
                                       ('file', tarfile.SYMTYPE, False),
                                       ('file', tarfile.REGTYPE, True)):
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode='w') as archive:
                item = tarfile.TarInfo(name)
                item.type, item.size = kind, 1 if kind == tarfile.REGTYPE else 0
                archive.addfile(item, io.BytesIO(b'x'))
                if duplicate:
                    archive.addfile(item, io.BytesIO(b'x'))
            with self.assertRaises(ValueError):
                archive_files(raw.getvalue())


if __name__ == '__main__':
    unittest.main()
