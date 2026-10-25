"""Validate public maintenance inputs before downloads or file writes."""
import hashlib
import io
from pathlib import Path, PurePosixPath
import re
import tarfile
import urllib.parse
import urllib.request
import zipfile

MAX_ARTIFACT = 256 * 1024 * 1024
PUBLIC_HOSTS = frozenset({
    'github.com', 'codeload.github.com', 'objects.githubusercontent.com',
    'release-assets.githubusercontent.com', 'get.helm.sh', 'go.dev', 'dl.google.com',
    'cache.agilebits.com', 'pkgs.tailscale.com', 'charts.jetstack.io',
    'helm.releases.hashicorp.com', 'raw.githubusercontent.com',
    'dl-cdn.alpinelinux.org', 'snapshot.debian.org',
    'helm.goharbor.io', 'charts.jetstack.io', 'charts.longhorn.io',
    'seaweedfs.github.io', 'kyverno.github.io', 'kiali.org',
    'istio-release.storage.googleapis.com', 'grafana.github.io',
    'grafana-community.github.io', 'argoproj.github.io',
    'charts.external-secrets.io', 'cloudnative-pg.github.io',
    'prometheus-community.github.io',
    'pypi.org', 'files.pythonhosted.org',
    'registry.npmjs.org',
    'tuf-repo-cdn.sigstore.dev',
})


def digest(data):
    return hashlib.sha256(data).hexdigest()


def relative(value):
    if not isinstance(value, str) or not value or '\\' in value or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('Maintenance path must be an explicit relative POSIX path')
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ('', '.', '..') for part in value.split('/')) or ':' in value:
        raise ValueError('Maintenance path escapes its owner')
    return path


def owned_path(root, value):
    path = Path(root) / relative(value)
    if not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Maintenance path escapes its owner')
    current = path
    while current != Path(root):
        if current.is_symlink():
            raise ValueError('Maintenance paths must not traverse symlinks')
        current = current.parent
    return path


def public_url(value, *, prefix=None):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != 'https' or parsed.hostname not in PUBLIC_HOSTS or
            parsed.port not in (None, 443) or parsed.username or parsed.password or
            parsed.query or parsed.fragment or '\\' in value or
            re.search(r'%2f|%5c|%2e|%00', value, re.I) or
            any(part in ('.', '..') for part in parsed.path.split('/'))):
        raise ValueError('Maintenance download must use an approved public HTTPS origin')
    if prefix and not value.startswith(prefix):
        raise ValueError('Maintenance download differs from its approved upstream')
    return value


class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        parsed = urllib.parse.urlsplit(target)
        public_url(urllib.parse.urlunsplit(parsed._replace(query='')))
        # GitHub's asset CDN signs redirect URLs. Callers still cannot supply queries.
        if parsed.query and (parsed.hostname not in {
                'release-assets.githubusercontent.com', 'objects.githubusercontent.com'} or
                len(parsed.query) > 16384 or any(ord(char) < 32 for char in parsed.query)):
            raise ValueError('Unexpected maintenance redirect query')
        return super().redirect_request(request, fp, code, message, headers, target)


def download(url, *, prefix, sha256=None):
    public_url(url, prefix=prefix)
    with urllib.request.build_opener(PublicRedirect()).open(url, timeout=120) as response:
        raw = response.read(MAX_ARTIFACT + 1)
    if len(raw) > MAX_ARTIFACT:
        raise ValueError('Maintenance artifact exceeds its size limit')
    if sha256 is not None and digest(raw) != sha256:
        raise ValueError('Maintenance artifact checksum mismatch')
    return raw


def archive_files(raw, *, max_unpacked=MAX_ARTIFACT):
    """Inspect archives without extracting paths, links, devices or duplicates."""
    files, total = {}, 0
    if not isinstance(max_unpacked, int) or not 0 < max_unpacked <= 512 * 1024 * 1024:
        raise ValueError('Unsupported maintenance archive bound')
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = [(item.filename, item.file_size, item.is_dir(),
                        (item.external_attr >> 16) & 0o170000, item)
                       for item in archive.infolist()]
            for name, size, directory, mode, item in entries:
                relative(name.rstrip('/'))
                if directory:
                    continue
                if mode not in (0, 0o100000) or name in files:
                    raise ValueError('Unsafe or duplicate maintenance archive member')
                total += size
                if total > max_unpacked:
                    raise ValueError('Maintenance archive exceeds its unpacked size limit')
                files[name] = archive.read(item)
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
            for item in archive:
                relative(item.name.rstrip('/'))
                if item.isdir():
                    continue
                if not item.isfile() or item.name in files:
                    raise ValueError('Unsafe or duplicate maintenance archive member')
                total += item.size
                if total > max_unpacked:
                    raise ValueError('Maintenance archive exceeds its unpacked size limit')
                files[item.name] = archive.extractfile(item).read()
    if not files:
        raise ValueError('Maintenance archive is empty')
    return files
