"""Bounded immutable Git chart snapshots shared by native source owners."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import time
import urllib.error
import urllib.request
from urllib.parse import quote

try:
    from .github_setup import repository
except ImportError:
    from github_setup import repository

MAX_FILE = 2 * 1024 * 1024
MAX_CHART = 16 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def read_url(url, deadline, limit):
    # No ambient proxy, authentication handler, Git hooks or provider credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('Git owner source exceeded its deadline')
    query = urllib.request.Request(url, headers={'User-Agent': 'cloudlab-service-owner'})
    try:
        with opener.open(query, timeout=min(15, remaining)) as response:
            raw = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError('Git owner source exceeded its deadline')
                chunk = response.read1(min(65536, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > limit:
                    raise ValueError('Git owner response exceeds its bound')
        return bytes(raw)
    except (urllib.error.URLError, TimeoutError):
        raise ValueError('Declared public Git owner is unavailable; checkout fallback refused') from None


def request(path, deadline, *, read=read_url):
    try:
        result = json.loads(read('https://api.github.com/' + path, deadline, 8 * 1024 * 1024))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError('Git owner response is invalid') from None
    if not isinstance(result, dict):
        raise ValueError('Git owner response must be an object')
    return result


def download(source, name, size, deadline, *, read=read_url):
    repo = repository(source['repository'])
    url = 'https://raw.githubusercontent.com/' + repo + '/' + source['revision'] + '/' + quote(source["path"].rstrip("/") + "/" + name, safe='/')
    return read(url, deadline, size)


def chart_files(source, *, fetch=request, read_file=download, deadline=None, require_schema=True):
    if type(require_schema) is not bool:
        raise ValueError('Git owner schema requirement must be a boolean')
    chart_path = source["path"].rstrip("/") + "/"
    repo = repository(source['repository'])
    revision = source['revision']
    if not re.fullmatch('[a-f0-9]{40}', revision or ''):
        raise ValueError('Git owner requires an immutable commit')
    deadline = deadline if deadline is not None else time.monotonic() + 90
    prefix = 'repos/' + repo + '/git/'
    def read(path):
        if time.monotonic() >= deadline:
            raise ValueError('Git owner source exceeded its deadline')
        result = fetch(path, deadline)
        if not isinstance(result, dict):
            raise ValueError('Git owner response must be an object')
        return result
    commit = read(prefix + 'commits/' + revision)
    tree = commit.get('tree', {}).get('sha')
    if commit.get('sha') != revision or not re.fullmatch('[a-f0-9]{40}', tree or ''):
        raise ValueError('Git owner commit differs from its declared revision')
    document = read(prefix + 'trees/' + tree + '?recursive=1')
    entries = document.get('tree')
    if document.get('sha') != tree or document.get('truncated') or not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError('Git owner tree is incomplete or exceeds its bound')
    selected = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Git owner tree has an invalid entry')
        path = entry.get('path', '')
        if not isinstance(path, str) or not path.startswith(chart_path):
            continue
        relative = path[len(chart_path):]
        if (not relative or '\\' in relative or ':' in relative or
                any(part in ('', '.', '..') for part in relative.split('/')) or
                any(ord(char) < 32 or ord(char) == 127 for char in relative)):
            raise ValueError('Git owner contains an unsafe chart path')
        if entry.get('type') == 'tree':
            continue
        if (entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755') or
                not re.fullmatch('[a-f0-9]{40}', entry.get('sha') or '') or
                type(entry.get('size')) is not int or not 0 <= entry['size'] <= MAX_FILE or relative in selected):
            raise ValueError('Git owner contains an unsupported chart file')
        selected[relative] = entry
    required = {'Chart.yaml', 'values.schema.json' if require_schema else 'values.yaml'}
    if (not required <= set(selected) or len(selected) > 128 or
            sum(entry['size'] for entry in selected.values()) > MAX_CHART):
        raise ValueError('Git owner chart is missing or exceeds its bound')
    if any('/'.join(PurePosixPath(name).parts[:index]) in selected
           for name in selected for index in range(1, len(PurePosixPath(name).parts))):
        raise ValueError('Git owner chart contains conflicting file paths')
    output = {}
    for name, entry in selected.items():
        # Only commit/tree metadata uses the rate-limited REST API. Immutable raw
        # bytes are checked against the selected Git tree's exact blob hashes.
        raw = read_file(source, name, entry['size'], deadline)
        if not isinstance(raw, bytes):
            raise ValueError('Git owner file must contain bytes')
        digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if len(raw) != entry['size'] or digest != entry['sha']:
            raise ValueError('Git owner bytes differ from their exact Git blob')
        output[name] = raw
    return output
