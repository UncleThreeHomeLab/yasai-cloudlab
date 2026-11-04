"""Validate service inputs against their exact public native chart owner."""
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import quote

import yaml

from playbooks.argocd.files.github_setup import repository
from playbooks.argocd.files.service_activation import catalog_path
from playbooks.services.files.contract import ROOT

CHART = 'platform/delivery/services/'
MAX_FILE = 2 * 1024 * 1024
MAX_CHART = 16 * 1024 * 1024


def configuration(public=None):
    public = public if public is not None else yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if not isinstance(public, dict) or not isinstance(public.get('services'), dict):
        raise ValueError('Service owner requires its reviewed public settings')
    source = public.get('services', {})
    repository(public.get('repository'))
    if not re.fullmatch('[a-f0-9]{40}', source.get('revision') or ''):
        raise ValueError('Service owner requires its declared immutable public revision')
    return {'repository': public['repository'], 'revision': source['revision'],
            'catalogPath': catalog_path(source.get('catalogPath', catalog_path()))}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def read_url(url, deadline, limit):
    # No ambient proxy, authentication handler, Git hooks or provider credentials.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError('Service owner source exceeded its deadline')
    query = urllib.request.Request(url, headers={'User-Agent': 'cloudlab-service-owner'})
    try:
        with opener.open(query, timeout=min(15, remaining)) as response:
            raw = bytearray()
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError('Service owner source exceeded its deadline')
                chunk = response.read1(min(65536, limit + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                if len(raw) > limit:
                    raise ValueError('Service owner response exceeds its bound')
        return bytes(raw)
    except (urllib.error.URLError, TimeoutError):
        raise ValueError('Declared public service owner is unavailable; checkout fallback refused') from None


def request(path, deadline):
    try:
        result = json.loads(read_url('https://api.github.com/' + path, deadline, 8 * 1024 * 1024))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError('Service owner response is invalid') from None
    if not isinstance(result, dict):
        raise ValueError('Service owner response must be an object')
    return result


def download(source, name, size, deadline):
    repo = repository(source['repository'])
    url = 'https://raw.githubusercontent.com/' + repo + '/' + source['revision'] + '/' + quote(CHART + name, safe='/')
    return read_url(url, deadline, size)


def chart_files(source, *, fetch=request, read_file=download):
    repo = repository(source['repository'])
    revision = source['revision']
    if not re.fullmatch('[a-f0-9]{40}', revision or ''):
        raise ValueError('Service owner requires an immutable commit')
    deadline = time.monotonic() + 90
    prefix = 'repos/' + repo + '/git/'
    def read(path):
        if time.monotonic() >= deadline:
            raise ValueError('Service owner source exceeded its deadline')
        result = fetch(path, deadline)
        if not isinstance(result, dict):
            raise ValueError('Service owner response must be an object')
        return result
    commit = read(prefix + 'commits/' + revision)
    tree = commit.get('tree', {}).get('sha')
    if commit.get('sha') != revision or not re.fullmatch('[a-f0-9]{40}', tree or ''):
        raise ValueError('Service owner commit differs from its declared revision')
    document = read(prefix + 'trees/' + tree + '?recursive=1')
    entries = document.get('tree')
    if document.get('sha') != tree or document.get('truncated') or not isinstance(entries, list) or len(entries) > 10000:
        raise ValueError('Service owner tree is incomplete or exceeds its bound')
    selected = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError('Service owner tree has an invalid entry')
        path = entry.get('path', '')
        if not isinstance(path, str) or not path.startswith(CHART):
            continue
        relative = path[len(CHART):]
        if (not relative or '\\' in relative or ':' in relative or
                any(part in ('', '.', '..') for part in relative.split('/')) or
                any(ord(char) < 32 or ord(char) == 127 for char in relative)):
            raise ValueError('Service owner contains an unsafe chart path')
        if entry.get('type') == 'tree':
            continue
        if (entry.get('type') != 'blob' or entry.get('mode') not in ('100644', '100755') or
                not re.fullmatch('[a-f0-9]{40}', entry.get('sha') or '') or
                type(entry.get('size')) is not int or not 0 <= entry['size'] <= MAX_FILE or relative in selected):
            raise ValueError('Service owner contains an unsupported chart file')
        selected[relative] = entry
    if (not {'Chart.yaml', 'values.schema.json'} <= set(selected) or len(selected) > 128 or
            sum(entry['size'] for entry in selected.values()) > MAX_CHART):
        raise ValueError('Service owner chart is missing or exceeds its bound')
    if any('/'.join(PurePosixPath(name).parts[:index]) in selected
           for name in selected for index in range(1, len(PurePosixPath(name).parts))):
        raise ValueError('Service owner chart contains conflicting file paths')
    output = {}
    for name, entry in selected.items():
        # Only commit/tree metadata uses the rate-limited REST API. Immutable raw
        # bytes are checked against the selected Git tree's exact blob hashes.
        raw = read_file(source, name, entry['size'], deadline)
        if not isinstance(raw, bytes):
            raise ValueError('Service owner file must contain bytes')
        digest = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if len(raw) != entry['size'] or digest != entry['sha']:
            raise ValueError('Service owner bytes differ from their exact Git blob')
        output[name] = raw
    return output


@contextmanager
def chart(public=None, *, fetch=request, read_file=download):
    source = configuration(public)
    contents = chart_files(source, fetch=fetch, read_file=read_file)
    with tempfile.TemporaryDirectory(prefix='cloudlab-service-owner-') as directory:
        root = Path(directory)
        for name, raw in contents.items():
            target = root.joinpath(*PurePosixPath(name).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o600)
        yield root
