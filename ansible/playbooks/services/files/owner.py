"""Validate service inputs against their exact public native chart owner."""
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
import re
import tempfile
import urllib.request

import yaml

from playbooks.argocd.files import source_snapshot as snapshot
from playbooks.argocd.files.github_setup import repository
from playbooks.argocd.files.service_activation import catalog_path
from playbooks.services.files.contract import ROOT

CHART = 'platform/delivery/services/'
MAX_FILE = snapshot.MAX_FILE
MAX_CHART = snapshot.MAX_CHART


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


NoRedirect = snapshot.NoRedirect
read_url = snapshot.read_url
def request(path, deadline):
    return snapshot.request(path, deadline, read=read_url)


def download(source, name, size, deadline):
    return snapshot.download(dict(source, path=CHART), name, size, deadline, read=read_url)


def chart_files(source, *, fetch=request, read_file=download):
    return snapshot.chart_files(dict(source, path=CHART), fetch=fetch, read_file=read_file)


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
