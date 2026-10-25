"""Maintain the three application checkout pins without a Git credential."""
import json
from pathlib import Path
import re

from .security import digest

FILES = ('.github/workflows/application-test.yaml', '.github/workflows/application-publish.yaml')


def official(revision):
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('Actions maintenance requires an immutable official commit')
    # A commit endpoint can expose fork-network objects. Only upstream's stable
    # release ref grants provenance; the caller still supplies an immutable SHA.
    import urllib.request

    def metadata(path):
        request = urllib.request.Request('https://api.github.com/repos/actions/checkout/' + path,
                                         headers={'Accept': 'application/vnd.github+json'})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('Checkout release metadata exceeds its size limit')
        return json.loads(raw)

    release = metadata('releases/latest')
    tag = release.get('tag_name', '')
    if (release.get('draft') is not False or release.get('prerelease') is not False or
            not re.fullmatch(r'v?[0-9]+[.][0-9]+[.][0-9]+', tag) or
            release.get('html_url') != 'https://github.com/actions/checkout/releases/tag/' + tag):
        raise ValueError('Checkout source requires the current stable upstream release')
    reference = metadata('git/ref/tags/' + tag)
    if reference.get('ref') != 'refs/tags/' + tag:
        raise ValueError('Checkout release tag identity differs')
    target, seen = reference.get('object', {}), set()
    for _ in range(5):
        sha = target.get('sha', '')
        if not re.fullmatch(r'[a-f0-9]{40}', sha) or sha in seen:
            raise ValueError('Checkout release tag is malformed or cyclic')
        seen.add(sha)
        if target.get('type') == 'commit':
            break
        if target.get('type') != 'tag':
            raise ValueError('Checkout release tag does not name a commit')
        target = metadata('git/tags/' + sha).get('object', {})
    else:
        raise ValueError('Checkout release tag exceeds its annotated-tag bound')
    if sha != revision:
        raise ValueError('Checkout commit is not the exact current stable upstream release')
    import yaml
    with urllib.request.urlopen('https://raw.githubusercontent.com/actions/checkout/' + revision + '/action.yml', timeout=60) as response:
        raw = response.read(65537)
    if len(raw) > 65536 or yaml.safe_load(raw)['runs']['using'] != 'node24':
        raise ValueError('Checkout revision must retain the supported Node 24 runtime')
    return revision


def update(root, revision):
    official(revision)
    result, count = {}, 0
    for relative in FILES:
        path = Path(root) / relative
        text = path.read_text()
        updated, changes = re.subn(r'(?m)(uses: actions/checkout@)[a-f0-9]{40}(?=\s*$)',
                                   r'\g<1>' + revision, text)
        result[relative], count = updated, count + changes
    if count != 3:
        raise ValueError('Application checkout inventory must contain exactly three immutable pins')
    for relative, text in result.items():
        (Path(root) / relative).write_text(text, newline='\n')
    return {'owner': 'actions', 'revision': revision, 'delivery': 'authorized-maintainer',
            'files': {path: digest(text.encode()) for path, text in result.items()}}
