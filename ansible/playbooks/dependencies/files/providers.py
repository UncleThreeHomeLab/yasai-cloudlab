"""Prepare and accept reviewed custom provider packages through native builds."""
import json
from pathlib import Path
import re

from .native import lock_and_check
from .inputs import baseline
from .security import digest, download
from .tools import write_json

SOURCES = {'cloudflare': 'https://codeload.github.com/cloudflare/terraform-provider-cloudflare/tar.gz/',
           'harbor': 'https://codeload.github.com/goharbor/terraform-provider-harbor/tar.gz/'}
PATCHES = {'cloudflare': 'cloudflare-legacy.patch', 'harbor': 'harbor-quota.patch'}
ROOTS = {'cloudflare': ('infra/cloudflare',),
         'harbor': ('infra/harbor', 'ansible/playbooks/harbor/tests/provider-fixture')}


def prepare(root, name, request, *, fetch=download):
    if (name not in SOURCES or set(request) not in ({'version', 'commit'}, {'version', 'commit', 'goVersion'}) or
            not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+-cloudlab\.[0-9]+', request['version']) or
            not re.fullmatch(r'[a-f0-9]{40}', request['commit'])):
        raise ValueError('Custom providers require an approved owner, derivative version and immutable upstream commit')
    directory = Path(root) / 'ansible/runner'
    path = directory / (name + '-provider.lock.json')
    lock = json.loads(path.read_text())
    original = json.loads(baseline(root, 'ansible/runner/' + name + '-provider.lock.json'))
    parsed = lambda value: tuple(map(int, re.fullmatch(r'([0-9]+)[.]([0-9]+)[.]([0-9]+)-cloudlab[.]([0-9]+)', value).groups()))
    if parsed(request['version'])[:2] != parsed(original['version'])[:2] or parsed(request['version']) < parsed(original['version']):
        raise ValueError('Custom provider version leaves its reviewed minor or reuses an older build')
    if 'goVersion' in request:
        if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', request['goVersion']):
            raise ValueError('Provider compiler requires an explicit stable Go version')
        if request['goVersion'].split('.')[:2] != original['go']['version'].split('.')[:2]:
            raise ValueError('Provider compiler minor changes require separate compatibility review')
        go_url = 'https://go.dev/dl/go' + request['goVersion'] + '.linux-amd64.tar.gz'
        go_raw = fetch(go_url, prefix='https://go.dev/dl/')
        from .security import archive_files
        if 'go/bin/go' not in archive_files(go_raw, max_unpacked=512 * 1024 * 1024):
            raise ValueError('Compiler archive lacks its expected native executable')
        lock['go'] = {'version': request['goVersion'], 'url': go_url, 'sha256': digest(go_raw)}
    if digest((directory / PATCHES[name]).read_bytes()) != lock['patch_sha256']:
        raise ValueError('Custom provider patch differs from its reviewed checksum')
    url = SOURCES[name] + request['commit']
    raw = fetch(url, prefix=SOURCES[name])
    from .security import archive_files
    archive_files(raw)
    if request['version'] == original['version'] and (
            request['commit'] != original['source'].get('commit') or digest(raw) != original['source']['sha256'] or
            lock['go'] != original['go'] or lock['patch_sha256'] != original['patch_sha256']):
        raise ValueError('Changed provider content requires a new explicit cloudlab version')
    lock['version'] = request['version']
    lock['source'].update(url=url, sha256=digest(raw), commit=request['commit'])
    write_json(path, lock)
    return {'owner': name + '-provider', 'status': 'pending-build', 'pendingBuild': 'review-' + name + '-provider',
            'next': 'docker compose -f ansible/playbooks/dependencies/compose.yaml run --build --rm review-' + name + '-provider'}


def accept(root, name, *, review=Path('/review'), mirror=Path('/opt/providers')):
    if name not in ROOTS:
        raise ValueError('Unsupported custom provider owner')
    lock_path = Path(root) / 'ansible/runner' / (name + '-provider.lock.json')
    lock = json.loads(lock_path.read_text())
    built = json.loads((review / 'source.lock.json').read_text())
    if lock != built:
        raise ValueError('Provider source changed after its reviewed build')
    patch = Path(root) / 'ansible/runner' / PATCHES[name]
    if digest(patch.read_bytes()) != lock['patch_sha256']:
        raise ValueError('Provider patch changed after its reviewed build')
    package = mirror / 'registry.opentofu.org/cloudlab' / name / (
        'terraform-provider-' + name + '_' + lock['version'] + '_linux_amd64.zip')
    original = json.loads(baseline(root, 'ansible/runner/' + name + '-provider.lock.json'))
    if lock['version'] == original['version'] and digest(package.read_bytes()) != original['package_sha256']:
        raise ValueError('A different provider package cannot replace an existing provider version')
    lock['package_sha256'] = digest(package.read_bytes())
    write_json(lock_path, lock)
    for relative in ROOTS[name]:
        directory = Path(root) / relative
        path = directory / 'versions.tf'
        text = path.read_text()
        pattern = r'(source\s*=\s*"cloudlab/' + name + r'"\s+version\s*=\s*"=\s*)[^"\s]+(")'
        text, count = re.subn(pattern, r'\g<1>' + lock['version'] + r'\2', text)
        if count != 1:
            raise ValueError('Custom provider constraint is missing or ambiguous')
        path.write_text(text, newline='\n')
        lock_and_check(directory, mirror=mirror)
    return {'owner': name + '-provider', 'packageAndLocksUpdated': True, 'nativeChecks': 'PASS',
            'pendingBuild': 'candidate-runner',
            'next': 'docker compose -f ansible/playbooks/dependencies/compose.yaml build candidate-runner'}


if __name__ == '__main__':
    import sys
    try:
        print(json.dumps(accept('/candidate', sys.argv[1])))
    except Exception:
        raise SystemExit('Reviewed provider acceptance failed; candidate remains draft') from None
