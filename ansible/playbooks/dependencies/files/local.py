"""Stage public tracked files and export separately reviewed application Actions pins."""
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

from . import actions
from .control import CANDIDATE, CONTROL, ROOT, helper_hash, load, save
from .gate import canonical
from .inventory import selected
from .security import MAX_ARTIFACT, archive_files, digest, owned_path
from .workspace import changes, files, supports_modes, tree

PUBLIC = ('ansible', 'platform', 'infra', 'apps', 'charts', 'gitops', 'verification', '.github',
          'compose.yaml', '.gitattributes', '.gitignore', '.env.example')


def stage(revision):
    CANDIDATE.mkdir(parents=True, exist_ok=True)
    CONTROL.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any(CANDIDATE.iterdir()):
        raise ValueError('Standalone Actions maintenance requires a new empty work directory')
    environment = {'PATH': os.environ['PATH'], 'HOME': '/tmp/home', 'GIT_CONFIG_NOSYSTEM': '1',
                   'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_OPTIONAL_LOCKS': '0'}
    clean = subprocess.run(['git', '--no-pager', '-c', 'core.fsmonitor=false', 'diff', '--quiet', 'HEAD', '--', *PUBLIC],
                           cwd=ROOT, env=environment, capture_output=True, timeout=60)
    if clean.returncode:
        raise ValueError('Standalone Actions maintenance requires clean committed public source')
    result = subprocess.run(['git', '--no-pager', '-c', 'core.fsmonitor=false', 'ls-files', '--cached', '--stage',
                             '-z', '--', *PUBLIC], cwd=ROOT,
                            env=environment, capture_output=True, timeout=60)
    if result.returncode:
        raise ValueError('Public source inventory is unavailable')
    indexed = {}
    for entry in result.stdout.decode().split('\0'):
        if not entry:
            continue
        metadata, relative = entry.split('\t', 1)
        mode, sha, stage = metadata.split()
        if mode not in {'100644', '100755'} or stage != '0' or not re.fullmatch(r'[a-f0-9]{40}', sha) or relative in indexed:
            raise ValueError('Actions source index has unsupported modes or conflicts')
        indexed[relative] = {'mode': mode, 'sha': sha}
    paths = sorted(indexed)
    if not paths or any(not any(path == prefix or path.startswith(prefix + '/') for prefix in PUBLIC) for path in paths):
        raise ValueError('Public source inventory escaped its scope')
    archived = subprocess.run(['git', '--no-pager', '-c', 'core.fsmonitor=false', 'archive', '--format=tar', 'HEAD', '--', *PUBLIC],
                              cwd=ROOT, env=environment, capture_output=True, timeout=120)
    if archived.returncode or len(archived.stdout) > MAX_ARTIFACT:
        raise ValueError('Committed public source archive is unavailable or exceeds its bound')
    committed = archive_files(archived.stdout)
    if set(committed) != set(paths):
        raise ValueError('Committed public source archive differs from its exact tracked index')
    actions.official(revision)
    base = {}
    for relative in paths:
        target = owned_path(CANDIDATE, relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        raw = committed[relative]
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
        if blob != indexed[relative]['sha']:
            raise ValueError('Actions public source changed after its clean index check')
        target.write_bytes(raw)
        target.chmod(0o755 if indexed[relative]['mode'] == '100755' else 0o644)
        base[relative] = indexed[relative]
    baseline = files(CANDIDATE)
    owner = selected(['actions'])['actions']
    operation = secrets.token_hex(16)
    plan = {'kind': 'actions', 'operation': operation, 'owners': ['actions'], 'targetRevision': revision,
            'checks': owner['checks']}
    save('operation.json', plan)
    save('baseline.json', baseline)
    save('check-plan.json', {'operation': operation, 'checks': owner['checks'], 'allowed': owner['writePaths'],
        'fileModes': supports_modes(CANDIDATE),
        'baseTree': base, 'baseFiles': {path: base64.b64encode((CANDIDATE / path).read_bytes()).decode()
                                       for path in owner['writePaths']}})
    actions.update(CANDIDATE, revision)
    return {'owner': 'actions', 'status': 'pending-verification', 'targetRevision': revision,
            'delivery': 'authorized-maintainer', 'botWorkflowPublication': False}


def export():
    plan = load('operation.json')
    if plan['kind'] != 'actions' or plan['owners'] != ['actions']:
        raise ValueError('Actions export cannot use a bot publication operation')
    owner = selected(['actions'])['actions']
    check_plan = load('check-plan.json')
    checks = json.loads(Path('/results/checks.json').read_bytes())
    if checks != {'operation': plan['operation'], 'candidateTree': tree(CANDIDATE),
                  'checks': {check: 'PASS' for check in owner['checks']},
                  'plan': digest(json.dumps(check_plan, sort_keys=True).encode())}:
        raise ValueError('Actions export requires the current existing workflow checks')
    toolchain = load('toolchain.json')
    if toolchain['operation'] != plan['operation'] or toolchain['candidateTree'] != tree(CANDIDATE):
        raise ValueError('Actions export toolchain record is stale')
    revision = actions.official(plan['targetRevision'])
    pins = [pin for path in actions.FILES for pin in re.findall(r'uses: actions/checkout@([a-f0-9]{40})',
                                                               (CANDIDATE / path).read_text())]
    if pins != [revision] * 3:
        raise ValueError('Actions export must bind all three checkout uses to the exact verified commit')
    patch = changes(CANDIDATE, load('baseline.json'), owner['writePaths'])
    output = ''
    for path, raw in patch.items():
        before = base64.b64decode(check_plan['baseFiles'][path], validate=True).decode()
        output += ''.join(difflib.unified_diff(before.splitlines(keepends=True), raw.decode().splitlines(keepends=True),
                                              fromfile='a/' + path, tofile='b/' + path))
    (CONTROL / 'actions.patch').write_text(output, newline='\n')
    save('actions-export.json', {'targetRevision': revision, 'candidateTree': tree(CANDIDATE),
         'patchSha256': digest(output.encode()), 'helpers': helper_hash(),
         'checks': checks['checks'], 'toolchain': toolchain['imageId'], 'delivery': 'authorized-maintainer'})
    return {'owner': 'actions', 'validated': True, 'targetRevision': revision,
            'changedFiles': len(patch), 'delivery': 'authorized-maintainer', 'botWorkflowPublication': False}


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['export']:
            result = export()
        elif sys.argv[1:] == ['stage']:
            raw = sys.stdin.read(16385)
            request = json.loads(raw)
            if len(raw) > 16384 or set(request) != {'version'}:
                raise ValueError('Actions staging requires one immutable revision')
            result = stage(request['version'])
        else:
            raise ValueError('Unsupported Actions maintenance operation')
        print(json.dumps(result))
    except Exception:
        raise SystemExit('Actions maintenance failed; no bot workflow publication is permitted') from None
