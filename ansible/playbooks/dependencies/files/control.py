"""Trusted credential owner; never execute candidate code in this process."""
import json
import base64
import os
from pathlib import Path
import secrets
import signal
import sys
import time
from contextlib import contextmanager
import fcntl

from dotenv import dotenv_values

from playbooks.argocd.files import repository_tokens
from playbooks.argocd.files.github_setup import GitHub
from playbooks.argocd.files.render import committed_payload

from .gate import Gate, branch_prefix, canonical
from .inventory import ROOT, paths, selected
from .security import digest, owned_path
from .workspace import changes, export, files, owned_diff, remote_tree, snapshot, supports_modes, tree
from .validate import file_change

CONTROL = Path('/control')
CANDIDATE = Path('/candidate')
HANDOFF = Path('/handoff')
WRITER = Path('/writer-lock')


@contextmanager
def writer_lock():
    WRITER.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (WRITER / 'writer.lock').open('a+b') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another maintenance control operation is active; writes refused') from None
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def load(name):
    return json.loads((CONTROL / name).read_bytes())


def save(name, value):
    target = CONTROL / name
    target.write_bytes(canonical(value))
    public = name in {'check-plan.json', 'toolchain.json'} or name.startswith('images/')
    target.chmod(0o644 if public else 0o600)


def helper_hash():
    inputs = [path for directory in ('ansible', 'platform') for path in (ROOT / directory).rglob('*')
              if path.is_file() and (path.suffix in {'.py', '.cs', '.patch', '.cjs'} or
                                     path.name in {'Dockerfile', '.dockerignore'})]
    inputs += list((ROOT / 'platform/delivery/dependencies').glob('*'))
    inputs += [ROOT / path for path in ('platform/data/cnpg/artifact.lock.json',
                                       'platform/connectivity/istio/base/artifact.lock.json',
                                       'platform/observability/policy.json',
                                       'ansible/playbooks/dependencies/compose.yaml')]
    return digest(canonical({str(path.relative_to(ROOT)): digest(path.read_bytes())
                             for path in sorted(set(inputs)) if path.is_file()}))


def allowed(owners, extra=()):
    import re
    result = set().union(*(set(owner['writePaths']) for owner in owners.values()))
    for owner in owners.values():
        if owner['updater'] != 'chart':
            continue
        for archive in [path for path in owner['writePaths'] if path.endswith('.tgz') and '/charts/' in path]:
            pattern = re.escape(archive)
            version = re.search(r'v?[0-9]+\.[0-9]+\.[0-9]+(?=[.]tgz$)', archive)
            if version:
                pattern = re.escape(archive[:version.start()]) + r'v?[0-9]+\.[0-9]+\.[0-9]+' + re.escape(archive[version.end():])
                result.update(path for path in extra if re.fullmatch(pattern, path))
    return result


def scope(lease, base):
    return {'repository': lease['repository'], 'repositoryId': lease['repositoryId'],
            'requester': lease['requester'], 'base': base, 'branchPrefix': branch_prefix(base)}


def bot_owners(names):
    owners = selected(names)
    if any(owner['updater'] == 'actions' or any(path.startswith('.github/workflows/') for path in owner['writePaths'])
           for owner in owners.values()):
        raise ValueError('Application Actions pins require the separate credential-free maintainer lane')
    return owners


def trusted_validation(gate, number):
    record = load('validated.json')
    import hashlib
    import hmac
    document, signature = record['body'], record['mac']
    if not hmac.compare_digest(signature, hmac.new(gate.key, canonical(document), hashlib.sha256).hexdigest()):
        raise ValueError('Maintenance validation record is not authentic')
    plan = load('operation.json')
    owners = bot_owners(plan['owners'])
    if (document['operation'] != plan['operation'] or document['number'] != number or
            document['candidateTree'] != tree(CANDIDATE) or document['helpers'] != helper_hash() or
            document['scope'] != gate.scope):
        raise ValueError('Maintenance source changed after verification')
    return document, owners


def propose(gate, lease, names):
    owners = bot_owners(names)
    include = sorted(set(path for owner in owners.values() for path in paths(owner)))
    dependencies = sorted(set(name for owner in owners.values() for name in owner['nativeDependencies']))
    if not dependencies:
        raise ValueError('Selected owners have no native Renovate proposal targets')
    gate.prepare_write()
    HANDOFF.mkdir(mode=0o700, parents=True, exist_ok=True)
    operation = secrets.token_hex(16)
    request = HANDOFF / 'request.json'
    result = HANDOFF / 'result.json'
    if request.exists() or result.exists():
        raise ValueError('Proposal handoff is not empty; stale operation cleanup required')
    temporary = HANDOFF / 'request.tmp'
    with temporary.open('x', encoding='utf-8') as stream:
        json.dump({'repository': lease['repository'], 'base': gate.scope['base'], 'token': lease['token'],
                   'operation': operation, 'expiresAt': int(time.time()) + 60,
                   'ownerPaths': include, 'dependencies': dependencies}, stream)
    temporary.chmod(0o600)
    temporary.replace(request)
    try:
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            if result.exists():
                answer = json.loads(result.read_text())
                if (set(answer) != {'operation', 'passed', 'extracted'} or answer['operation'] != operation or
                        answer['passed'] is not True or type(answer['extracted']) is not int or answer['extracted'] < 1):
                    raise ValueError('Native Renovate proposal failed')
                rows = gate.prepare_write()
                matching = []
                for row in rows:
                    base = remote_tree(gate.api, gate.scope['repository'], row['base']['sha'])
                    head = remote_tree(gate.api, gate.scope['repository'], row['head']['sha'])
                    try:
                        owned_diff(base, head, allowed(owners, set(base) | set(head)))
                    except ValueError:
                        continue
                    matching.append(row['number'])
                if gate.scope['base'].startswith('cloudlab-maintenance-fixture/') and not matching:
                    raise ValueError('Fixture proposal did not produce an owned draft with the selected pin changes')
                return {'operation': 'propose', 'draftsOnly': True, 'passed': True,
                        'state': 'draft-proposals' if matching else 'no-updates', 'proposalNumbers': matching,
                        'selectedDependencyCount': answer['extracted']}
            time.sleep(1)
        raise RuntimeError('Native Renovate proposal exceeded its time limit')
    finally:
        request.unlink(missing_ok=True)
        result.unlink(missing_ok=True)
        # Native updates can leave incomplete drafts; every failure remains gated.
        gate.prepare_write()


def export_pr(gate, number, names):
    owners = bot_owners(names)
    row = gate.redraft(number)
    base = remote_tree(gate.api, gate.scope['repository'], row['base']['sha'])
    head = remote_tree(gate.api, gate.scope['repository'], row['head']['sha'])
    permitted = allowed(owners, set(base) | set(head))
    changed = owned_diff(base, head, permitted)
    base_source = snapshot(gate.scope['repository'], row['base']['sha'], expected=base)
    head_source = snapshot(gate.scope['repository'], row['head']['sha'], expected=head)
    for path in changed:
        file_change(path, base_source.get(path), head_source.get(path))
    baseline = export(CANDIDATE, gate.scope['repository'], row['head']['sha'], expected=head)
    plan = {'operation': secrets.token_hex(16), 'number': number, 'owners': names,
            'scope': gate.scope, 'head': row['head']['sha'], 'base': row['base']['sha'],
            'checks': sorted(set(check for owner in owners.values() for check in owner['checks']))}
    save('operation.json', plan)
    save('baseline.json', baseline)
    save('head-tree.json', head)
    save('check-plan.json', {'operation': plan['operation'], 'checks': plan['checks'],
         'fileModes': supports_modes(CANDIDATE),
         'allowed': sorted(permitted), 'archiveOwners': {name: owner for name, owner in owners.items() if owner['updater'] == 'chart'}, 'baseTree': base,
         'baseFiles': {path: base64.b64encode(raw).decode() for path, raw in base_source.items()
                       if path in permitted}})
    (CONTROL / 'validated.json').unlink(missing_ok=True)
    return {'operation': 'export', 'number': number, 'head': plan['head'], 'checks': len(plan['checks'])}


def run(action, request):
    if action not in {'propose', 'export', 'publish', 'ready'} or set(request) - {'base', 'number', 'owners'} or 'base' not in request:
        raise ValueError('Invalid trusted maintenance request')
    if action in {'propose', 'export'}:
        bot_owners(request.get('owners', []))
    source = committed_payload()
    if source['branch'] != 'main':
        raise ValueError('Credentialed maintenance requires the reviewed public main source')
    with writer_lock():
        return credentialed(action, request, source)


def credentialed(action, request, source):
    from .toolchain import embedded
    embedded(ROOT)
    if any((HANDOFF / name).exists() for name in ('request.json', 'request.tmp', 'result.json', 'result.tmp')):
        raise ValueError('A proposal handoff is active or stale; stop and recover it before another operation')
    values = dotenv_values(ROOT / '.env', interpolate=False)
    token = values.get('OP_SERVICE_ACCOUNT_TOKEN')
    if not token:
        raise ValueError('Maintenance requires the existing read-only 1Password service account')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = token
    lease = None
    try:
        lease = repository_tokens.issue(values, 'public-platform', {'contents': 'write', 'pull_requests': 'write'},
                                        include_requester=True)
        if source['repository'] != 'https://github.com/' + lease['repository'] + '.git':
            raise ValueError('Maintenance credentials differ from the exact public driver repository')
        gate = Gate(GitHub(lease['token']), scope(lease, request['base']), CONTROL)
        if action == 'propose':
            return propose(gate, lease, request.get('owners', []))
        number = request.get('number')
        if action == 'export':
            return export_pr(gate, number, request.get('owners', []))
        if action == 'publish':
            validation, owners = trusted_validation(gate, number)
            baseline = load('baseline.json')
            permitted = allowed(owners, set(baseline) | set(files(CANDIDATE)))
            patch = changes(CANDIDATE, baseline, permitted)
            captured = dict(baseline)
            for path, raw in patch.items():
                if raw is None:
                    captured.pop(path)
                else:
                    captured[path] = digest(raw)
            if digest(json.dumps(captured, sort_keys=True).encode()) != validation['candidateTree']:
                raise ValueError('Captured maintenance patch differs from its verified candidate tree')
            result = gate.publish(number, validation['head'], validation['base'], patch, permitted,
                                  modes={path: row['mode'] for path, row in load('head-tree.json').items()})
            (CONTROL / 'validated.json').unlink(missing_ok=True)
            return result
        if action == 'ready':
            validation, _ = trusted_validation(gate, number)
            return gate.ready(number, {key: validation[key] for key in
                ('candidateTree', 'pinset', 'helpers', 'toolchain', 'checks')})
        raise ValueError('Unsupported trusted maintenance operation')
    finally:
        os.environ.pop('OP_SERVICE_ACCOUNT_TOKEN', None)
        if lease is not None:
            repository_tokens.revoke(lease)


def interrupted(signum, frame):
    raise RuntimeError('Maintenance interrupted')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, interrupted)
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ''
        raw = sys.stdin.read(16385)
        if len(raw) > 16384:
            raise ValueError('Maintenance request exceeds its size limit')
        print(json.dumps(run(action, json.loads(raw))))
    except Exception:
        raise SystemExit('Maintenance operation failed; credentials and private diagnostics withheld') from None
