"""Explicit disposable public dependency fixtures; candidate contents remain data."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile

from playbooks.argocd.files.github_setup import GitHub, GitHubHTTPError
from playbooks.dependencies.files import control, tools, workspace
from playbooks.dependencies.files.gate import Gate, canonical
from playbooks.dependencies.files.inventory import fingerprint
from playbooks.dependencies.files.security import digest, download

LIMIT = 1024 * 1024
PATHS = frozenset(('ansible/runner/tools.lock.json',
    'ansible/playbooks/data/tests/provider-fixture/versions.tf',
    'ansible/playbooks/data/tests/s3-provider-fixture/versions.tf',
    'ansible/playbooks/harbor/tests/provider-fixture/versions.tf',
    'ansible/playbooks/keycloak/tests/provider-fixture/versions.tf',
    'ansible/playbooks/observability/tests/provider-fixture/versions.tf',
    'ansible/playbooks/tailscale/provider-fixture/versions.tf',
    'infra/cloudflare/versions.tf', 'infra/github/versions.tf', 'infra/harbor/versions.tf'))
ARTIFACTS = Path('/fixture-artifact')
FIELDS = {'format', 'nonce', 'driver', 'helpers', 'repository', 'source', 'inputs', 'branch',
          'base', 'native', 'expectation', 'bound', 'intent', 'rejected', 'closed', 'deleted'}


def refuse():
    raise ValueError('Dependency fixture refused; diagnostics withheld')


def unique(pairs):
    value = dict(pairs)
    if len(value) != len(pairs): refuse()
    return value


def document(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMIT: refuse()
    return json.loads(raw, object_pairs_hook=unique)


def read_public(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): refuse()
        return document(stream.read(LIMIT + 1))


def blob(raw):
    return hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def private_directory(path):
    path = Path(path)
    path.mkdir(mode=0o700, exist_ok=True)
    row = path.lstat()
    if not stat.S_ISDIR(row.st_mode) or row.st_uid != os.getuid() or stat.S_IMODE(row.st_mode) != 0o700:
        refuse()


def journal(nonce, value=None, expected=None):
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce): refuse()
    parent = control.CONTROL / 'fixtures'
    private_directory(control.CONTROL)
    private_directory(parent)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = nonce + '.json'
    try:
        try: fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError: prior = None
        else:
            with os.fdopen(fd, 'rb') as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                        stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1): refuse()
                prior = stream.read(LIMIT + 1)
            document(prior)
        if value is None:
            if prior is None: return None, None
            return document(prior), digest(prior)
        if (digest(prior) if prior is not None else None) != expected: refuse()
        raw = canonical(value)
        document(raw)
        temporary = '.' + nonce + '-' + secrets.token_hex(8)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try: os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError: pass
        return digest(raw)
    finally: os.close(directory)


def inventory():
    owners = control.bot_owners(['tool:tofu'])
    if set(owners) != {'tool:tofu'} or set(owners['tool:tofu']['writePaths']) != PATHS: refuse()
    return owners


def encode_inputs(source, tree):
    return {path: {'bytes': base64.b64encode(source[path]).decode(), **tree[path]} for path in sorted(PATHS)}


def decode_inputs(value):
    if not isinstance(value, dict) or set(value) != PATHS: refuse()
    result = {}
    for path, row in value.items():
        if not isinstance(row, dict) or set(row) != {'bytes', 'sha', 'mode'} or row['mode'] != '100644': refuse()
        raw = base64.b64decode(row['bytes'], validate=True)
        if len(raw) > LIMIT // 4 or blob(raw) != row['sha']: refuse()
        result[path] = raw
    return result


def validate(state):
    if (not isinstance(state, dict) or set(state) != FIELDS or state['format'] != 1 or
            type(state['format']) is not int or not re.fullmatch('[a-f0-9]{32}', state['nonce']) or
            state['branch'] != 'cloudlab-maintenance-fixture/' + state['nonce'] or
            set(state['repository']) != {'name', 'id', 'node'} or type(state['repository']['id']) is not int or
            not re.fullmatch('[a-f0-9]{40}', state['driver']) or
            not re.fullmatch('[a-f0-9]{64}', state['helpers']) or
            not isinstance(state['source'], dict) or not 10 <= len(state['source']) <= 10000 or
            not isinstance(state['deleted'], dict) or set(state['deleted']) - {'bot', 'base'} or
            any(value is not True for value in state['deleted'].values()) or
            type(state['rejected']) is not bool or type(state['closed']) is not bool or
            state['repository']['id'] < 1 or not isinstance(state['repository']['node'], str) or
            not 1 <= len(state['repository']['node']) <= 256 or
            not re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', state['repository']['name'])): refuse()
    if state['base'] is not None:
        base = state['base']
        if (not isinstance(base, dict) or set(base) != {'blobs', 'tree', 'head', 'created'} or
                not isinstance(base['blobs'], dict) or set(base['blobs']) - PATHS or
                type(base['created']) is not bool or any(not re.fullmatch('[a-f0-9]{40}', value)
                    for value in base['blobs'].values()) or any(value is not None and not re.fullmatch('[a-f0-9]{40}', value)
                    for value in (base['tree'], base['head'])) or base['created'] and base['head'] is None): refuse()
    if state['native'] is not None:
        native = state['native']
        if (not isinstance(native, dict) or set(native) != {'number', 'node', 'branch', 'head', 'user'} or
                type(native['number']) is not int or native['number'] < 1 or not isinstance(native['node'], str) or
                not 1 <= len(native['node']) <= 256 or not re.fullmatch('[a-f0-9]{40}', native['head']) or
                not isinstance(native['user'], dict) or set(native['user']) != {'login', 'type'} or
                native['user']['type'] != 'Bot' or not re.fullmatch(r'[A-Za-z0-9-]+\[bot\]', native['user']['login']) or
                not re.fullmatch('cloudlab-maintenance/[a-z0-9][a-z0-9-]{0,79}', native['branch'])): refuse()
    if state['bound'] is not None and (state['native'] is None or not re.fullmatch('[a-f0-9]{40}', state['bound'])): refuse()
    if state['intent'] is not None:
        if (not isinstance(state['intent'], dict) or set(state['intent']) != {'kind', 'method', 'route', 'body'} or
                not isinstance(state['intent']['kind'], str) or state['intent']['method'] not in ('POST', 'PATCH') or
                not isinstance(state['intent']['route'], str) or not isinstance(state['intent']['body'], dict)): refuse()
    if state['expectation'] is not None:
        expected = state['expectation']
        if (not isinstance(expected, dict) or set(expected) != {'head', 'tree', 'inputs', 'operation', 'source'} or
                not re.fullmatch('[a-f0-9]{40}', expected['head']) or
                any(not re.fullmatch('[a-f0-9]{64}', expected[key]) for key in ('tree', 'source')) or
                not re.fullmatch('[a-f0-9]{32}', expected['operation']) or
                not isinstance(expected['inputs'], dict) or set(expected['inputs']) != {'pinset', 'helpers', 'checks', 'toolchain'}): refuse()
    for path, row in state['source'].items():
        workspace.relative(path)
        if (not isinstance(row, dict) or set(row) != {'sha', 'mode'} or
                row['mode'] not in ('100644', '100755') or not re.fullmatch('[a-f0-9]{40}', row['sha'])): refuse()
    decode_inputs(state['inputs'])
    if any(state['source'].get(path) != {key: row[key] for key in ('sha', 'mode')}
           for path, row in state['inputs'].items()): refuse()
    if state['rejected']: refuse()


def descriptor(state):
    return {'format': 1, 'nonce': state['nonce'], 'revision': state['driver'], 'inputs': state['inputs'],
            'from': '1.13.1', 'to': '1.13.0'}


def artifact(value, output):
    if (not isinstance(value, dict) or set(value) != {'format', 'nonce', 'revision', 'inputs', 'from', 'to'} or
            type(value['format']) is not int or value['format'] != 1 or
            not re.fullmatch('[a-f0-9]{32}', value['nonce']) or not re.fullmatch('[a-f0-9]{40}', value['revision']) or
            value['from'] != '1.13.1' or value['to'] != '1.13.0'): refuse()
    inputs = decode_inputs(value['inputs'])
    with tempfile.TemporaryDirectory(prefix='dependency-fixture-artifact-') as directory:
        root = Path(directory)
        for path, raw in inputs.items():
            target = root/path; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        tools.update(root, 'tofu', '1.13.0', fetch=download)
        updated = {path: (root/path).read_bytes() for path in PATHS}
    manifest = dict(value, files={path: {'before': value['inputs'][path]['sha'], 'mode': '100644',
        'sha': blob(raw), 'bytes': base64.b64encode(raw).decode()} for path, raw in sorted(updated.items())})
    document(canonical(manifest))
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = output/(value['nonce']+'.json')
    raw = canonical(manifest)
    if target.exists():
        if read_public(target) != manifest: refuse()
    else:
        temporary = output/('.'+secrets.token_hex(16))
        with temporary.open('xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        temporary.chmod(0o644); temporary.replace(target)
        fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    return {'artifact': True, 'companions': 10}


def capture_artifact(state):
    path = ARTIFACTS/(state['nonce']+'.json')
    value = read_public(path)
    if set(value) != set(descriptor(state)) | {'files'} or any(value[key] != item for key, item in descriptor(state).items()): refuse()
    if not isinstance(value['files'], dict) or set(value['files']) != PATHS: refuse()
    before, after = decode_inputs(state['inputs']), {}
    for path, row in value['files'].items():
        if (not isinstance(row, dict) or set(row) != {'before', 'mode', 'sha', 'bytes'} or
                row['before'] != state['source'][path]['sha'] or row['mode'] != '100644'): refuse()
        raw = base64.b64decode(row['bytes'], validate=True)
        if len(raw) > LIMIT // 4 or blob(raw) != row['sha']: refuse()
        after[path] = raw
        if path.endswith('/versions.tf'):
            old, new = b'required_version = "= 1.13.1"', b'required_version = "= 1.13.0"'
            if before[path].count(old) != 1 or raw != before[path].replace(old, new): refuse()
    old, new = json.loads(before['ansible/runner/tools.lock.json']), json.loads(after['ansible/runner/tools.lock.json'])
    if (old['tofu']['version'] != '1.13.1' or set(new) != set(old) or
            any(new[key] != old[key] for key in old if key != 'tofu') or
            set(new['tofu']) != {'version', 'url', 'sha256'} or new['tofu']['version'] != '1.13.0' or
            new['tofu']['url'] != tools.TOOLS['tofu'][0] + tools.TOOLS['tofu'][1].format(version='1.13.0')): refuse()
    raw = download(new['tofu']['url'], prefix=tools.TOOLS['tofu'][0])
    if digest(raw) != new['tofu']['sha256']: refuse()
    return after


def repository(gate, state):
    gate.identity()
    row = gate.api.request('GET', gate.repository)
    if (row.get('node_id') != state['repository']['node'] or row.get('default_branch') != 'main' or
            gate.scope['repositoryId'] != state['repository']['id'] or gate.scope['repository'] != state['repository']['name']): refuse()
    main = ref(gate, 'main')
    if main is None or main['object']['sha'] != state['driver']: refuse()


def ref(gate, branch):
    try: row = gate.api.request('GET', gate.repository+'/git/ref/heads/'+branch)
    except GitHubHTTPError as error:
        if error.status == 404: return None
        raise
    if (not isinstance(row, dict) or not isinstance(row.get('object'), dict) or
            not isinstance(row['object'].get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', row['object']['sha']) or
            'ref' in row and row['ref'] != 'refs/heads/'+branch): refuse()
    return row


def base_current(gate, state):
    row = ref(gate, state['branch'])
    if row is None or row['object']['sha'] != state['base']['head']: refuse()


def write(gate, state, save, kind, method, route, body):
    intent = {'kind': kind, 'method': method, 'route': route, 'body': body}
    if state['intent'] is not None and state['intent'] != intent: refuse()
    state['intent'] = intent; save()
    try: return gate.api.request(method, route, body)
    except GitHubHTTPError as error:
        if 400 <= error.status < 500 and error.status not in (408, 429):
            state['rejected'] = True; save()
        raise


def prepare(gate, state, save, source, nonce):
    if state is not None: return state
    row = gate.api.request('GET', gate.repository)
    if (row.get('default_branch') != 'main' or not row.get('node_id')): refuse()
    gate.identity(); inventory()
    tree = workspace.remote_tree(gate.api, gate.scope['repository'], source['revision'])
    contents = workspace.snapshot(gate.scope['repository'], source['revision'], expected=tree)
    if json.loads(contents['ansible/runner/tools.lock.json'])['tofu']['version'] != '1.13.1': refuse()
    state = dict(format=1, nonce=nonce, driver=source['revision'], helpers=control.helper_hash(),
        repository={'name': gate.scope['repository'], 'id': gate.scope['repositoryId'], 'node': row['node_id']},
        source=tree, inputs=encode_inputs(contents, tree), branch=gate.scope['base'],
        base=None, native=None, expectation=None, bound=None, intent=None, rejected=False, closed=False, deleted={})
    save(state)
    return state


def create(gate, state, save):
    after = capture_artifact(state)
    current = ref(gate, state['branch'])
    base = state['base']
    if current is not None:
        intent = {'kind': 'create-ref', 'method': 'POST', 'route': gate.repository+'/git/refs',
                  'body': {'ref': 'refs/heads/'+state['branch'], 'sha': base['head'] if base else None}}
        if (not base or not base.get('head') or current['object']['sha'] != base['head'] or
                state['intent'] is not None and state['intent'] != intent or
                not (base.get('created') or state['intent'] == intent)): refuse()
        base['created'] = True; state['intent'] = None; save(); return
    if base and base.get('created'): refuse()
    if base is None:
        state['base'] = base = {'blobs': {}, 'tree': None, 'head': None, 'created': False}; save()
    for path, raw in sorted(after.items()):
        if path in base['blobs']:
            if base['blobs'][path] != blob(raw): refuse()
            continue
        row = write(gate, state, save, 'blob:'+path, 'POST', gate.repository+'/git/blobs',
                    {'content': base64.b64encode(raw).decode(), 'encoding': 'base64'})
        if row.get('sha') != blob(raw): refuse()
        base['blobs'][path] = row['sha']; state['intent'] = None; save()
    if base['tree'] is None:
        parent = gate.api.request('GET', gate.repository+'/git/commits/'+state['driver'])
        row = write(gate, state, save, 'tree', 'POST', gate.repository+'/git/trees',
            {'base_tree': parent['tree']['sha'], 'tree': [{'path': path, 'mode': '100644', 'type': 'blob', 'sha': sha}
                                                       for path, sha in sorted(base['blobs'].items())]})
        if not isinstance(row.get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', row['sha']): refuse()
        base['tree'] = row['sha']; state['intent'] = None; save()
    if base['head'] is None:
        if state['intent'] is not None: refuse()  # Unknown commit response cannot establish ref ownership.
        row = write(gate, state, save, 'commit', 'POST', gate.repository+'/git/commits',
            {'message': 'Prepare disposable dependency fixture', 'tree': base['tree'], 'parents': [state['driver']]})
        if not isinstance(row.get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', row['sha']): refuse()
        base['head'] = row['sha']; state['intent'] = None; save()
    commit = gate.api.request('GET', gate.repository+'/git/commits/'+base['head'])
    if (commit.get('tree', {}).get('sha') != base['tree'] or
            [row['sha'] for row in commit.get('parents', [])] != [state['driver']] or
            commit.get('message') != 'Prepare disposable dependency fixture'): refuse()
    expected = copy.deepcopy(state['source'])
    for path, sha in base['blobs'].items(): expected[path]['sha'] = sha
    if workspace.remote_tree(gate.api, gate.scope['repository'], base['head']) != expected: refuse()
    write(gate, state, save, 'create-ref', 'POST', gate.repository+'/git/refs',
          {'ref': 'refs/heads/'+state['branch'], 'sha': base['head']})
    base_current(gate, state)
    base['created'] = True; state['intent'] = None; save()


def identity(gate, state, *, closed=False):
    native = state['native']
    if (not native or not native['branch'].startswith(gate.scope['branchPrefix']) or
            native['user'] != {'login': gate.scope['requester'], 'type': 'Bot'}): refuse()
    if closed:
        row = gate.api.request('GET', gate.repository+'/pulls/'+str(native['number']))
    else: row = gate.current(native['number'])
    if (row.get('node_id') != native['node'] or row.get('number') != native['number'] or row.get('merged') or
            row.get('state') not in ('open', 'closed') or
            {key: row.get('user', {}).get(key) for key in ('login', 'type')} != native['user'] or
            row.get('head', {}).get('ref') != native['branch'] or
            row['head'].get('repo', {}).get('id') != state['repository']['id'] or
            row['base'].get('repo', {}).get('id') != state['repository']['id'] or
            row['base'].get('ref') != state['branch'] or row['base'].get('sha') != state['base']['head']): refuse()
    return row


def record_native(gate, state, save, number):
    base_current(gate, state)
    row = gate.current(number)
    pulls = gate.api.request('GET', gate.repository+'/pulls?state=open&per_page=100')
    if not isinstance(pulls, list) or len(pulls) >= 100: refuse()
    matches = [item for item in pulls if item.get('user', {}).get('login') == gate.scope['requester'] and
               item.get('base', {}).get('ref') == state['branch'] and
               item.get('head', {}).get('ref', '').startswith(gate.scope['branchPrefix'])]
    if len(matches) != 1 or matches[0]['number'] != number or not row.get('draft') or not row.get('node_id'): refuse()
    base = workspace.remote_tree(gate.api, gate.scope['repository'], state['base']['head'])
    head = workspace.remote_tree(gate.api, gate.scope['repository'], row['head']['sha'])
    changed = workspace.owned_diff(base, head, PATHS)
    contents = workspace.snapshot(gate.scope['repository'], row['head']['sha'], expected=head)
    before = workspace.snapshot(gate.scope['repository'], state['base']['head'], expected=base)
    for path in changed: control.file_change(path, before[path], contents[path])
    if json.loads(contents['ansible/runner/tools.lock.json'])['tofu']['version'] != '1.13.1': refuse()
    native = {'number': number, 'node': row['node_id'], 'branch': row['head']['ref'],
              'head': row['head']['sha'], 'user': {key: row['user'][key] for key in ('login', 'type')}}
    if state['native'] is not None and state['native'] != native: refuse()
    state['native'] = native; save()


def verified(gate, state):
    base_current(gate, state)
    row = identity(gate, state)
    value, owners = control.trusted_validation(gate, state['native']['number'])
    operation = control.load('operation.json')
    record = control.load('toolchain.json')
    checks = sorted(set(item for owner in inventory().values() for item in owner['checks']))
    expected = {key: value[key] for key in ('pinset', 'helpers', 'checks', 'toolchain')}
    if (set(owners) != {'tool:tofu'} or operation['owners'] != ['tool:tofu'] or
            operation['number'] != state['native']['number'] or operation['scope'] != gate.scope or
            operation['checks'] != checks or value['checks'] != dict.fromkeys(checks, 'PASS') or
            value['helpers'] != state['helpers'] or value['pinset'] != fingerprint(control.CANDIDATE, owners) or
            value['head'] != row['head']['sha'] or value['base'] != row['base']['sha'] or
            operation['head'] != value['head'] or operation['base'] != value['base'] or
            record['operation'] != operation['operation'] or record['candidateTree'] != value['candidateTree'] or
            record['role'] != 'candidate-runner' or
            not re.fullmatch('sha256:[a-f0-9]{64}', record['imageId']) or
            'cloudlab-maintenance-candidate@'+record['imageId'] not in value['toolchain']): refuse()
    contents = workspace.files(control.CANDIDATE)
    if set(contents) != set(state['source']): refuse()
    check_plan = control.load('check-plan.json')
    mode_check = check_plan['fileModes']
    if type(mode_check) is not bool or check_plan['operation'] != operation['operation']: refuse()
    remote = workspace.remote_tree(gate.api, gate.scope['repository'], value['head'])
    snapshot = workspace.snapshot(gate.scope['repository'], value['head'], expected=remote)
    if control.load('head-tree.json') != remote or control.load('baseline.json') != {
            path: digest(raw) for path, raw in snapshot.items()}: refuse()
    for path, item in state['source'].items():
        target = control.CANDIDATE/path
        if blob(target.read_bytes()) != item['sha']: refuse()
        if mode_check and bool(target.stat().st_mode & 0o111) != (item['mode'] == '100755'): refuse()
    expected['toolchain'] = [item for item in value['toolchain'] if not item.startswith('cloudlab-maintenance-candidate@')]
    return row, value, expected


def expect_publication(gate, state, save):
    row, value, inputs = verified(gate, state)
    if row['head']['sha'] != state['native']['head'] or not row.get('draft'): refuse()
    patch = workspace.changes(control.CANDIDATE, control.load('baseline.json'), PATHS)
    if not patch: refuse()
    expectation = {'head': row['head']['sha'], 'tree': value['candidateTree'], 'inputs': inputs,
                   'operation': value['operation'], 'source': digest(canonical(state['source']))}
    if state['expectation'] is not None and state['expectation'] != expectation: refuse()
    state['expectation'] = expectation; save()


def bind_verified(gate, state, save):
    row, value, inputs = verified(gate, state)
    if not row.get('draft') or workspace.changes(control.CANDIDATE, control.load('baseline.json'), PATHS): refuse()
    head = row['head']['sha']
    if head != state['native']['head']:
        expected = state['expectation']
        if (not expected or expected['head'] != state['native']['head'] or expected['tree'] != value['candidateTree'] or
                expected['inputs'] != inputs or expected['source'] != digest(canonical(state['source']))): refuse()
        commit = gate.api.request('GET', gate.repository+'/git/commits/'+head)
        if ([item['sha'] for item in commit.get('parents', [])] != [expected['head']] or
                commit.get('message') != 'Maintain reviewed dependency companions'): refuse()
    if workspace.remote_tree(gate.api, gate.scope['repository'], head) != state['source']: refuse()
    if state['bound'] is not None and state['bound'] != head: refuse()
    state['bound'] = head; save()


def delete_ref(gate, state, save, label, branch, head):
    route = gate.repository+'/git/ref/heads/'+branch
    row = ref(gate, branch)
    mutation = digest(canonical({'repository': state['repository']['node'], 'branch': branch, 'head': head}))
    body = {'query': 'mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}',
            'variables': {'input': {'repositoryId': state['repository']['node'], 'clientMutationId': mutation,
                'refUpdates': [{'name': 'refs/heads/'+branch, 'beforeOid': head, 'afterOid': '0'*40, 'force': False}]}}}
    intent = {'kind': 'delete:'+label, 'method': 'POST', 'route': 'graphql', 'body': body}
    pending = state['intent'] == intent
    if state['intent'] is not None and not pending: refuse()
    if row is None:
        if not state['deleted'].get(label) and not pending: refuse()
    else:
        if row['object']['sha'] != head or state['deleted'].get(label): refuse()
        result = write(gate, state, save, 'delete:'+label, 'POST', 'graphql', body)
        if (not isinstance(result, dict) or result.get('errors') or
                result.get('data', {}).get('updateRefs', {}).get('clientMutationId') != mutation): refuse()
        if ref(gate, branch) is not None: refuse()
    state['deleted'][label] = True; state['intent'] = None; save()


def cleanup(gate, state, save):
    if not state['base'] or not state['base'].get('created'): refuse()
    if state['intent'] is not None and state['intent']['kind'] not in {'close', 'delete:bot', 'delete:base'}: refuse()
    if not state['deleted'].get('base') and not (state['intent'] and state['intent']['kind'] == 'delete:base'):
        base_current(gate, state)
    if state['native']:
        row = identity(gate, state, closed=True)
        if row['head']['sha'] not in {state['native']['head'], state['bound']}: refuse()
        if row['state'] == 'open':
            if state['intent'] is not None and state['intent']['kind'] != 'close': refuse()
            write(gate, state, save, 'close', 'PATCH', gate.repository+'/pulls/'+str(state['native']['number']), {'state': 'closed'})
            current = identity(gate, state, closed=True)
            if current['state'] != 'closed' or current['head']['sha'] != row['head']['sha']: refuse()
        elif not state['closed'] and state['intent'] != {'kind': 'close', 'method': 'PATCH',
                'route': gate.repository+'/pulls/'+str(state['native']['number']), 'body': {'state': 'closed'}}: refuse()
        state['closed'] = True
        if state['intent'] and state['intent']['kind'] == 'close': state['intent'] = None
        save()
        if state['deleted'].get('bot'):
            if ref(gate, state['native']['branch']) is not None: refuse()
        else: delete_ref(gate, state, save, 'bot', state['native']['branch'], row['head']['sha'])
    else:
        pulls = gate.api.request('GET', gate.repository+'/pulls?state=open&per_page=100')
        if not isinstance(pulls, list) or len(pulls) >= 100 or any(item.get('base', {}).get('ref') == state['branch'] for item in pulls): refuse()
    delete_ref(gate, state, save, 'base', state['branch'], state['base']['head'])


def run(action, request):
    stages = {'create': create, 'record-native': record_native, 'expect-publication': expect_publication,
              'bind-verified': bind_verified, 'cleanup': cleanup}
    if action not in {'prepare', *stages} or not isinstance(request, dict) or set(request) != (
            {'nonce', 'number'} if action == 'record-native' else {'nonce'}): refuse()
    nonce = request['nonce']
    if not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce): refuse()
    source = control.committed_payload()
    if source['branch'] != 'main': refuse()
    with control.writer_lock():
        from playbooks.dependencies.files.toolchain import embedded
        embedded(control.ROOT)
        if any((control.HANDOFF/name).exists() for name in ('request.json', 'request.tmp', 'result.json', 'result.tmp')): refuse()
        state, previous = journal(nonce)
        if state is not None:
            validate(state)
            if state['driver'] != source['revision'] or state['helpers'] != control.helper_hash(): refuse()
            if state['intent'] is not None and action not in {'create', 'cleanup'}: refuse()
        values = control.dotenv_values(control.ROOT/'.env', interpolate=False)
        token = values.get('OP_SERVICE_ACCOUNT_TOKEN')
        if not token: refuse()
        lease = None
        try:
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = token
            lease = control.repository_tokens.issue(values, 'public-platform', {'contents': 'write', 'pull_requests': 'write'}, include_requester=True)
            if source['repository'] != 'https://github.com/'+lease['repository']+'.git': refuse()
            gate = Gate(GitHub(lease['token']), control.scope(lease, 'cloudlab-maintenance-fixture/'+nonce), control.CONTROL)
            def save(initial=None):
                nonlocal state, previous
                if initial is not None: state = initial
                previous = journal(nonce, state, previous)
            if action == 'prepare':
                state = prepare(gate, state, save, source, nonce)
                validate(state); repository(gate, state)
                # Public data only; copy this descriptor to the separate artifact target.
                path = control.CONTROL/'fixtures'/(nonce+'.public.json')
                raw = canonical(descriptor(state))
                if path.exists():
                    if path.is_symlink() or path.read_bytes() != raw: refuse()
                else:
                    with path.open('xb') as stream: stream.write(raw)
                    path.chmod(0o644)
            else:
                if state is None: refuse()
                repository(gate, state); inventory()
                if action not in {'create', 'cleanup'}: base_current(gate, state)
                if action == 'record-native': stages[action](gate, state, save, request['number'])
                else: stages[action](gate, state, save)
            return {'fixtureStageCompleted': True, 'companions': 10, 'nativeAcceptanceComplete': False}
        finally:
            os.environ.pop('OP_SERVICE_ACCOUNT_TOKEN', None)
            if lease is not None: control.repository_tokens.revoke(lease)


if __name__ == '__main__':
    try:
        action = sys.argv[1] if len(sys.argv) == 2 else ''
        if action == 'artifact':
            print(json.dumps(artifact(read_public(Path('/fixture-input.json')), Path('/artifact'))))
        else:
            raw = sys.stdin.buffer.read(16385)
            if len(raw) > 16384: refuse()
            print(json.dumps(run(action, document(raw))))
    except Exception:
        raise SystemExit('Dependency fixture refused; credentials and diagnostics withheld') from None
