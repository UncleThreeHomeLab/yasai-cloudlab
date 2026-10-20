"""Pull exact OCI digests from each node host using short-lived, pull-only tokens."""
import base64
import http.client
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import time
import traceback
from urllib.parse import urlencode, urlsplit


class NodeCommandError(RuntimeError):
    def __init__(self, namespace, arguments, result):
        super().__init__('Node containerd proof failed; private diagnostics withheld')
        words = ('unauthorized', 'denied', 'permission', 'invalid', 'unsupported', 'unknown', 'token', 'credential',
                 'authorization', 'certificate', 'x509', 'connection refused', 'no such host', 'hosts', 'local',
                 'fetch', 'resolve', 'unpack', 'snapshot', 'content', '401', '403', '404', '500')
        error = result.stderr.decode(errors='replace').lower()
        self.details = {'namespace': namespace, 'command': list(arguments[:2]), 'exit_code': result.returncode,
                        'classes': [word for word in words if word in error]}


def table_keys(raw, columns, limit):
    lines = raw.decode().splitlines()
    if not lines or lines[0].split() != list(columns) or len(lines) > limit + 1:
        raise RuntimeError('Node containerd inventory format or size changed')
    keys = [line.split()[0] for line in lines[1:] if line.strip()]
    if len(keys) != len(set(keys)) or any(not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9:._+-]*', key) for key in keys):
        raise RuntimeError('Node containerd inventory returned an invalid identity')
    return keys


def token(payload):
    host, project = payload['host'], payload['project']
    repository = payload.get('repository', 'bootstrap')
    parsed = urlsplit('https://' + host)
    if (parsed.hostname != host or parsed.netloc != host or parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', host) or
            project not in ('cloudlab-public', 'cloudlab-private') or
            not isinstance(repository, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', repository) or
            payload['username'] != 'robot$' + project + '+pull' or len(payload['password']) < 32 or
            not re.fullmatch(r'sha256:[a-f0-9]{64}', payload['digest'])):
        raise ValueError('Node proof requires a canonical registry, pull identity and exact digest')
    connection = http.client.HTTPSConnection(host, timeout=20)
    try:
        scope = 'repository:' + project + '/' + repository + ':pull'
        authorization = base64.b64encode((payload['username'] + ':' + payload['password']).encode()).decode()
        connection.request('GET', '/service/token?' + urlencode({'service': 'harbor-registry', 'scope': scope}),
                           headers={'Authorization': 'Basic ' + authorization})
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError('Node registry authentication failed; private response withheld')
        raw = response.read(65537)
        if len(raw) > 65536:
            raise RuntimeError('Node registry token exceeds its bound')
        value = json.loads(raw)['token']
        if not re.fullmatch(r'[a-zA-Z0-9_-]+[.][a-zA-Z0-9_-]+[.][a-zA-Z0-9_-]+', value):
            raise RuntimeError('Node registry returned an invalid token')
        encoded = value.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4)))
        if (claims.get('access') != [{'type': 'repository', 'name': project + '/' + repository, 'actions': ['pull']}] or
                claims.get('aud') not in ('harbor-registry', ['harbor-registry']) or
                not 240 <= claims.get('exp', 0) - time.time() <= 305):
            raise RuntimeError('Node token exceeds its exact pull scope or five-minute lifetime')
        return value
    finally:
        connection.close()


def run(payload):
    bearer = token(payload)
    host = payload['host']
    reference = host + '/' + payload['project'] + '/' + payload.get('repository', 'bootstrap') + '@' + payload['digest']
    namespace = 'cloudlab-harbor-proof-' + secrets.token_hex(8)
    command = ['/usr/local/bin/k3s', 'ctr', '--namespace', namespace]
    deadline = None
    def execute(*arguments, timeout=30, required=True, target=None):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Owned node proof cleanup exceeded its time bound')
            timeout = min(timeout, remaining)
        current = [*command[:3], target or namespace]
        result = subprocess.run([*current, *arguments], capture_output=True, timeout=timeout)
        if required and result.returncode:
            raise NodeCommandError(target or namespace, arguments, result)
        return result
    # This reserved prefix belongs only to the serialized probe; never remove data-bearing leftovers.
    deadline = time.monotonic() + 60
    for previous in table_keys(execute('namespaces', 'list').stdout, ('NAME', 'LABELS'), 128):
        if not re.fullmatch(r'cloudlab-harbor-proof-[a-f0-9]{16}', previous):
            continue
        children = (('images', 'list'), ('snapshots', 'list'), ('containers', 'list'), ('content', 'list'), ('leases', 'list'))
        if all(len(execute(*resource, target=previous).stdout.decode().splitlines()) == 1 for resource in children):
            execute('namespaces', 'remove', previous)
    deadline = None
    execute('namespaces', 'create', namespace)
    try:
        with tempfile.TemporaryDirectory(prefix='cloudlab-harbor-pull-') as temporary:
            directory = Path(temporary) / host
            directory.mkdir(mode=0o700)
            configuration = directory / 'hosts.toml'
            origin = json.dumps('https://' + host)
            configuration.write_text('server = ' + origin + '\n[host.' + origin + ']\n'
                'capabilities = ["pull", "resolve"]\n[host.' + origin + '.header]\n'
                'authorization = [' + json.dumps('Bearer ' + bearer) + ']\n')
            configuration.chmod(0o600)
            execute('images', 'pull', '--local', '--hosts-dir', temporary, '--platform', 'linux/amd64',
                    '--max-concurrent-downloads', '2', reference, timeout=180)
    finally:
        deadline = time.monotonic() + 60
        execute('images', 'remove', reference, required=False)
        snapshots = table_keys(execute('snapshots', 'list').stdout, ('KEY', 'PARENT', 'KIND'), 64)
        while snapshots:
            previous = set(snapshots)
            for snapshot in snapshots:
                execute('snapshots', 'remove', snapshot, required=False)
            snapshots = table_keys(execute('snapshots', 'list').stdout, ('KEY', 'PARENT', 'KIND'), 64)
            if snapshots and not set(snapshots) < previous:
                raise RuntimeError('Owned node proof snapshots could not be cleaned up')
        execute('namespaces', 'remove', namespace)
    identity = hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest()
    return {'host_dns_tls': True, 'containerd_pull_by_digest': True, 'temporary_credentials_removed': True,
            'host_identity': identity}


def verify_nodes(client, record):
    from playbooks.access.files.preflight import ssh
    endpoints = {(client.values.get(prefix + '_HOST'), client.values.get(prefix + '_PORT') or '22')
                 for prefix in ('VM', 'VM2')}
    if len(endpoints) != 2:
        raise ValueError('Containerd proof requires two distinct node endpoints')
    results, identities = [], {}
    source = Path(__file__).read_text()
    for prefix in ('VM', 'VM2'):
        for suffix in ('HOST', 'USER', 'PASSWORD'):
            key = prefix + '_' + suffix
            if not client.values.get(key):
                raise ValueError('Both existing node SSH inputs are required for containerd proof')
            os.environ[key] = client.values[key]
        os.environ[prefix + '_PORT'] = client.values.get(prefix + '_PORT') or '22'
        for project, entry in record['projects'].items():
            credential = client.private['robots'][project + '-pull']
            payload = {'username': credential['username'], 'password': credential['password'],
                       'host': client.private['host'], 'project': project, 'digest': entry['digest']}
            if 'repository' in entry:
                payload['repository'] = entry['repository']
            result = json.loads(ssh(prefix, client.values[prefix + '_HOST'], 'python3 -c ' + shlex.quote(source),
                                    input=json.dumps(payload), timeout=420,
                                    diagnostics=client.path / 'artifacts/node-diagnostics.txt'))
            identity = result.pop('host_identity', '')
            if (not re.fullmatch(r'[a-f0-9]{64}', identity) or
                    (prefix in identities and identities[prefix] != identity) or
                    result != {'host_dns_tls': True, 'containerd_pull_by_digest': True, 'temporary_credentials_removed': True}):
                raise RuntimeError('Node registry pull proof returned incomplete evidence')
            identities[prefix] = identity
            results.append(result)
    if len(set(identities.values())) != 2:
        raise RuntimeError('Both registry endpoints reached the same node kernel; two-node proof refused')
    return len(results)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raw = sys.stdin.read(16385)
        if len(raw) > 16384:
            raise ValueError('Node proof input exceeds its bound')
        print(json.dumps(run(json.loads(raw)), sort_keys=True))
    except Exception as error:
        print(json.dumps({'exception': type(error).__name__, 'frames': [
            {'file': Path(frame.filename).name, 'line': frame.lineno}
            for frame in traceback.extract_tb(error.__traceback__)],
            'native': error.details if isinstance(error, NodeCommandError) else None}), file=sys.stderr)
        raise SystemExit('Node registry proof incomplete; private values withheld') from None
