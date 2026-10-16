"""Pull exact OCI digests from each node host using short-lived, pull-only tokens."""
import base64
import http.client
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
from urllib.parse import urlencode, urlsplit


def token(payload):
    host, project = payload['host'], payload['project']
    parsed = urlsplit('https://' + host)
    if (parsed.hostname != host or parsed.netloc != host or parsed.path or parsed.query or parsed.fragment or
            not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', host) or
            not re.fullmatch(r'cloudlab-[a-z]+', project) or
            payload['username'] != 'robot$' + project + '+pull' or len(payload['password']) < 32 or
            not re.fullmatch(r'sha256:[a-f0-9]{64}', payload['digest'])):
        raise ValueError('Node proof requires a canonical registry, pull identity and exact digest')
    connection = http.client.HTTPSConnection(host, timeout=20)
    try:
        scope = 'repository:' + project + '/bootstrap:pull'
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
        if (claims.get('access') != [{'type': 'repository', 'name': project + '/bootstrap', 'actions': ['pull']}] or
                claims.get('aud') not in ('harbor-registry', ['harbor-registry']) or
                not 240 <= claims.get('exp', 0) - time.time() <= 305):
            raise RuntimeError('Node token exceeds its exact pull scope or five-minute lifetime')
        return value
    finally:
        connection.close()


def run(payload):
    bearer = token(payload)
    host = payload['host']
    reference = host + '/' + payload['project'] + '/bootstrap@' + payload['digest']
    namespace = 'cloudlab-harbor-proof-' + secrets.token_hex(8)
    command = ['/usr/local/bin/k3s', 'ctr', '--namespace', namespace]
    deadline = None
    def execute(*arguments, timeout=30, required=True):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError('Owned node proof cleanup exceeded its time bound')
            timeout = min(timeout, remaining)
        result = subprocess.run([*command, *arguments], capture_output=True, timeout=timeout)
        if required and result.returncode:
            raise RuntimeError('Node containerd proof failed; private diagnostics withheld')
        return result
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
        snapshots = execute('snapshots', 'list', '--quiet').stdout.decode().splitlines()
        if len(snapshots) > 64:
            raise RuntimeError('Node proof snapshot inventory exceeds its isolated scope')
        while snapshots:
            previous = set(snapshots)
            for snapshot in snapshots:
                execute('snapshots', 'remove', snapshot, required=False)
            snapshots = execute('snapshots', 'list', '--quiet').stdout.decode().splitlines()
            if snapshots and not set(snapshots) < previous:
                raise RuntimeError('Owned node proof snapshots could not be cleaned up')
        execute('namespaces', 'remove', namespace)
    return {'host_dns_tls': True, 'containerd_pull_by_digest': True, 'temporary_credentials_removed': True}


def verify_nodes(client, record):
    from automation.connectivity.preflight import ssh
    results = []
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
            result = json.loads(ssh(prefix, client.values[prefix + '_HOST'], 'python3 -c ' + shlex.quote(source),
                                    input=json.dumps(payload), timeout=330))
            if result != {'host_dns_tls': True, 'containerd_pull_by_digest': True, 'temporary_credentials_removed': True}:
                raise RuntimeError('Node registry pull proof returned incomplete evidence')
            results.append(result)
    return len(results)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        raw = sys.stdin.read(16385)
        if len(raw) > 16384:
            raise ValueError('Node proof input exceeds its bound')
        print(json.dumps(run(json.loads(raw)), sort_keys=True))
    except Exception:
        raise SystemExit('Node registry proof incomplete; private values withheld') from None
