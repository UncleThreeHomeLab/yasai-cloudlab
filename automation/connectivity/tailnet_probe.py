"""Ephemeral clients prove both network denial and Kubernetes RBAC denial."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))
from control import API
from verify_access import binaries, tailnet_connect
from automation.connectivity.traffic import https

GRANT_RECEIPT = Path('/state/connectivity/rbac-probe.json')


def remove_retained_grant(api):
    if not GRANT_RECEIPT.exists():
        return
    grant = json.loads(GRANT_RECEIPT.read_text())
    import ipaddress
    if (set(grant) != {'src', 'dst', 'ip'} or grant['ip'] != ['tcp:443']
            or len(grant['src']) != 1 or len(grant['dst']) != 1
            or any(ipaddress.ip_address(ip) not in ipaddress.ip_network('100.64.0.0/10') for ip in grant['src'] + grant['dst'])):
        raise RuntimeError('Retained fixture grant has an invalid ownership contract')
    current, etag = api.request('GET', 'tailnet/-/acl')
    if not etag:
        raise RuntimeError('Cannot safely remove ephemeral RBAC grant without an ETag')
    if grant in current.get('grants', []):
        current['grants'].remove(grant)
        api.request('POST', 'tailnet/-/acl', current, etag)
    if grant in api.request('GET', 'tailnet/-/acl')[0].get('grants', []):
        raise RuntimeError('Ephemeral RBAC transport grant cleanup failed')
    GRANT_RECEIPT.unlink()


@contextmanager
def client(*, rbac=False):
    with tempfile.TemporaryDirectory(prefix='cloudlab-access-denial-') as folder:
        directory = Path(folder)
        binaries(directory)
        tag = 'tag:cloudlab-operator' if rbac else 'tag:cloudlab-denied'
        api = API('tailscale-operator' if rbac else 'tailscale-test-enrollment')
        credential, _ = api.request('POST', 'tailnet/-/keys', {'capabilities': {'devices': {'create': {
            'reusable': False, 'ephemeral': True, 'preauthorized': True, 'tags': [tag]}}}, 'expirySeconds': 300})
        key = directory / 'key'
        key.write_text(credential['key'])
        key.chmod(0o600)
        control_socket = str(directory / 'tailscale.sock')
        cli = [str(directory / 'tailscale'), '--socket=' + control_socket]
        with (directory / 'private.log').open('w') as log:
            process = subprocess.Popen([str(directory / 'tailscaled'), '--tun=userspace-networking',
                '--state=mem:', '--socket=' + control_socket], stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if Path(control_socket).exists(): break
                    time.sleep(0.1)
                result = subprocess.run(cli + ['up', '--auth-key=file:' + str(key),
                    '--hostname=cloudlab-rbac-fixture' if rbac else '--hostname=cloudlab-network-denial-fixture',
                    '--accept-dns=false', '--accept-routes=false', '--timeout=60s'], capture_output=True, timeout=75)
                key.unlink()
                if result.returncode:
                    raise RuntimeError('Ephemeral access fixture enrollment failed')
                status = json.loads(subprocess.check_output(cli + ['status', '--json'], stderr=subprocess.DEVNULL))
                if status['BackendState'] != 'Running' or status['Self'].get('Tags') != [tag]:
                    raise RuntimeError('Access fixture has an unexpected tailnet identity')
                yield control_socket, status
            finally:
                try:
                    subprocess.run(cli + ['logout'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                finally:
                    process.terminate()
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def dial(control_socket, address):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(12)
    try:
        stream.connect(control_socket)
        request = ('POST /localapi/v0/dial HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: upgrade\r\n'
                   'Upgrade: ts-dial\r\nDial-Host: ' + address + '\r\nDial-Port: 443\r\nContent-Length: 0\r\n\r\n')
        stream.sendall(request.encode('ascii'))
        header = b''
        while not header.endswith(b'\r\n\r\n') and len(header) < 8192:
            byte = stream.recv(1)
            if not byte: break
            header += byte
        if not header.startswith(b'HTTP/1.1 101 '):
            raise RuntimeError('RBAC fixture did not establish a tailnet-only connection')
        return stream
    except Exception:
        stream.close()
        raise


@contextmanager
def rbac_transport(source, destination):
    """Allow one ephemeral IP to one API VIP; grant no Kubernetes permission."""
    api = API('tailscale-policy')
    remove_retained_grant(api)
    grant = {'src': [source], 'dst': [destination], 'ip': ['tcp:443']}
    current, etag = api.request('GET', 'tailnet/-/acl')
    if grant in current.get('grants', []) or not etag:
        raise RuntimeError('Ephemeral RBAC transport grant collides or lacks a concurrency guard')
    current.setdefault('grants', []).append(grant)
    if api.request('POST', 'tailnet/-/acl/validate', current)[0]:
        raise RuntimeError('Ephemeral RBAC transport policy failed validation')
    GRANT_RECEIPT.parent.mkdir(mode=0o700, exist_ok=True)
    temporary = GRANT_RECEIPT.with_suffix('.tmp')
    descriptor = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(grant, stream)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(GRANT_RECEIPT)
    directory = os.open(GRANT_RECEIPT.parent, os.O_DIRECTORY)
    try: os.fsync(directory)
    finally: os.close(directory)
    try:
        api.request('POST', 'tailnet/-/acl', current, etag)
        yield
    finally:
        remove_retained_grant(api)


def verify(api_hostname, api_address, ingress_address, nameservers):
    with client() as (control_socket, status):
        peers = {ip for p in (status.get('Peer') or {}).values() for ip in p.get('TailscaleIPs', [])}
        for address, port in [(api_address, 443), (ingress_address, 443)] + [(server, 53) for server in nameservers]:
            if tailnet_connect(control_socket, address, port, peers):
                raise RuntimeError('Unauthorized tailnet fixture reached a private route')
    with client(rbac=True) as (control_socket, status):
        source = next(ip for ip in status['TailscaleIPs'] if ':' not in ip)
        with rbac_transport(source, api_address):
            response = None
            for attempt in range(20):
                try:
                    response = https(api_hostname, stream=dial(control_socket, api_address), path='/api/v1/namespaces')
                    break
                except (OSError, RuntimeError):
                    if attempt == 19: raise
                    time.sleep(2)
            if response['status'] != 403:
                raise RuntimeError('Network-authorized but RBAC-unbound tailnet identity was not forbidden')
            body = json.loads(response['body'])
            if body.get('reason') != 'Forbidden' or body.get('kind') != 'Status':
                raise RuntimeError('RBAC denial was not a Kubernetes authorization response')
    return {'tailnet_unauthorized_denied': True, 'api_rbac_denied': True, 'ephemeral_grant_removed': True}
