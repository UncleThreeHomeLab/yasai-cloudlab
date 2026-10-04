"""Allowed workstation SSH and an isolated, ephemeral denied tailnet client."""
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

from control import API, HOST_TAG, TEST_TAG, policy


def ssh(prefix, host, command, known_hosts='/state/known_hosts', strict='yes', *, input=None, timeout=30):
    env = dict(os.environ, SSHPASS=os.environ[prefix + '_PASSWORD'])
    result = subprocess.run(['sshpass', '-e', 'ssh', '-p', os.environ[prefix + '_PORT'],
        '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1', '-o', 'PreferredAuthentications=password',
        '-o', 'PubkeyAuthentication=no', '-o', 'StrictHostKeyChecking=' + strict,
        '-o', 'UserKnownHostsFile=' + known_hosts, os.environ[prefix + '_USER'] + '@' + host, command],
        env=env, input=input, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('SSH verification failed for ' + prefix + '; recovery path retained')
    return result.stdout


def binaries(directory):
    pin = json.loads(Path(__file__).with_name('release.json').read_text())
    archive = urllib.request.urlopen(pin['url'], timeout=120).read()
    if hashlib.sha256(archive).hexdigest() != pin['sha256']:
        raise RuntimeError('Tailscale test artifact checksum mismatch')
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for name in ('tailscale', 'tailscaled'):
            member = 'tailscale_' + pin['version'] + '_amd64/' + name
            target = directory / name
            target.write_bytes(tar.extractfile(member).read())
            target.chmod(0o700)


def tailnet_connect(control_socket, address, destination_port, peers):
    # SOCKS and the nc CLI may fall back to the workstation route for peers
    # omitted by policy. Use LocalAPI directly and never honor Dial-Self.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.settimeout(10)
        stream.connect(control_socket)
        request = ('POST /localapi/v0/dial HTTP/1.1\r\n'
                   'Host: local-tailscaled.sock\r\nConnection: upgrade\r\n'
                   'Upgrade: ts-dial\r\nDial-Host: ' + address + '\r\n'
                   'Dial-Port: ' + str(destination_port) + '\r\nContent-Length: 0\r\n\r\n')
        stream.sendall(request.encode('ascii'))
        response = http.client.HTTPResponse(stream)
        try:
            response.begin()
        except socket.timeout:
            raise RuntimeError('Denied fixture dial timed out; denial is not proven') from None
        if response.status == 101:
            return True
        if response.status == 200 and response.getheader('Dial-Self') == 'true':
            if address in peers:
                raise RuntimeError('Known tailnet peer unexpectedly requested system routing')
            return False
        raise RuntimeError('Denied fixture dial failed unexpectedly; denial is not proven')


def verify():
    policy(False)
    with tempfile.TemporaryDirectory(prefix='cloudlab-access-') as temp:
        directory = Path(temp)
        targets = []
        # Resolve via already trusted recovery SSH, then verify identical SSH keys
        # over tailnet. Public SSH success cannot satisfy the allowed-client gate.
        for prefix in ('VM', 'VM2'):
            host = os.environ[prefix + '_HOST']
            status = json.loads(ssh(prefix, host, 'tailscale status --json'))
            if status['BackendState'] != 'Running' or status['Self'].get('Tags') != [HOST_TAG]:
                raise RuntimeError('Host Tailscale is not ready')
            address = next(a for a in status['TailscaleIPs'] if ipaddress.ip_address(a).version == 4)
            key = ssh(prefix, host, 'cat /etc/ssh/ssh_host_ed25519_key.pub').strip()
            known = directory / (prefix + '-known-hosts')
            port = int(os.environ[prefix + '_PORT'])
            known.write_text(('[' + address + ']:' + str(port) if port != 22 else address) + ' ' + key + '\n')
            if ssh(prefix, address, 'printf cloudlab-access-ok', str(known)) != 'cloudlab-access-ok':
                raise RuntimeError('Allowed-client host command did not complete')
            targets.append((address, port))
        print('Allowed workstation tailnet SSH to both hosts: passed', flush=True)
        binaries(directory)
        api = API('tailscale-test-enrollment')
        key, _ = api.request('POST', 'tailnet/-/keys', {'capabilities': {'devices': {'create': {
            'reusable': False, 'ephemeral': True, 'preauthorized': True, 'tags': [TEST_TAG]}}}, 'expirySeconds': 300})
        key_path = directory / 'auth-key'
        key_path.write_text(key['key'])
        key_path.chmod(0o600)
        control_socket = str(directory / 'tailscale.sock')
        cli = [str(directory / 'tailscale'), '--socket=' + control_socket]
        with (directory / 'private.log').open('w') as log:
            process = subprocess.Popen([str(directory / 'tailscaled'), '--tun=userspace-networking',
                '--state=mem:', '--socket=' + control_socket],
                stdout=log, stderr=log)
            try:
                for _ in range(100):
                    if Path(control_socket).exists():
                        break
                    time.sleep(0.1)
                result = subprocess.run(cli + ['up', '--auth-key=file:' + str(key_path),
                    '--hostname=cloudlab-denial-fixture', '--accept-dns=false', '--accept-routes=false',
                    '--timeout=60s'], capture_output=True, timeout=75)
                key_path.unlink()
                if result.returncode:
                    raise RuntimeError('Denied fixture enrollment failed; denial is not proven')
                state = json.loads(subprocess.check_output(cli + ['status', '--json'], stderr=subprocess.DEVNULL))
                if state['BackendState'] != 'Running' or state['Self'].get('Tags') != [TEST_TAG]:
                    raise RuntimeError('Denied fixture has unexpected identity')
                peers = {ip for peer in state.get('Peer', {}).values() for ip in peer.get('TailscaleIPs', [])}
                for address, destination_port in targets:
                    if tailnet_connect(control_socket, address, destination_port, peers):
                        raise RuntimeError('Denied fixture reached a host SSH port')
                print('Separate denied identity has no authorized route to either host; system fallback refused: passed', flush=True)
            finally:
                try:
                    subprocess.run(cli + ['logout'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == '__main__':
    try:
        verify()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Access fixture failed: ' + type(error).__name__) from None
