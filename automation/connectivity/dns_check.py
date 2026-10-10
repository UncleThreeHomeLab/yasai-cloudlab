"""Run the exact pinned DNS binary in an isolated runner with both private views."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.connectivity.dns import configuration
from automation.connectivity.dns_wire import absent_answer, private_answer, query


def check():
    pin = json.loads((ROOT / 'platform/connectivity/private-dns/artifact.lock.json').read_text())
    data = urllib.request.urlopen(pin['url'], timeout=120).read()
    if hashlib.sha256(data).hexdigest() != pin['sha256']:
        raise RuntimeError('Independent DNS artifact checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='cloudlab-dns-check-') as folder:
        directory = Path(folder)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            binary = directory / 'coredns'
            binary.write_bytes(archive.extractfile('coredns').read())
            binary.chmod(0o700)
        inputs = dict(zone='internal.example.invalid', identity_host='login.example.invalid', names=['app'], tailnet_address='100.64.0.1',
                      host_address='10.44.0.1', cluster_gateway='10.43.0.10', tailnet_gateway='100.64.0.5',
                      nameservers=['100.64.0.1', '100.64.0.2'], upstreams=['1.1.1.1'])
        for name, content in configuration(inputs).items():
            if name == 'Corefile':
                content = content.replace('bind 100.64.0.1', 'bind 127.0.0.2').replace('bind 127.0.0.1 10.44.0.1', 'bind 127.0.0.1 127.0.0.3')
                content = content.replace('allow net 100.64.0.0/10', 'allow net 127.0.0.2/32')
            (directory / name).write_text(content)
        process = subprocess.Popen([str(binary), '-conf', 'Corefile'], cwd=directory,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for attempt in range(15):
                if process.poll() is not None:
                    raise RuntimeError('Independent DNS candidate failed to start')
                try:
                    private_answer('127.0.0.1', 'app.internal.example.invalid', '10.43.0.10')
                    break
                except (OSError, RuntimeError):
                    if attempt == 14:
                        raise
                    time.sleep(0.2)
            for tcp in (False, True):
                private_answer('127.0.0.1', 'app.internal.example.invalid', '10.43.0.10', tcp=tcp)
                private_answer('127.0.0.2', 'app.internal.example.invalid', '100.64.0.5', source='127.0.0.2', tcp=tcp)
                private_answer('127.0.0.1', 'login.example.invalid', '10.43.0.10', tcp=tcp)
                private_answer('127.0.0.2', 'login.example.invalid', '100.64.0.5', source='127.0.0.2', tcp=tcp)
                if query('127.0.0.2', 'missing.login.example.invalid', source='127.0.0.2', tcp=tcp)['addresses']:
                    raise RuntimeError('Unknown issuer subdomain resolved through the private view')
                if query('127.0.0.2', 'login.example.invalid', source='127.0.0.1', tcp=tcp)['rcode'] != 5:
                    raise RuntimeError('Canonical issuer DNS bypassed its source restriction')
                for destination, source in [('127.0.0.1', '127.0.0.1'), ('127.0.0.2', '127.0.0.2')]:
                    absent_answer(destination, 'missing.internal.example.invalid', source=source, tcp=tcp)
                if query('127.0.0.2', 'github.com', source='127.0.0.2', tcp=tcp)['rcode'] != 5:
                    raise RuntimeError('Tailnet listener became a public recursive resolver')
                if query('127.0.0.2', 'app.internal.example.invalid', source='127.0.0.1', tcp=tcp)['rcode'] != 5:
                    raise RuntimeError('DNS source restriction failed')
        finally:
            process.terminate()
            process.wait(timeout=10)
    return {'artifact_verified': True, 'private_views_udp_tcp': True, 'canonical_private_issuer_udp_tcp': True, 'unknown_names_fail_closed': True,
            'tailnet_recursion_denied': True, 'source_restriction': True, 'live_host_dns_tested': False}


if __name__ == '__main__':
    print(json.dumps(check()))
