"""Prove DNS-01 renewal, Secret delivery and retained certificate identities."""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid

from configuration import BASE, certificate
from kube import application_ready, get, kube, ready, wait


def fingerprint(name, namespace, trusted=False):
    obj = get('certificate.cert-manager.io', name, namespace)
    secret = get('secret', obj['spec']['secretName'], namespace)
    pem = base64.b64decode(secret['data']['tls.crt'], validate=True)
    # OpenSSL reads certificate bytes only; private keys never leave Kubernetes.
    result = subprocess.run(['openssl', 'x509', '-noout', '-checkend', '86400'],
                            input=pem, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Issued certificate is invalid or expires within one day')
    for pattern in obj['spec']['dnsNames']:
        hostname = pattern.replace('*.', 'verification.', 1)
        result = subprocess.run(['openssl', 'x509', '-noout', '-checkhost', hostname],
                                input=pem, capture_output=True, timeout=30)
        if result.returncode or b'does match certificate' not in result.stdout:
            raise RuntimeError('Issued certificate does not match its declared DNS names')
    if trusted:
        with tempfile.TemporaryDirectory(prefix='cloudlab-public-certificate-') as directory:
            # Only the public chain is written; the private key stays in the Secret.
            chain = Path(directory) / 'chain.pem'
            chain.write_bytes(pem)
            result = subprocess.run(['openssl', 'verify', '-CApath', '/etc/ssl/certs',
                                     '-untrusted', str(chain), str(chain)], capture_output=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Production certificate chain is not publicly trusted')
    return {'certificate_uid': obj['metadata']['uid'], 'secret_uid': secret['metadata']['uid'],
            'revision': obj.get('status', {}).get('revision', 0), 'certificate_hash': hashlib.sha256(pem).hexdigest(),
            'private_key_hash': hashlib.sha256(secret['data']['tls.key'].encode()).hexdigest(),
            'renewal_time_present': bool(obj.get('status', {}).get('renewalTime'))}


def delivery(namespace, image, expected):
    name = 'cloudlab-certificate-check-' + uuid.uuid4().hex[:10]
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': name, 'namespace': namespace,
        'labels': {'app.kubernetes.io/managed-by': 'cloudlab-certificate-verify'}},
        'spec': {'restartPolicy': 'Never', 'activeDeadlineSeconds': 300,
            'automountServiceAccountToken': False,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
                                'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'reader', 'image': image, 'command': ['sh', '-c', 'sleep 300'],
                'securityContext': {'allowPrivilegeEscalation': False, 'readOnlyRootFilesystem': True,
                                    'capabilities': {'drop': ['ALL']}},
                'resources': {'requests': {'cpu': '10m', 'memory': '16Mi'},
                              'limits': {'cpu': '100m', 'memory': '64Mi'}},
                'volumeMounts': [{'name': 'tls', 'mountPath': '/tls', 'readOnly': True}]}],
            'volumes': [{'name': 'tls', 'secret': {'secretName': 'cloudlab-gateway-tls',
                                                  'items': [{'key': 'tls.crt', 'path': 'tls.crt'}]}}]}}
    created = False
    try:
        kube('create', '-f', '-', document=pod)
        created = True
        kube('wait', '--for=condition=Ready', 'pod/' + name, '-n', namespace, '--timeout=180s', timeout=210)
        actual = kube('exec', '-n', namespace, name, '--', 'sha256sum', '/tls/tls.crt').split()[0]
        if actual != expected:
            raise RuntimeError('Mounted certificate differs from its generated Secret')
    finally:
        if created:
            kube('delete', 'pod', name, '-n', namespace, '--wait=true', '--timeout=120s')


def verify(payload):
    os.umask(0o077)
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = json.loads((BASE / 'ownership.json').read_text())
        if state['phase'] != 'accepted':
            raise RuntimeError('Accept staging and production issuance before certificate verification')
        for app in ('cloudlab-cert-manager', 'cloudlab-certificates'):
            wait(lambda: application_ready(app, payload['revision']), 'certificate GitOps convergence')
        for kind in ('public', 'private'):
            namespace = 'cloudlab-gateway-' + kind
            if certificate('cloudlab-gateway', namespace) != state['identities'][kind]:
                raise RuntimeError('Gateway certificate identity changed')
            current = fingerprint('cloudlab-gateway', namespace, trusted=True)
            if not current['renewal_time_present']:
                raise RuntimeError('Production certificate has no renewal schedule')
            delivery(namespace, payload['probe_image'], current['certificate_hash'])
        original = fingerprint('cloudlab-staging', 'cert-manager')
        result = subprocess.run(['/usr/local/bin/cloudlab-cmctl', 'renew', 'cloudlab-staging',
                                 '-n', 'cert-manager', '--kubeconfig=/etc/rancher/k3s/k3s.yaml'],
                                capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise RuntimeError('Staging renewal request failed; private diagnostics withheld')
        def renewed():
            obj = get('certificate.cert-manager.io', 'cloudlab-staging', 'cert-manager')
            if not ready(obj) or obj.get('status', {}).get('revision', 0) <= original['revision']:
                return False
            current = fingerprint('cloudlab-staging', 'cert-manager')
            if any(current[key] != original[key] for key in ('certificate_uid', 'secret_uid')):
                raise RuntimeError('Staging renewal replaced a retained object')
            return (current['certificate_hash'] != original['certificate_hash']
                    and current['private_key_hash'] != original['private_key_hash']
                    and current['renewal_time_present'])
        wait(renewed, 'staging renewal and private key rotation')
        # The declared solver is DNS-01; renewal succeeds without any HTTP challenge listener.
        for name in ('cloudlab-acme-staging', 'cloudlab-acme-production'):
            issuer = get('clusterissuer.cert-manager.io', name)
            if not ready(issuer) or any('dns01' not in solver or 'http01' in solver
                                       for solver in issuer['spec']['acme']['solvers']):
                raise RuntimeError('Certificate issuer readiness or DNS-only policy changed')
        wait(lambda: application_ready('cloudlab-certificates', payload['revision']), 'post-renewal convergence')
        return {'staging_issuance_and_renewal': True, 'private_key_rotated': True,
                'certificate_and_secret_uids_preserved': True, 'production_certificates': 2,
                'production_renewal_schedules_present': True, 'production_chains_trusted': True,
                'mounted_secret_delivery': True, 'http_challenges': False}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Certificate verification failed; private diagnostics withheld') from None
