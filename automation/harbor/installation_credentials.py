"""Generate installation secrets locally and preserve every existing vault value."""
from datetime import datetime, timedelta, timezone
import base64
import fcntl
from functools import lru_cache
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import yaml

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dotenv import dotenv_values

from automation.credentials.provision import ensure_items


def signing_material():
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'cloudlab-harbor-token')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1825))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    return {'tls_key': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()).decode(),
            'tls_crt': certificate.public_bytes(serialization.Encoding.PEM).decode()}


def htpasswd(password):
    # Reuse the pinned Helm/Sprig bcrypt implementation; password travels only through stdin.
    with tempfile.TemporaryDirectory() as temporary:
        chart = Path(temporary)
        (chart / 'templates').mkdir()
        (chart / 'Chart.yaml').write_text('apiVersion: v2\nname: credentials\nversion: 0.1.0\n')
        (chart / 'templates/value.yaml').write_text('apiVersion: v1\nkind: ConfigMap\nmetadata: {name: credentials}\ndata:\n  hash: {{ htpasswd "harbor_registry_user" .Values.password | toJson }}\n')
        result = subprocess.run(['helm', 'template', 'credentials', str(chart), '-f', '-'],
            input=json.dumps({'password': password}), capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise RuntimeError('Registry bcrypt generation failed; values withheld')
        documents = [document for document in yaml.safe_load_all(result.stdout) if document]
        if len(documents) != 1:
            raise RuntimeError('Registry bcrypt output invalid; values withheld')
        value = documents[0]['data']['hash']
        if not value.startswith('harbor_registry_user:$2'):
            raise RuntimeError('Registry requires bcrypt credentials')
        return value


def definitions():
    password = lru_cache(maxsize=1)(lambda: secrets.token_urlsafe(48))
    signing = lru_cache(maxsize=1)(signing_material)
    runtime = {name: ('CONCEALED', lambda size=size: secrets.token_urlsafe(size)) for name, size in (
        ('secretKey', 12), ('secret', 12), ('CSRF_KEY', 24), ('JOBSERVICE_SECRET', 12), ('REGISTRY_HTTP_SECRET', 24))}
    runtime.update(REGISTRY_PASSWD=('CONCEALED', password),
                   REGISTRY_HTPASSWD=('CONCEALED', lambda: htpasswd(password())))
    return {
        'harbor-emergency': {'username': ('STRING', lambda: 'admin'),
                             'password': ('CONCEALED', lambda: secrets.token_urlsafe(48))},
        'harbor-database': {'password': ('CONCEALED', lambda: secrets.token_urlsafe(48))},
        'harbor-runtime': runtime,
        'harbor-browser-key': {'cookie_secret': ('CONCEALED', lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())},
        'harbor-token-signing': {name: (kind, lambda name=name: signing()[name])
                                 for name, kind in (('tls_key', 'CONCEALED'), ('tls_crt', 'STRING'))},
    }


def provision():
    values = dotenv_values('/workspace/.env', interpolate=False)
    os.umask(0o077)
    with Path('/state/harbor-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), definitions())


if __name__ == '__main__':
    try:
        print(json.dumps(provision(), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor installation credentials incomplete; existing values preserved') from None
