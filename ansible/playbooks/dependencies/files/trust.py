"""Refresh reviewed public certificate inputs without adding trust authority."""
import base64
import json
from pathlib import Path
import re

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature

from .images import packages
from .inputs import baseline
from .security import digest, download, owned_path
from .tools import write_json

LOCK = 'platform/delivery/services/sigstore-fulcio.lock.json'
BUNDLE = 'platform/delivery/services/sigstore-fulcio.crt'
SOURCE = 'https://tuf-repo-cdn.sigstore.dev/targets/trusted_root.json'


def certificates(raw):
    pattern = rb'-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----'
    if b'\r' in raw or re.sub(pattern, b'', raw).strip():
        raise ValueError('Public roots must contain only canonical PEM certificates')
    values = x509.load_pem_x509_certificates(raw)
    if not values or len(values) > 16:
        raise ValueError('Public certificate bundle count is invalid')
    return values


def validate(old, new):
    before, after = certificates(old), certificates(new)
    if old == new:
        return
    key = lambda cert: (cert.subject, cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo))
    previous = {key(cert): cert for cert in before}
    if len(previous) != len(before) or len(after) != len(before) or set(map(key, after)) != set(previous):
        raise ValueError('New certificate authorities or keys require separate owner review')
    for cert in after:
        original = previous[key(cert)]
        if cert.issuer != original.issuer or list(cert.extensions) != list(original.extensions):
            raise ValueError('Certificate maintenance cannot change authority constraints')
        issuers = [issuer for issuer in before if issuer.subject == cert.issuer]
        valid = False
        for issuer in issuers:
            try:
                cert.verify_directly_issued_by(issuer)
                valid = True
                break
            except (ValueError, TypeError, InvalidSignature):
                continue
        if not valid:
            raise ValueError('Renewed public certificate is not signed by its existing authority')


def update(root, request, *, fetch=download):
    if (set(request) != {'trustedRootSha256', 'bundleSha256'} or
            any(not re.fullmatch(r'[a-f0-9]{64}', value) for value in request.values())):
        raise ValueError('Public root maintenance requires both exact reviewed input checksums')
    bundle = owned_path(root, BUNDLE).read_bytes()
    if digest(bundle) != request['bundleSha256']:
        raise ValueError('Reviewed public bundle checksum differs')
    validate(baseline(root, BUNDLE), bundle)
    raw = fetch(SOURCE, prefix='https://tuf-repo-cdn.sigstore.dev/targets/', sha256=request['trustedRootSha256'])
    published(raw, bundle)
    lock = json.loads(owned_path(root, LOCK).read_bytes())
    if lock['source'] != SOURCE:
        raise ValueError('Public root source differs from its fixed owner')
    lock.update(trusted_root_sha256=request['trustedRootSha256'], sha256=digest(bundle))
    write_json(owned_path(root, LOCK), lock)
    owned_path(root, 'ansible/playbooks/previews/files/sigstore-fulcio.crt').write_bytes(bundle)
    packages(root, 'python')
    return {'owner': 'sigstore-roots', 'status': 'pending-verification', 'authorityExpansion': False,
            'sourceValidation': 'reviewed public input checksum and existing CA signatures'}


def published(raw, bundle):
    published = set()

    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get('rawBytes'), str):
                published.add(base64.b64decode(value['rawBytes'], validate=True))
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(json.loads(raw))
    if any(cert.public_bytes(Encoding.DER) not in published for cert in certificates(bundle)):
        raise ValueError('Reviewed bundle differs from the checksum-verified official public root input')


def verify(root, *, fetch=download):
    bundle = owned_path(root, BUNDLE).read_bytes()
    validate(baseline(root, BUNDLE), bundle)
    lock = json.loads(owned_path(root, LOCK).read_bytes())
    if lock['source'] != SOURCE or digest(bundle) != lock['sha256']:
        raise ValueError('Public root source differs from its fixed owner')
    raw = fetch(SOURCE, prefix='https://tuf-repo-cdn.sigstore.dev/targets/', sha256=lock['trusted_root_sha256'])
    published(raw, bundle)
