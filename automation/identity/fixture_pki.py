"""Ephemeral localhost TLS trust for the unexposed identity/browser fixture."""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    root = Path('/fixture')
    root.mkdir(exist_ok=True)
    os.chown(root, 1000, 1000)
    root.chmod(0o700)
    if (root / 'tls.key').exists():
        return
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Disposable identity fixture')])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(leaf_name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.DNSName('admin.fixture.test'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False).sign(ca_key, hashes.SHA256()))
    for filename, data, mode in (
            ('ca.crt', ca.public_bytes(serialization.Encoding.PEM), 0o644),
            ('tls.crt', cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM), 0o644),
            ('tls.key', key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()), 0o400)):
        target = root / filename
        target.write_bytes(data)
        os.chown(target, 1000, 1000)
        target.chmod(mode)
    print('Disposable localhost TLS trust generated; no production credentials')


if __name__ == '__main__':
    main()
