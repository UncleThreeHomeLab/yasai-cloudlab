"""Vendor official candidate artifacts; installation needs separate compatibility proof."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'platform/identity/keycloak'
VERSION = '26.6.4'
SERVER_VERSION = '26.8.0'
IMAGES = {
    'server': 'quay.io/keycloak/keycloak:26.8.0@sha256:b0f60d489d51c5d113390bdf5461d4c06e6051be026c05549f2e1e10ec352bcc',
    'operator': 'quay.io/keycloak/keycloak-operator:26.6.4@sha256:831827a0a267805d0e5bef00e402d99f728ce7fc4caa62d486a9114912412434',
    'config_cli': 'quay.io/adorsys/keycloak-config-cli:6.5.1-26.5.5@sha256:0955d98c8a341898b7aa177477edf8a1e90569ae50bbe7598141c1270b773274',
    'python': 'python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed',
}


def main():
    sources = {}
    for name in ('kubernetes.yml', 'keycloaks.k8s.keycloak.org-v1.yml',
                 'keycloakrealmimports.k8s.keycloak.org-v1.yml'):
        url = f'https://raw.githubusercontent.com/keycloak/keycloak-k8s-resources/{VERSION}/kubernetes/{name}'
        data = urllib.request.urlopen(url, timeout=60).read()
        target = BASE / 'upstream' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sources[name] = {'url': url, 'sha256': hashlib.sha256(data).hexdigest()}
    (BASE / 'artifact.lock.json').write_text(json.dumps({
        'operator_version': VERSION, 'server_version': SERVER_VERSION,
        'config_cli_version': '6.5.1', 'config_cli_build_server': '26.5.5',
        'compatibility': '26.6.4 Operator with patched 26.8.0 server; delegated version exception; isolated CR reconciliation proof pending',
        'operator_install_verified': False,
        'sources': sources, 'images': IMAGES,
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
