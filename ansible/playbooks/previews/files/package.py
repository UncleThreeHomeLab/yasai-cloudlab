"""Keep deployed Python and trust assets identical to their authoritative owners."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
FILES = ('contract.py', 'github.py', 'kube.py', 'lifecycle.py', 'resources.py', 'controller.py',
         'images.lock.json', 'sigstore-fulcio.crt')


def artifacts():
    source = Path(__file__).parent
    expected = {name: (source / name).read_bytes().replace(b'\r\n', b'\n') for name in FILES}
    if expected['images.lock.json'] != (ROOT / 'platform/connectivity/istio/images.lock.json').read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Preview proxy images differ from the Istio owner')
    if expected['sigstore-fulcio.crt'] != (ROOT / 'platform/delivery/services/sigstore-fulcio.crt').read_bytes().replace(b'\r\n', b'\n'):
        raise ValueError('Preview verifier roots differ from the artifact owner')
    return expected


def build():
    target = ROOT / 'platform/delivery/previews/runtime'
    for name, raw in artifacts().items():
        target.joinpath(name).write_bytes(raw)
    (ROOT / 'platform/identity/keycloak/runtime/preview_contract.py').write_bytes(artifacts()['contract.py'])
    (ROOT / 'platform/identity/keycloak/runtime/preview_clients.py').write_bytes(
        (ROOT / 'ansible/playbooks/keycloak/files/preview_clients.py').read_bytes().replace(b'\r\n', b'\n'))


def check():
    for name, raw in artifacts().items():
        if (ROOT / 'platform/delivery/previews/runtime' / name).read_bytes() != raw:
            raise ValueError('Packaged preview runtime differs from its owning source')


if __name__ == '__main__':
    import sys
    build() if sys.argv[1:] == ['build'] else check()
