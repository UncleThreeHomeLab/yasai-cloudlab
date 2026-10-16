"""Synthetic protected recovery metadata; no service credentials."""
import json
from automation.harbor.recovery import CLAIMS, SECRETS, ARTIFACTS


def manifest():
    generation = 'harbor-' + 'a' * 24
    return {'format': 1, 'generation': generation, 'captured': True, 'captured_at': 1790805600,
        'capture_seconds': 1, 'consistency': 'all-writers-stopped',
        'operation': 'monthly', 'installation': {'revision': 'f' * 40,
            'chart_sha256': json.loads((ARTIFACTS / 'server/artifact.lock.json').read_text())['sha256'],
            'images': sorted(json.loads((ARTIFACTS / 'images.lock.json').read_text()).values())},
        'secrets': {name: 'b' * 64 for name in SECRETS},
        'inventory': {'database_sha256': 'c' * 64, 'blobs_sha256': 'd' * 64,
                      'artifact_digests': ['sha256:' + 'e' * 64]},
        'volumes': {component: {'claim': claim, 'claim_uid': f'{number:08d}-1111-2222-3333-444444444444',
            'volume_uid': f'{number:08d}-5555-6666-7777-888888888888',
            'volume': f'pvc-{number:08d}-1111-2222-3333-444444444444', 'size': '1Gi', 'actual_bytes': 1024,
            'snapshot': generation + '-' + component} for number, (component, claim) in enumerate(CLAIMS.items())}}
