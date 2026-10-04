"""Preserve reviewed backup semantics without retaining the retired templates."""
import hashlib
import json
from backup_chart import ROOT, render


def verify():
    lock = json.loads((ROOT / 'render.lock.json').read_text())
    values = lock['fixture']
    actual = render(values)[0]
    canonical = json.dumps(sorted(json.dumps(obj, sort_keys=True) for obj in actual), separators=(',', ':'))
    if hashlib.sha256(canonical.encode()).hexdigest() != lock['semantic_sha256']:
        raise ValueError('Backup chart differs from reviewed declaration semantics')
    if render({'store': values['store']}, True)[0] != [next(obj for obj in actual if obj['kind'] == 'ExternalSecret')]:
        raise ValueError('Credential-only seed differs from the final Argo declaration')
    print(json.dumps({'backup_chart_parity': True, 'objects': len(actual), 'real_private_inputs_used': False}))


if __name__ == '__main__':
    verify()
