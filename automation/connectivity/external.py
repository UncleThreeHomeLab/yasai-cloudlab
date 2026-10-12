"""Verify the accepted native owner after existing access workloads converge."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from automation.connectivity.preflight import audit, ssh
from automation.connectivity.checkpoint import transaction


READY = '''import json, subprocess
def get(kind,name,namespace):
 r=subprocess.run(['/usr/local/bin/k3s','kubectl','get',kind,name,'-n',namespace,'-o','json'],capture_output=True,text=True)
 if r.returncode: raise RuntimeError('Access resources unavailable')
 return json.loads(r.stdout)
for name,namespace in [('operator','tailscale'),('cloudflared','cloudlab-connectors')]:
 d=get('deployment',name,namespace)
 if d.get('status',{}).get('observedGeneration')!=d['metadata']['generation'] or d.get('status',{}).get('availableReplicas',0)!=d['spec']['replicas']: raise RuntimeError('Access deployment not ready')
for name in ('cloudlab-ingress','cloudlab-api'):
 p=get('proxygroup',name,'tailscale')
 if not any(c.get('type')=='ProxyGroupReady' and c.get('status')=='True' and c.get('observedGeneration')==p['metadata']['generation'] for c in p.get('status',{}).get('conditions',[])): raise RuntimeError('Access proxy group not ready')
print('ready')
'''


def run():
    import fcntl
    os.umask(0o077)
    result = audit()
    if not result['ready']:
        print(json.dumps(result, sort_keys=True))
        raise RuntimeError('External reconciliation blocked by access prerequisites')
    if ssh('VM', os.environ['VM_HOST'], 'python3 -', input=READY, timeout=120).strip() != 'ready':
        raise RuntimeError('Access workloads must converge before external publication')
    state_dir = Path('/state/connectivity')
    state_dir.mkdir(mode=0o700, exist_ok=True)
    with (state_dir / 'external.lock').open('a') as lock, transaction() as receipts:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = receipts.load('external') or {}
        accepted(state)
        from automation.infra.command import main as infra
        if infra(['verify', 'cloudflare']) != 0:
            raise RuntimeError('Owned Cloudflare infrastructure verification failed; review an independent plan')
    print(json.dumps({'changed': False, 'configured': True, 'infra_owner': 'cloudflare'}))


def accepted(state):
    owner = state.get('infra_owner')
    if (not isinstance(owner, dict) or owner.get('phase') != 'accepted' or
            owner.get('binding') != state.get('binding') or not isinstance(owner.get('objects'), dict) or
            not owner['objects'] or owner['objects'] != {
                key: state.get('objects', {}).get(key) for key in owner['objects']}):
        raise RuntimeError('Cloudflare ownership maintenance incomplete; neither writer may mutate')


if __name__ == '__main__':
    try:
        run()
    except (RuntimeError, ValueError, KeyError, OSError):
        raise SystemExit('External access reconciliation failed; retain state and credentials for recovery.') from None
