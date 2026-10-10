"""Compose entry point for bounded external reconciliation after GitOps readiness."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from automation.connectivity.cloudflare import API
from automation.connectivity.preflight import audit, ssh
from automation.connectivity.reconcile import Reconciler
from automation.credentials.vault import fields
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
    admin_values = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID', 'ZONE_ID'))
    dns_values = fields('cloudlab-dns01', ('API_TOKEN', 'ZONE_ID'))
    runtime = fields('cloudflare-tunnel', ('TUNNEL_ID',))
    machine = fields('cloudflare-access-machine', ('SERVICE_TOKEN_ID',))
    admin, dns = API(admin_values['API_TOKEN']), API(dns_values['API_TOKEN'])
    zone = dns.request('GET', 'zones/' + dns_values['ZONE_ID'])['name']
    organization = admin.request('GET', 'accounts/' + admin_values['ACCOUNT_ID'] + '/access/organizations')
    domain = organization['auth_domain']
    if not domain.endswith('.cloudflareaccess.com'):
        raise RuntimeError('Unsupported Access organization domain')
    state_dir = Path('/state/connectivity')
    state_dir.mkdir(mode=0o700, exist_ok=True)
    path = state_dir / 'external.json'
    with (state_dir / 'external.lock').open('a') as lock, transaction() as receipts:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = receipts.load('external') or {}
        from automation.identity.access_cutover import approved_email, selection
        selected_provider, identity_group = selection(state, os.environ['CLOUDFLARE_IDP_ID'])

        def save(value):
            receipts.save('external', value)
            temporary = path.with_suffix('.tmp')
            with temporary.open('w') as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
            descriptor = os.open(state_dir, os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

        result = Reconciler(admin, dns, state, save).run(
            account=admin_values['ACCOUNT_ID'], zone_id=dns_values['ZONE_ID'], zone=zone,
            tunnel=runtime['TUNNEL_ID'], rules=json.loads(os.environ['CLOUDFLARE_ACCESS_HOSTS']),
            team=domain.removesuffix('.cloudflareaccess.com'), human_email=approved_email(state, os.environ['CLOUDFLARE_HUMAN_EMAIL']),
            identity_provider=selected_provider, identity_group=identity_group, service_token_id=machine['SERVICE_TOKEN_ID'],
            add_identity_protocol=os.environ.get('LAB_IDENTITY_ENABLED') == '1')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        run()
    except (RuntimeError, ValueError, KeyError, OSError):
        raise SystemExit('External access reconciliation failed; retain state and credentials for recovery.') from None
