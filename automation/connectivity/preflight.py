"""Read-only, sanitized milestone 03 prerequisite and dependency audit."""
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'automation/tailscale'))

from automation.credentials.vault import fields
from automation.connectivity.cloudflare import API
from automation.connectivity.contract import host_rules, policy, private_names, tunnel_identity
from automation.connectivity.provider_http import open_request
from verify_access import ssh


HOST_AUDIT = '''import json, pathlib, subprocess
def kubectl(*args):
 r=subprocess.run(['/usr/local/bin/k3s','kubectl','--request-timeout=30s',*args,'-o','json'],capture_output=True,text=True)
 if r.returncode: raise RuntimeError('Cluster prerequisite read failed')
 return json.loads(r.stdout)
def ready(obj, name):
 return any(c.get('type')==name and c.get('status')=='True' for c in obj.get('status',{}).get('conditions',[]))
def receipt(path):
 p=pathlib.Path(path)
 if not p.is_file(): return 'missing'
 return json.loads(p.read_text()).get('phase','unknown')
apps=kubectl('get','applications.argoproj.io','-n','argocd')['items']
certs=kubectl('get','certificates.cert-manager.io','-A')['items']
gateways=kubectl('get','gateways.gateway.networking.k8s.io','-A')['items']
services=kubectl('get','services','-A')['items']
ingresses=kubectl('get','ingresses.networking.k8s.io','-A')['items']
routes=kubectl('get','httproutes.gateway.networking.k8s.io','-A')['items']
crds=kubectl('get','customresourcedefinitions')['items']
helm=kubectl('get','helmcharts.helm.cattle.io','-n','kube-system')['items']
deploy=kubectl('get','deployments','-A')['items']
tail=subprocess.run(['tailscale','status','--json'],capture_output=True,text=True)
status=json.loads(tail.stdout) if tail.returncode==0 else {}
live_apps={a['metadata']['name']:a for a in apps}
required=['cloudlab-public-root','cloudlab-external-secrets','cloudlab-longhorn','cloudlab-longhorn-backup','cloudlab-cert-manager','cloudlab-certificates','cloudlab-istio-base','cloudlab-istio-istiod','cloudlab-istio-cni','cloudlab-istio-ztunnel','cloudlab-gateways']
app_health=all(n in live_apps and live_apps[n].get('status',{}).get('sync',{}).get('status')=='Synced' and live_apps[n].get('status',{}).get('health',{}).get('status')=='Healthy' and not live_apps[n].get('operation') for n in required)
cert_health=all(any(c['metadata']['namespace']=='cloudlab-gateway-'+e and c['metadata']['name']=='cloudlab-gateway' and ready(c,'Ready') for c in certs) for e in ('public','private'))
gateway_health=all(any(g['metadata']['namespace']=='cloudlab-gateway-'+e and g['metadata']['name']=='cloudlab' and ready(g,'Programmed') for g in gateways) for e in ('public','private'))
internal=all(any(s['metadata']['namespace']=='cloudlab-gateway-'+e and s['metadata']['name']=='cloudlab-istio' and s['spec'].get('type','ClusterIP')=='ClusterIP' for s in services) for e in ('public','private'))
gateway_crds=[c for c in crds if c['spec']['group']=='gateway.networking.k8s.io']
traefik_crd_dependencies=sum(len(kubectl('get',c['spec']['names']['plural']+'.'+c['spec']['group'],'-A')['items']) for c in crds if c['spec']['group'] in ('traefik.io','traefik.containo.us'))
traefik_ingresses=sum(1 for i in ingresses if i['spec'].get('ingressClassName','traefik')=='traefik')
traefik_routes=sum(1 for i in routes if any(p.get('name')!='cloudlab' for p in i['spec'].get('parentRefs',[])))
legacy_services=sum(1 for s in services if s['spec'].get('type')=='LoadBalancer' and s['metadata']['name']!='traefik' and s['spec'].get('loadBalancerClass')!='tailscale')
print(json.dumps({
 'gitops_ready':app_health,'certificates_ready':cert_health,'gateways_ready':gateway_health,
 'internal_gateways':internal,'mesh_receipt':receipt('/var/lib/cloudlab/mesh/ownership.json'),
 'eso_receipt':receipt('/var/lib/cloudlab/external-secrets/ownership.json'),
 'longhorn_receipt':receipt('/var/lib/cloudlab/longhorn/ownership.json'),
 'backup_receipt':receipt('/var/lib/cloudlab/longhorn/backup-ownership.json'),
 'gateway_api_crds':len(gateway_crds),
 'gateway_api_traefik_owned':all(c['metadata'].get('annotations',{}).get('meta.helm.sh/release-name')=='traefik-crd' for c in gateway_crds),
 'gateway_api_cutover_owned':all(c['metadata'].get('annotations',{}).get('cloudlab.io/owner')=='cloudlab-gateway-api' for c in gateway_crds),
 'traefik_chart_present':any(h['metadata']['name']=='traefik' for h in helm),
 'traefik_ingress_dependencies':traefik_ingresses,'traefik_crd_dependencies':traefik_crd_dependencies,
 'other_gateway_route_dependencies':traefik_routes,'other_servicelb_consumers':legacy_services,
 'host_tailscale_ready':status.get('BackendState')=='Running' and status.get('Self',{}).get('Tags')==['tag:cloudlab-host']
}))
'''


def oauth(values):
    request = urllib.request.Request('https://api.tailscale.com/api/v2/oauth/token',
        data=urllib.parse.urlencode({'client_id': values['CLIENT_ID'], 'client_secret': values['CLIENT_SECRET'],
                                    'grant_type': 'client_credentials'}).encode())
    try:
        with open_request(request, timeout=30) as response:
            document = json.load(response)
        return document['access_token'], set(document.get('scope', '').split())
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError):
        raise RuntimeError('Tailscale OAuth authentication failed') from None


def tailnet_read(token, path):
    request = urllib.request.Request('https://api.tailscale.com/api/v2/tailnet/-/' + path,
                                    headers={'Authorization': 'Bearer ' + token})
    try:
        with open_request(request, timeout=30) as response:
            return json.load(response)
    except (urllib.error.URLError, TimeoutError, ValueError):
        raise RuntimeError('Tailscale prerequisite read unavailable') from None


def audit():
    results, blockers, credentials = {}, [], {}
    for item, names in policy()['items'].items():
        try:
            credentials[item] = fields(item, names)
            results[item] = True
        except (RuntimeError, ValueError):
            results[item] = False
            blockers.append('Required CloudLab item unavailable or incomplete: ' + item)
    try:
        results['cluster'] = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -', input=HOST_AUDIT, timeout=180))
        cluster = results['cluster']
        if not all(cluster.get(k) for k in ('gitops_ready', 'certificates_ready', 'gateways_ready', 'internal_gateways', 'host_tailscale_ready')):
            blockers.append('Milestone 02 live health or independent host access prerequisite failed')
        if any(cluster.get(k) != 'accepted' for k in ('eso_receipt', 'mesh_receipt', 'longhorn_receipt', 'backup_receipt')):
            blockers.append('Milestone 02 mesh or storage ownership handoff is not accepted')
        if cluster.get('gateway_api_crds') != 10 or not (cluster.get('gateway_api_traefik_owned') or cluster.get('gateway_api_cutover_owned')):
            blockers.append('Gateway API baseline ownership requires review before cutover')
        if any(cluster.get(k) for k in ('traefik_ingress_dependencies', 'traefik_crd_dependencies', 'other_gateway_route_dependencies', 'other_servicelb_consumers')):
            blockers.append('Legacy ingress dependency audit found consumers; cutover prohibited')
    except (RuntimeError, ValueError, KeyError, TimeoutError):
        results['cluster'] = {'audit_passed': False}
        blockers.append('Milestone 02 live prerequisite read failed; private diagnostics withheld')
    management, runtime, dns = (credentials.get(name) for name in
        ('cloudflare-management', 'cloudflare-tunnel', 'cloudlab-dns01'))
    if management and runtime and dns:
        try:
            if management['ZONE_ID'] != dns['ZONE_ID'] or management['API_TOKEN'] == dns['API_TOKEN']:
                raise ValueError('Cloudflare DNS and management credentials must be separate and select the same zone')
            tunnel_identity(runtime['TUNNEL_TOKEN'], management['ACCOUNT_ID'], runtime['TUNNEL_ID'])
            admin, zone_api = API(management['API_TOKEN']), API(dns['API_TOKEN'])
            zone = zone_api.request('GET', 'zones/' + dns['ZONE_ID'])
            if zone.get('account', {}).get('id') != management['ACCOUNT_ID']:
                raise ValueError('Cloudflare zone and account mismatch')
            tunnel = admin.request('GET', 'accounts/' + management['ACCOUNT_ID'] + '/cfd_tunnel/' + runtime['TUNNEL_ID'])
            if tunnel.get('deleted_at') or tunnel.get('config_src') != 'cloudflare':
                raise ValueError('Saved tunnel must exist and use API-managed configuration')
            results['cloudflare_tunnel_identity'] = True
            prefix = 'accounts/' + management['ACCOUNT_ID'] + '/access/'
            for key in ('apps', 'service_tokens', 'identity_providers', 'organizations'):
                try:
                    result = admin.request('GET', prefix + key)
                    if key == 'organizations':
                        results['access_organization_available'] = bool(result.get('auth_domain'))
                        if not results['access_organization_available']:
                            blockers.append('Cloudflare Zero Trust organization must be pre-provisioned on the free plan')
                    else:
                        results['access_' + key] = len(result)
                        if key == 'identity_providers' and not result:
                            blockers.append('Cloudflare Access human identity provider is not provisioned')
                except RuntimeError:
                    results['access_' + key + '_readable'] = False
                    blockers.append('Cloudflare Access prerequisite read unavailable: ' + key)
            try:
                rules = host_rules(json.loads(os.environ.get('CLOUDFLARE_ACCESS_HOSTS') or '[]'), zone['name'])
                results['public_hostname_classifications'] = len(rules)
                private_names(json.loads(os.environ.get('PRIVATE_ACCESS_HOSTS') or '[]'))
            except ValueError:
                blockers.append('Declare public Access classifications and private hostname labels in .env')
        except (RuntimeError, ValueError, KeyError) as error:
            # Only messages from this module and the sanitized API class can escape.
            blockers.append(str(error) if isinstance(error, (RuntimeError, ValueError)) else 'Cloudflare prerequisite response incomplete')
    for item, expected in [('tailscale-operator', policy()['operatorScopes']), ('tailscale-policy', policy()['policyScopes'])]:
        if item not in credentials:
            continue
        try:
            token, scopes = oauth(credentials[item])
            missing = [scope for scope in expected if scope not in scopes and scope + ':write' not in scopes]
            results[item + '_required_scopes'] = not missing
            if missing:
                blockers.append(item + ' lacks required write scopes: ' + ', '.join(missing))
            if item == 'tailscale-policy':
                tailnet_read(token, 'dns/split-dns')
                results['tailnet_split_dns_readable'] = True
        except RuntimeError as error:
            blockers.append(str(error))
    if os.environ.get('ACCESS_FREE_TIER_CONFIRMED') != '1':
        blockers.append('Confirm existing Tailscale Personal and Cloudflare Zero Trust Free eligibility in ACCESS_FREE_TIER_CONFIRMED')
    if not os.environ.get('CLOUDFLARE_HUMAN_EMAIL') or not os.environ.get('CLOUDFLARE_IDP_ID'):
        blockers.append('Human Access identity and approved provider must be declared explicitly')
    return {'read_only': True, 'ready': not blockers, 'checks': results, 'blockers': blockers,
            'cutover_authorized': False}


if __name__ == '__main__':
    result = audit()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result['ready'] else 2)
