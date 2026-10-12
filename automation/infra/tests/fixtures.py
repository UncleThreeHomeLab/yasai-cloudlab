"""Synthetic existing ownership shared by infrastructure maintenance checks."""
import copy
import json
from pathlib import Path


def cloudflare_owner():
    fixture = json.loads(Path('/workspace/infra/cloudflare/fixtures.json').read_text())
    app = copy.deepcopy(fixture['applications']['fixture'])
    app.update(id='existing-app', aud='existing-audience', type='self_hosted')
    app['policies'] = [dict(policy, reusable=False) for policy in app['policies'].values()]
    snapshot = {'applications': {app['domain']: app}, 'tunnel': {'id': fixture['tunnel_id']},
                'configuration': {'config': {'ingress': [
                    {'hostname': app['domain'], 'service': 'https://origin.example.invalid:443'},
                    {'service': 'http_status:404'}]}},
                'dns': {app['domain']: {'id': 'existing-dns', 'name': app['domain'], 'type': 'CNAME',
                    'content': fixture['tunnel_id'] + '.cfargotunnel.com', 'proxied': True, 'ttl': 1,
                    'comment': 'existing-owner'}},
                'organization': {'auth_domain': 'synthetic.cloudflareaccess.com'},
                'owner': {'binding': 'synthetic-binding', 'phase': 'configured',
                          'identity_cutover': {'phase': 'accepted'}, 'identity_provider': {'phase': 'accepted'},
                          'objects': {
                    'app:' + app['domain']: {'id': app['id']}, 'dns:' + app['domain']: {'id': 'existing-dns'}}}}
    bundle = {'management': {'ACCOUNT_ID': fixture['account_id'], 'ZONE_ID': fixture['zone_id'],
                             'API_TOKEN': 'synthetic-management'},
              'dns': {'ZONE_ID': fixture['zone_id'], 'API_TOKEN': 'synthetic-dns'},
              'tunnel': {'TUNNEL_ID': fixture['tunnel_id']},
              'backend': {'PROJECT_ID': '123', 'USERNAME': 'synthetic', 'TOKEN': 'synthetic-backend'},
              'encryption': {'PASSPHRASE': 'synthetic-independent-passphrase-for-fixture'}}
    return snapshot, bundle
