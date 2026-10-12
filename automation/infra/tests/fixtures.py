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


def github_owner():
    fixture = json.loads(Path('/workspace/infra/github/fixtures.json').read_text())
    repository = copy.deepcopy(fixture['repositories']['fixture'])
    repository.update(id=123, node_id='synthetic-node', full_name=fixture['owner'] + '/' + repository['name'],
                      fork=False, archived=False, private=False)
    rule = fixture['rulesets']['fixture']
    parameters = copy.deepcopy(rule['pull_request'])
    parameters.update(require_extra_approval_for_unattributed_changes=True,
                      dismissal_restriction={'enabled': False, 'allowed_actors': []}, required_reviewers=[])
    rules = [{'type': field} for field in ('deletion', 'non_fast_forward', 'required_linear_history')]
    rules.append({'type': 'pull_request', 'parameters': parameters})
    ruleset = {'id': 456, 'name': rule['name'], 'target': 'branch', 'enforcement': 'active',
               'conditions': {'ref_name': {'include': rule['include'], 'exclude': rule['exclude']}},
               'bypass_actors': [], 'rules': rules}
    return {'fixture': {'repository': repository, 'rulesets': [ruleset], 'branch': {'name': 'main'}}}
