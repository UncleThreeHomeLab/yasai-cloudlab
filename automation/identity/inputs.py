"""Resolve required private source metadata without publishing it."""
import json
import os
from pathlib import Path
import sys

from dotenv import dotenv_values
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.gitops.render import committed_payload
from automation.gitops.github_setup import repository


def native_argo(values):
    import urllib.request
    from automation.credentials.vault import fields
    from automation.connectivity.cloudflare import API
    from automation.gitops.github_app import app_token, verify_installation
    from automation.gitops.github_setup import GitHub
    from automation.identity.private_source import argo_values
    from automation.connectivity.contract import host_rules
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    dns = fields('cloudlab-dns01', ('API_TOKEN', 'ZONE_ID'))
    zone = API(dns['API_TOKEN']).request('GET', 'zones/' + dns['ZONE_ID'])['name']
    rules = host_rules(json.loads(values.get('CLOUDFLARE_ACCESS_HOSTS') or '[]'), zone)
    hosts = sorted(rule['hostname'] for rule in rules if rule['access'] == 'human')
    if not hosts:
        raise RuntimeError('Native Argo requires an existing independently protected human hostname')
    origins = ['https://' + hosts[0], 'https://cd.internal.' + zone]
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    api = GitHub(app_token(credentials))
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    token = api.request('POST', path + '/access_tokens', {
        'repositories': [repo.split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    client = GitHub(token)
    try:
        revision = client.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        contract = argo_values(client, values, revision, 'https://login.' + zone + '/realms/platform',
                               origins[0], origins[1:])
        return {'target': {'valuesRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'valuesRevision': revision},
                'configuration': contract['helm'], 'client': contract['client']}
    finally:
        request = urllib.request.Request('https://api.github.com/installation/token', method='DELETE',
            headers={'Authorization': 'Bearer ' + token, 'Accept': 'application/vnd.github+json'})
        with client.opener.open(request, timeout=30) as response:
            if response.status != 204:
                raise RuntimeError('Private values reader token revocation failed')


def payload():
    result = committed_payload()
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if not public.get('identity', {}).get('enabled'):
        raise RuntimeError('Identity operator and dedicated CNPG contract must be reviewed and enabled first')
    values = dotenv_values(ROOT / '.env', interpolate=False)
    private = values.get('PRIVATE_CONFIG_REPOSITORY')
    private_name = repository(private)
    public_name = repository(result['repository'])
    if private_name == public_name or private_name.split('/')[0] != public_name.split('/')[0]:
        raise RuntimeError('Identity private source must be a distinct designated configuration repository')
    result = {key: result[key] for key in ('repository', 'branch', 'revision')} | {
        'private_repository': private, 'private_branch': 'main'}
    if os.environ.get('LAB_IDENTITY_PHASE') == 'argo':
        result['argo'] = native_argo(values)
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Required identity source metadata unavailable; no changes made') from None
