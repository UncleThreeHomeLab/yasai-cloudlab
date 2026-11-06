"""Resolve required private source metadata without publishing it."""
import json
import os
import re
from pathlib import Path
import sys

from dotenv import dotenv_values
import yaml

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ROOT))
from playbooks.argocd.files.render import committed_payload
from playbooks.argocd.files.github_setup import repository


def native_argo(values):
    recovery_revision = values.get('KEYCLOAK_ARGO_RECOVERY_REVISION') or None
    if recovery_revision is not None and not re.fullmatch('[a-f0-9]{40}', recovery_revision):
        raise ValueError('Native Argo recovery requires its exact recorded private revision')
    import urllib.request
    from playbooks.secrets.files.vault import fields
    from playbooks.access.files.cloudflare import API
    from playbooks.argocd.files.github_app import app_token, verify_installation
    from playbooks.argocd.files.github_setup import GitHub
    from playbooks.keycloak.files.private_source import argo_values
    from playbooks.keycloak.files.private_source import decode_contents
    from playbooks.argocd.files.service_activation import prepare
    from playbooks.argocd.files.private_activation import prepare as prepare_private
    from playbooks.argocd.files.access_activation import prepare as prepare_access
    from playbooks.argocd.files.data_activation import prepare as prepare_data
    from playbooks.argocd.files.private_sources import registry, accepted_source, registry_enabled, acceptance_commitment
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    private_enabled = registry_enabled(public)
    if private_enabled: acceptance_commitment(public)
    from playbooks.services.files.inputs import validate_catalog
    from playbooks.access.files.contract import host_rules
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
        current_revision = client.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        current = None
        if recovery_revision:
            # Historical inputs hydrate a checkpoint; current Git still authorizes access.
            current = argo_values(client, values, current_revision, 'https://login.' + zone + '/realms/platform',
                                  origins[0], origins[1:])
        revision = recovery_revision or current_revision
        contract = argo_values(client, values, revision, 'https://login.' + zone + '/realms/platform',
                               origins[0], origins[1:])
        catalog = None
        if public.get('services', {}).get('enabled', False):
            from playbooks.argocd.files.service_activation import catalog_path
            selected_path = catalog_path(public['services'].get('catalogPath', catalog_path()))
            from playbooks.data.files.native import private_file
            catalog = validate_catalog(private_file(client, values['PRIVATE_CONFIG_REPOSITORY'], revision, selected_path), public=public)
        acceptance = accepted_source(client, values['PRIVATE_CONFIG_REPOSITORY'], current_revision, public) if private_enabled else None
        private_registry = (registry(client, values, public, acceptance['acceptedRevision'], acceptance=acceptance)
                            if private_enabled else None)
        result = {'target': {'valuesRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'valuesRevision': revision},
                'configuration': contract['helm'], 'client': contract['client'],
                'serviceActivation': prepare(public, values['PRIVATE_CONFIG_REPOSITORY'], revision, catalog,
                    namespace_declaration=yaml.safe_load((ROOT / 'platform/delivery/admission/policies/templates/workload-namespace.yaml').read_text())),
                'privateActivation': prepare_private(public, values['PRIVATE_CONFIG_REPOSITORY'], revision,
                                                     private_registry, acceptance=acceptance),
                'accessActivation': prepare_access(public, values['PRIVATE_CONFIG_REPOSITORY'], revision, client),
                'dataActivation': prepare_data(public, values['PRIVATE_CONFIG_REPOSITORY'], revision, client, catalog),
                'recovery': recovery_revision is not None}
        if recovery_revision:
            result['currentSecurityProjection'] = {'revision': current_revision,
                'configuration': current['helm'], 'client': current['client']}
        return result
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
        'private_repository': private, 'private_branch': 'main',
        'telemetry_enabled': bool(public.get('observability', {}).get('enabled', False))}
    result['identity_application_enabled'] = public.get('identity', {}).get('application', {}).get('enabled', False)
    if result['identity_application_enabled']:
        from playbooks.keycloak.files.ownership import public_installation_revision
        result['installation_revision'] = public_installation_revision(public)
    from playbooks.access.files.inputs import observation
    result['access_observation'] = observation(public, private)
    if os.environ.get('LAB_IDENTITY_PHASE') == 'argo':
        result['argo'] = native_argo(values)
    return result


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Required identity source metadata unavailable; no changes made') from None
