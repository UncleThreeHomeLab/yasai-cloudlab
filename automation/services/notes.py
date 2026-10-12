"""Compile two notes workloads from the reviewed service and identity/data inputs."""
import copy
from pathlib import Path

import yaml

from automation.services.contract import ROOT, validate


def values(definition, issuer, database_ca):
    definition = validate(definition)
    if definition['name'] != 'notes' or not definition['oidc']['enabled'] or not definition['oidc']['public']:
        raise ValueError('Notes requires its approved public PKCE client')
    if set(definition['data']) != {'database', 'bucket'}:
        raise ValueError('Notes requires scoped SQL and S3 requests')
    if not issuer.startswith('https://') or not issuer.endswith('/realms/applications'):
        raise ValueError('Notes requires the approved application realm issuer')
    if 'BEGIN CERTIFICATE' not in database_ca:
        raise ValueError('Notes requires the existing CNPG public CA')
    result = yaml.safe_load((ROOT / 'apps/notes/values.yaml').read_text())
    private = [e for e in definition.get('additionalExposures', []) if e['class'] == 'private']
    if len(private) != 1:
        raise ValueError('Notes requires one private operations exposure')
    for name in ('web', 'api'):
        value = result[name]
        for field in ('owner', 'image', 'replicas', 'resources'):
            value[field] = copy.deepcopy(definition[field])
        value['exposure'] = copy.deepcopy(definition['exposure'])
        value['additionalExposures'] = copy.deepcopy(private)
        value['oidc'] = copy.deepcopy(definition['oidc'])
        value['environment']['OIDC_ISSUER'] = issuer
        value['environment']['OIDC_AUDIENCE'] = definition['oidc']['audience']
        value['environment']['OPERATIONS_HOST'] = private[0]['hostname']
    result['web']['environment']['OIDC_CLIENT'] = definition['oidc']['client']
    result['web']['environment']['OIDC_SCOPES'] = ' '.join(['openid', *definition['oidc']['scopes']])
    result['web']['data'] = {}
    result['web']['secrets'] = []
    result['api']['exposure']['path'] = '/api'
    result['api']['additionalExposures'][0]['path'] = '/api'
    result['api']['data'] = copy.deepcopy(definition['data'])
    result['api']['environment']['PGDATABASE'] = definition['data']['database']['name']
    result['api']['environment']['PGHOST'] = 'cloudlab-postgres-rw.cloudlab-data.svc'
    result['api']['secrets'] = [
        {'name': definition['data']['database']['credentialReference'], 'mountPath': '/secrets/database'},
        {'name': definition['data']['bucket']['credentialReference'], 'mountPath': '/secrets/objects'}]
    result['databaseCA'] = database_ca
    for kind, budget in (('requests', 1000), ('limits', 2000)):
        for unit, suffix in (('cpu', 1), ('memory', 2)):
            if 2 * definition['replicas'] * int(definition['resources'][kind][unit][:-suffix]) > budget:
                raise ValueError('Combined notes workloads exceed their namespace budget')
    for name in ('web', 'api'): validate(result[name])
    return result
