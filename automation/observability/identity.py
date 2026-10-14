"""Telemetry clients stay with the retained private source/config-cli owner."""
import json
import os

import yaml
from automation.observability.configuration import grafana, kiali
from automation.identity.operations import change, private_files
from automation.identity.private_source import decode_contents, publish
from automation.identity.rotation import local
from automation.credentials.vault import fields
from automation.gitops.github_setup import repository


def contracts(metadata):
    issuer = 'https://' + metadata['loginHost'] + '/realms/platform'
    return (grafana(issuer, 'https://' + metadata['grafanaHost'])['client'],
            kiali(issuer, 'https://' + metadata['kialiHost']))


def provision(metadata, values, api):
    for client in contracts(metadata):
        local({'action': 'provision', 'realm': 'platform', 'client_id': client['id'], 'client': client})
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    document = api.request('GET', 'repos/' + repo + '/contents/identity/configmap.yaml?ref=' + revision)
    manifest = yaml.safe_load(decode_contents(document))
    if manifest.get('metadata', {}).get('name') != 'identity-private-state' or set(manifest.get('data', {})) != {'desired_state', 'revocations'}:
        raise ValueError('Telemetry identity clients require the complete retained inventory')
    source, revoked = json.loads(manifest['data']['desired_state']), json.loads(manifest['data']['revocations'])
    for client in contracts(metadata):
        source, revoked = change(source, revoked, {'action': 'provision-client', 'realm': 'platform', 'client': client})
    return publish(api, values, private_files(source, revoked, credentials, metadata['loginHost']))
