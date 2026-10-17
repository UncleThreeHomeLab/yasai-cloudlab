"""Telemetry clients stay with the retained private source/config-cli owner."""
import json
import os

import yaml
from playbooks.observability.files.configuration import grafana, kiali
from playbooks.keycloak.files.operations import change, private_files
from playbooks.keycloak.files.private_source import decode_contents, publish
from playbooks.keycloak.files.rotation import local
from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_setup import repository


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
