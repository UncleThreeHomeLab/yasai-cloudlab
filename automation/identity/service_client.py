"""Service client changes use the existing private source and sole identity writer."""
import json
import os

from automation.identity.operations import change, private_files
from automation.identity.private_source import decode_contents, publish
from automation.services.contract import identity_request, validate


def prepare(definition, action):
    definition = validate(definition)
    oidc = definition['oidc']
    if not oidc['enabled']:
        return {'identity_change_required': False}
    if action not in ('provision-client', 'retire-client', 'remove-client'):
        raise ValueError('Unsupported service client lifecycle')
    from automation.gitops.github_setup import inputs, repository
    from automation.credentials.vault import fields
    values, api = inputs()
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    proposal = identity_request(definition, {oidc.get('secretReference'): 'x' * 48})
    if not oidc['public'] and action == 'provision-client':
        from automation.identity.rotation import local
        local({'action': 'provision', 'realm': oidc['realm'], 'client_id': oidc['client'], 'client': proposal['client']})
        credentials = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    # Credential custody never transfers to the onboarding module or public Git.
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    document = api.request('GET', 'repos/' + repo + '/contents/identity/configmap.yaml?ref=' + revision)
    import yaml
    manifest = yaml.safe_load(decode_contents(document))
    if manifest.get('metadata', {}).get('name') != 'identity-private-state' or set(manifest.get('data', {})) != {'desired_state', 'revocations'}:
        raise ValueError('Service client operation requires the complete owned identity inventory')
    source = json.loads(manifest['data']['desired_state'])
    revoked = json.loads(manifest['data']['revocations'])
    operation = {'action': action, 'realm': oidc['realm']}
    operation.update({'client': proposal['client']} if action == 'provision-client' else {'client_id': oidc['client']})
    source, revoked = change(source, revoked, operation)
    # Reuse the identity owner's canonical issuer, never a service-supplied host.
    overlay = api.request('GET', 'repos/' + repo + '/contents/identity/argo-values.yaml?ref=' + revision)
    configuration = yaml.safe_load(decode_contents(overlay))
    oidc_configuration = yaml.safe_load(configuration['argo-cd']['configs']['cm']['oidc.config'])
    from automation.identity.integrations import issuer
    rp_id = issuer(oidc_configuration['issuer']).split('/')[2]
    return publish(api, values, private_files(source, revoked, credentials, rp_id))
