"""Reviewable private source changes; the config-cli job remains the realm writer."""
import copy
import json
from pathlib import Path
import sys

from automation.identity.configuration import compile_state, name, REALMS
from automation.identity.integrations import argo, access


def change(source, revocations, operation):
    source, revocations = copy.deepcopy(source), copy.deepcopy(revocations)
    realm = operation.get('realm')
    if realm not in REALMS:
        raise ValueError('Operation must target a managed realm')
    action = operation.get('action')
    desired = source['realms'].setdefault(realm, {})
    denied = revocations['realms'].setdefault(realm, {'users': [], 'clients': []})
    if action == 'provision-client':
        if set(operation) != {'action', 'realm', 'client'}:
            raise ValueError('Invalid client provisioning fields')
        identifier = name(operation['client']['id'])
        if identifier in denied.get('clients', []):
            raise ValueError('Retired clients cannot be re-enabled through provisioning')
        clients = desired.setdefault('clients', [])
        existing = next((c for c in clients if c['id'] == identifier), None)
        if existing is not None and existing != operation['client']:
            raise ValueError('Client already exists with a different contract')
        if existing is None:
            clients.append(copy.deepcopy(operation['client']))
    elif action in ('disable-client', 'retire-client', 'remove-client'):
        if set(operation) != {'action', 'realm', 'client_id'}:
            raise ValueError('Invalid retirement fields')
        identifier = name(operation['client_id'])
        if not any(c['id'] == identifier for c in desired.get('clients', [])):
            if action == 'remove-client' and identifier in denied.get('removed_clients', []):
                return source, revocations
            raise ValueError('Only an inventoried client can be retired')
        if action == 'remove-client':
            if identifier not in denied.get('clients', []) or any(c.get('enabled', True) for c in desired['clients'] if c['id'] == identifier):
                raise ValueError('Disable and persist retirement before preparing removal')
            desired['clients'] = [c for c in desired['clients'] if c['id'] != identifier]
            if identifier not in denied.setdefault('removed_clients', []):
                denied['removed_clients'].append(identifier)
            return source, revocations
        if identifier not in denied.setdefault('clients', []):
            denied['clients'].append(identifier)
        for item in desired['clients']:
            if item['id'] == identifier:
                item['enabled'] = False
    elif action == 'offboard-user':
        if set(operation) != {'action', 'realm', 'username'} or not isinstance(operation['username'], str) or not operation['username']:
            raise ValueError('Invalid offboarding fields')
        username = operation['username']
        if username.startswith('service-account-'):
            raise ValueError('Human lifecycle must not disable machine credentials')
        if not any(u['username'] == username for u in desired.get('memberships', [])):
            raise ValueError('Only an inventoried private membership can be offboarded')
        if username not in denied.setdefault('users', []):
            denied['users'].append(username)
    else:
        raise ValueError('Unsupported scoped identity operation')
    return source, revocations


def main():
    request = json.load(sys.stdin)
    if set(request) != {'source', 'revocations', 'operation', 'client_secrets', 'rp_id'}:
        raise ValueError('Identity operation requires a complete private input snapshot')
    operation = request['operation']
    integration = None
    if operation.get('action') == 'provision-argo':
        if set(operation) != {'action', 'issuer', 'origin'}:
            raise ValueError('Argo requires its exact issuer and origin')
        integration = argo(operation['issuer'], operation['origin'])
    elif operation.get('action') == 'provision-access':
        if set(operation) != {'action', 'issuer', 'team'}:
            raise ValueError('Access requires its exact issuer and team')
        integration = access(operation['issuer'], operation['team'],
                             request['client_secrets'].get('platform', {}).get('cloudflare-access'))
        # A provider API request needs the secret; the reviewable source must not.
        integration['provider']['config'].pop('client_secret')
        integration['credential_delivery'] = 'Resolve the platform/cloudflare-access value from keycloak-client-secrets through ESO at apply time'
    if integration:
        operation = {'action': 'provision-client', 'realm': 'platform', 'client': integration['client']}
    source, revocations = change(request['source'], request['revocations'], operation)
    for realm in REALMS:
        compile_state(realm, request['rp_id'], source, request['client_secrets'], revocations)
    target = Path('/recovery/identity-private-change.json')
    if target.exists():
        raise RuntimeError('Previous identity change requires review before generating another')
    with target.open('x') as stream:
        target.chmod(0o600)
        result = {'desired_state': source, 'revocations': revocations}
        if operation['action'] == 'remove-client':
            realm, identifier = operation['realm'], operation['client_id']
            result['removal'] = {
                'cache_key': 'remove-' + realm + '-' + identifier,
                'seed': {'realm': realm, 'clients': [{'clientId': identifier, 'enabled': False}]},
                'remove': {'realm': realm, 'clients': []},
                'seed_properties': {'import.cache.enabled': False, 'import.managed.client': 'no-delete'},
                'remove_properties': {'import.cache.enabled': False, 'import.managed.client': 'full'},
                'requirements': 'Publish the complete private tombstone first. Verify disable/session deadline. Run seed then removal through the shared Lease and scoped Argo jobs; never use the main cache key.',
            }
        if integration:
            result['integration_configuration'] = integration
        json.dump(result, stream, sort_keys=True)
    print(json.dumps({'private_change': str(target), 'realm_changed': False,
                      'requires_private_source_review': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError))
                         else 'Private identity operation failed; no realm changes made') from None
