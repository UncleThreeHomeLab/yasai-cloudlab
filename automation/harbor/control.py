"""Prepare local inputs and reviewed identity declarations without writing realm APIs."""
import argparse
import json
import os

from dotenv import dotenv_values
import fcntl
from pathlib import Path
import re
import yaml

from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_setup import inputs, repository
from automation.identity.operations import change, private_files
from automation.identity.private_source import decode_contents, publish
from automation.identity.rotation import local
from automation.observability.payload import metadata
from automation.harbor.configuration import client


def identity_prepare(values, api):
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        if not values.get(key):
            raise ValueError('Harbor identity preparation requires existing VM inputs')
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    discovered = metadata()
    login = discovered['loginHost']
    definition = client('https://' + login + '/realms/platform', 'https://harbor.internal.' + login[6:])
    local({'action': 'provision', 'realm': 'platform', 'client_id': definition['id'], 'client': definition})
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    document = api.request('GET', 'repos/' + repo + '/contents/identity/configmap.yaml?ref=' + revision)
    manifest = yaml.safe_load(decode_contents(document))
    if manifest.get('metadata', {}).get('name') != 'identity-private-state' or set(manifest.get('data', {})) != {'desired_state', 'revocations'}:
        raise ValueError('Harbor identity requires the retained complete private inventory')
    source, revoked = json.loads(manifest['data']['desired_state']), json.loads(manifest['data']['revocations'])
    source, revoked = change(source, revoked, {'action': 'provision-client', 'realm': 'platform', 'client': definition})
    return publish(api, values, private_files(source, revoked, credentials, login))


def private_dns_input():
    from automation.connectivity.contract import private_names
    path = '/workspace/.env'
    values = dotenv_values(path, interpolate=False)
    baseline = private_names(json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]'))
    if 'harbor' in baseline:
        return {'changed': False}
    # A file-only writable bind keeps every other source file read-only in Compose.
    with Path(path).open('r+', encoding='utf-8') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original = stream.read()
        lines = original.splitlines(keepends=True)
        indices = [index for index, line in enumerate(lines) if re.match(r'^PRIVATE_ACCESS_HOSTS=', line)]
        if len(indices) != 1:
            raise ValueError('Private DNS input must have one explicit existing declaration')
        lines[indices[0]] = 'PRIVATE_ACCESS_HOSTS=' + json.dumps(sorted(baseline + ['harbor']), separators=(',', ':')) + '\n'
        stream.seek(0)
        stream.write(''.join(lines))
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())
    return {'changed': True, 'private_host_added': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('identity-prepare', 'private-dns-input', 'credentials'))
    action = parser.parse_args().action
    if action == 'identity-prepare':
        values, api = inputs()
        result = identity_prepare(values, api)
    elif action == 'credentials':
        from automation.harbor.installation_credentials import provision
        result = provision()
    else:
        result = private_dns_input()
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Harbor input preparation incomplete; private values withheld and existing data retained') from None
