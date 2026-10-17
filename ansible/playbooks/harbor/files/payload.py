"""Compile public installation pins with retained private identity/gateway metadata."""
import json
import os

from playbooks.argocd.files.render import committed_payload
from playbooks.observability.files.payload import metadata
from playbooks.harbor.files.values import values
from playbooks.harbor.files.configuration import client


def compile_payload(source, discovered):
    login = discovered['loginHost']
    host = 'harbor.internal.' + login.removeprefix('login.')
    identity_client = client('https://' + login + '/realms/platform', 'https://' + host)
    server = values()
    server['externalURL'] = 'https://' + host
    server['core']['hostAliases'] = [{'ip': discovered['gatewayIP'], 'hostnames': [login]}]
    return {'repository': source['repository'], 'revision': source['revision'],
            'configuration': {'enabled': True, 'harborHost': host, 'loginHost': login,
                              'gatewayIP': discovered['gatewayIP']}, 'identity_client': identity_client,
            'server': {'harbor': server}}


def payload():
    return compile_payload(committed_payload(), metadata())


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception:
        raise SystemExit('Harbor requires published source and the accepted private identity/gateway contract') from None
