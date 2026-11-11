"""Delete one dual-approved CloudNativePG database, then remove its CR.

PostSync hook companion to the bucket reconciler: reads the chart-rendered
database deletions from CLOUDLAB_DELETIONS, verifies each live Database CR
still carries the approved spec.name plus a recomputed approval digest,
patches its reclaim policy to delete, and removes the CR once the database
is gone. A missing CR counts as success (idempotent). Anything unexpected
fails with the database retained.

Stdlib only: the in-cluster python image carries no third-party packages.
"""

import hashlib
import http.client
import json
import os
import re
import ssl
import sys
import time
from pathlib import Path

SERVICE_NAME = re.compile(r'^[a-z][a-z0-9-]{0,30}$')
SQL_IDENTIFIER = re.compile(r'^[a-z][a-z0-9_]{0,62}$')
RESERVED_DATABASES = {'postgres', 'template0', 'template1'}
DIGEST_HEX = re.compile(r'^[0-9a-f]{64}$')
DELETION_SCOPE = 'disposable-fixture-delete-v1'
NAMESPACE = 'cloudlab-data'
API_PATH = '/apis/postgresql.cnpg.io/v1/namespaces/cloudlab-data/databases/%s'
POLL_SECONDS = 5
POLL_ROUNDS = 30


def fail(message):
    raise ValueError(message)


def deletion_digest(service, kind, name):
    """Hex digest over the canonical deletion bytes (mirrors the chart gate).

    Duplicated from reconcile.py on purpose: the destructive path never
    depends on the bucket module.
    """
    canonical = json.dumps({'service': service, 'kind': kind, 'name': name,
                            'scope': DELETION_SCOPE},
                           sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def valid_sql_identifier(value):
    return (isinstance(value, str) and SQL_IDENTIFIER.match(value) is not None
            and not value.startswith('pg_') and value not in RESERVED_DATABASES)


def load_deletions(text):
    """Parse and authenticate the chart-rendered database deletions."""
    try:
        entries = json.loads(text)
    except ValueError as error:
        fail('Deleter input is unreadable: ' + str(error))
    if not isinstance(entries, list) or len(entries) > 2:
        fail('Deleter input must list at most 2 entries')
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict)
                or set(entry) != {'service', 'kind', 'name', 'digest'}):
            fail('Deleter entry has unknown shape')
        if entry['kind'] != 'database':
            fail('Deleter refuses a non-database kind: ' + repr(entry['kind']))
        if (not isinstance(entry['service'], str)
                or SERVICE_NAME.match(entry['service']) is None):
            fail('Deleter service is invalid: ' + repr(entry['service']))
        if not valid_sql_identifier(entry['name']):
            fail('Deleter database name is invalid: ' + repr(entry['name']))
        if (not isinstance(entry['digest'], str)
                or DIGEST_HEX.match(entry['digest']) is None
                or entry['digest'] != deletion_digest(entry['service'], 'database',
                                                      entry['name'])):
            fail('Deleter digest does not match its approval: ' + entry['service'])
        triple = (entry['service'], entry['name'])
        if triple in seen:
            fail('Deleter entry is declared twice: ' + entry['service'])
        seen.add(triple)
    return entries


def api_request(host, port, token, context, method, path, body=None, content_type=None):
    """One authenticated Kubernetes API call; transport errors retain everything."""
    headers = {'Authorization': 'Bearer ' + token, 'Accept': 'application/json'}
    raw = None
    if body is not None:
        headers['Content-Type'] = content_type or 'application/json'
        raw = body.encode()
    try:
        connection = http.client.HTTPSConnection(host, port, timeout=30, context=context)
        try:
            connection.request(method, path, headers=headers, body=raw)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    except (OSError, ssl.SSLError) as error:
        raise RuntimeError('Kubernetes API request failed; database retained: '
                           + str(error)) from None


def live_spec(call, service):
    """Fetch the live Database spec; missing CR returns None (success path)."""
    status, raw = call('GET', API_PATH % service)
    if status == 404:
        return None
    if status != 200:
        raise RuntimeError('Database check refused for %s; database retained' % service)
    try:
        live = json.loads(raw.decode())
    except ValueError:
        raise RuntimeError('Database state is unreadable for %s; database retained'
                           % service) from None
    if not isinstance(live, dict) or not isinstance(live.get('spec'), dict):
        raise RuntimeError('Database state is unreadable for %s; database retained'
                           % service)
    return live['spec']


def delete_database(call, entry):
    """Verify, patch reclaim to delete, re-verify, delete, confirm absence."""
    service = entry['service']
    spec = live_spec(call, service)
    if spec is None:
        return False
    if spec.get('name') != entry['name']:
        raise RuntimeError('Database live name mismatch for %s; database retained' % service)
    patch = json.dumps([{'op': 'replace', 'path': '/spec/databaseReclaimPolicy',
                         'value': 'delete'}])
    status, _ = call('PATCH', API_PATH % service, patch, 'application/json-patch+json')
    if status != 200:
        raise RuntimeError('Database reclaim update refused for %s; database retained'
                           % service)
    spec = live_spec(call, service)
    if spec is None:
        return True
    if spec.get('name') != entry['name']:
        raise RuntimeError('Database live name mismatch for %s; database retained' % service)
    if spec.get('databaseReclaimPolicy') != 'delete':
        raise RuntimeError('Database reclaim did not converge for %s; database retained'
                           % service)
    status, _ = call('DELETE', API_PATH % service)
    if status not in (200, 202):
        raise RuntimeError('Database deletion refused for %s; database retained' % service)
    for _ in range(POLL_ROUNDS):
        if live_spec(call, service) is None:
            return True
        time.sleep(POLL_SECONDS)
    raise RuntimeError('Database did not converge for %s; database retained' % service)


def main():
    try:
        entries = load_deletions(os.environ.get('CLOUDLAB_DELETIONS', ''))
        host = os.environ.get('KUBERNETES_SERVICE_HOST', '')
        port = os.environ.get('KUBERNETES_SERVICE_PORT', '')
        if not host or not port.isdigit():
            fail('Kubernetes API endpoint is unavailable; database retained')
        try:
            token = Path('/var/run/secrets/kubernetes.io/serviceaccount/token').read_text().strip()
            authority = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
            context = ssl.create_default_context(cafile=authority)
        except (OSError, ssl.SSLError) as error:
            fail('Service account credential is unreadable: ' + str(error))
        if not token:
            fail('Service account credential is unreadable; database retained')
        call = lambda method, path, body=None, content_type=None: api_request(
            host, int(port), token, context, method, path, body, content_type)
        removed = []
        for entry in entries:
            if delete_database(call, entry):
                removed.append(entry['service'])
    except (ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr, flush=True)
        return 1
    if removed:
        print('Deleted approved databases: ' + ', '.join(removed), flush=True)
    else:
        print('Approved databases already absent', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
