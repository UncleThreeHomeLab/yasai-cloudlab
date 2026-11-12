"""Ensure approved SeaweedFS buckets exist; delete only dual-approved ones.

Reads desired state rendered by this chart from /desired/desired.json and
uses only the mounted data-admin S3 identity. Buckets listed under `buckets`
are created when missing and never removed; buckets listed under `deletions`
are removed when present, with absent counting as success. Every deletion
entry is self-authenticating: its digest must recompute over the fixed
deletion scope or the cycle fails with nothing deleted. PostgreSQL grants
are rendered as static SQL by the chart and applied by the companion psql
container as each database owner; this module validates the shared desired
document and reconciles buckets only.

Stdlib only: the in-cluster python image carries no third-party packages.
"""

import hashlib
import hmac
import http.client
import json
import re
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

SQL_IDENTIFIER = re.compile(r'^[a-z][a-z0-9_]{0,62}$')
RESERVED_DATABASES = {'postgres', 'template0', 'template1'}
SECRET_NAME = re.compile(r'^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$')
BUCKET_NAME = re.compile(r'^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')
S3_HOST = re.compile(r'^s3\.internal\.[a-z0-9.-]+$')
SERVICE_NAME = re.compile(r'^[a-z][a-z0-9-]{0,30}$')
DIGEST_HEX = re.compile(r'^[0-9a-f]{64}$')
DELETION_SCOPE = 'disposable-fixture-delete-v1'

EMPTY_SHA256 = hashlib.sha256(b'').hexdigest()


def fail(message):
    raise ValueError(message)


def valid_sql_identifier(value):
    return (isinstance(value, str) and SQL_IDENTIFIER.match(value) is not None
            and not value.startswith('pg_') and value not in RESERVED_DATABASES)


def deletion_digest(service, kind, name):
    """Hex digest over the canonical deletion bytes (mirrors the chart gate)."""
    canonical = json.dumps({'service': service, 'kind': kind, 'name': name,
                            'scope': DELETION_SCOPE},
                           sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(canonical).hexdigest()


def load_desired(path):
    """Parse and validate the chart-rendered desired document file."""
    try:
        return load_desired_text(Path(path).read_text())
    except OSError as error:
        fail('Desired data state is unreadable: ' + str(error))


def load_desired_text(text):
    """Parse and validate the chart-rendered desired document."""
    try:
        document = json.loads(text)
    except ValueError as error:
        fail('Desired data state is unreadable: ' + str(error))
    if (not isinstance(document, dict)
            or set(document) != {'s3Host', 'databases', 'buckets', 'deletions'}):
        fail('Desired data state has unknown shape')
    host = document['s3Host']
    if not isinstance(host, str) or len(host) > 253 or S3_HOST.match(host) is None:
        fail('Desired S3 host is not the approved internal endpoint')
    databases = document['databases']
    if not isinstance(databases, list) or not databases or len(databases) > 10:
        fail('Desired databases must list between 1 and 10 entries')
    seen = set()
    roles = set()
    for entry in databases:
        if (not isinstance(entry, dict)
                or set(entry) != {'name', 'owner', 'secret', 'applicationRole'}):
            fail('Desired database entry has unknown shape')
        if not valid_sql_identifier(entry['name']):
            fail('Desired database name is invalid or reserved: ' + repr(entry['name']))
        if not valid_sql_identifier(entry['owner']):
            fail('Desired database owner is invalid: ' + repr(entry['owner']))
        if (not isinstance(entry['secret'], str)
                or SECRET_NAME.match(entry['secret']) is None):
            fail('Desired database secret is invalid: ' + repr(entry['secret']))
        role = entry['applicationRole']
        if role is not None and (not valid_sql_identifier(role) or role == entry['owner']):
            fail('Desired application role is invalid: ' + repr(role))
        if entry['name'] in seen:
            fail('Desired database is declared twice: ' + entry['name'])
        seen.add(entry['name'])
        for held in [entry['owner']] if role is None else [entry['owner'], role]:
            if held in roles:
                fail('Desired data role is reused across databases: ' + held)
            roles.add(held)
    buckets = document['buckets']
    if not isinstance(buckets, list) or not buckets or len(buckets) > 10:
        fail('Desired buckets must list between 1 and 10 entries')
    if any(not isinstance(name, str) or BUCKET_NAME.match(name) is None for name in buckets):
        fail('Desired bucket name is invalid')
    if len(set(buckets)) != len(buckets):
        fail('Desired bucket is declared twice')
    deletions = document['deletions']
    if not isinstance(deletions, list) or len(deletions) > 2:
        fail('Desired deletions must list at most 2 entries')
    seen_deletions = set()
    for entry in deletions:
        if (not isinstance(entry, dict)
                or set(entry) != {'service', 'kind', 'name', 'digest'}):
            fail('Desired deletion entry has unknown shape')
        kind = entry['kind']
        if kind not in ('database', 'bucket'):
            fail('Desired deletion kind is not supported: ' + repr(kind))
        if (not isinstance(entry['service'], str)
                or SERVICE_NAME.match(entry['service']) is None):
            fail('Desired deletion service is invalid: ' + repr(entry['service']))
        valid_name = (valid_sql_identifier(entry['name']) if kind == 'database'
                      else isinstance(entry['name'], str)
                      and BUCKET_NAME.match(entry['name']) is not None)
        if not valid_name:
            fail('Desired deletion name is invalid: ' + repr(entry['name']))
        if (not isinstance(entry['digest'], str)
                or DIGEST_HEX.match(entry['digest']) is None
                or entry['digest'] != deletion_digest(entry['service'], kind, entry['name'])):
            fail('Desired deletion digest does not match its approval: '
                 + entry['service'] + '/' + kind)
        triple = (entry['service'], kind, entry['name'])
        if triple in seen_deletions:
            fail('Desired deletion is declared twice: ' + entry['service'] + '/' + entry['name'])
        seen_deletions.add(triple)
        if kind == 'bucket' and entry['name'] in buckets:
            fail('Desired deletion overlaps a retained bucket: ' + entry['name'])
    return document


def _hmac(key, message):
    if isinstance(key, str):
        key = key.encode()
    if isinstance(message, str):
        message = message.encode()
    return hmac.new(key, message, hashlib.sha256).digest()


def signature_headers(method, path, host, access, secret, region, now):
    """Sign one S3 bucket request with Signature Version 4."""
    stamp = now.strftime('%Y%m%d')
    amzdate = now.strftime('%Y%m%dT%H%M%SZ')
    scope = '%s/%s/s3/aws4_request' % (stamp, region)
    canonical = '\n'.join([method, path, '',
                           'host:' + host,
                           'x-amz-content-sha256:' + EMPTY_SHA256,
                           'x-amz-date:' + amzdate, '',
                           'host;x-amz-content-sha256;x-amz-date',
                           EMPTY_SHA256])
    signing = _hmac(_hmac(_hmac(_hmac('AWS4' + secret, stamp), region), 's3'), 'aws4_request')
    string_to_sign = '\n'.join(['AWS4-HMAC-SHA256', amzdate, scope,
                               hashlib.sha256(canonical.encode()).hexdigest()])
    signature = hmac.new(signing, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {'Authorization': 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s'
            % (access, scope, 'host;x-amz-content-sha256;x-amz-date', signature),
            'x-amz-date': amzdate, 'x-amz-content-sha256': EMPTY_SHA256}


def s3_status(host, method, path, headers, timeout=30):
    try:
        connection = http.client.HTTPSConnection(host, 443, timeout=timeout,
                                                context=ssl.create_default_context())
        try:
            connection.request(method, path, headers=headers)
            return connection.getresponse().status
        finally:
            connection.close()
    except (OSError, ssl.SSLError) as error:
        raise RuntimeError('S3 bucket request failed; buckets retained: ' + str(error)) from None


def ensure_buckets(document, access, secret, region, transport=None):
    """Create missing approved buckets; never delete or modify existing ones."""
    if not access or not secret:
        raise RuntimeError('S3 admin identity is missing; buckets retained')
    call = transport or (lambda method, path, headers:
                         s3_status(document['s3Host'], method, path, headers))
    ensured = []
    for bucket in document['buckets']:
        path = '/%s/' % bucket
        headers = signature_headers('HEAD', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        status = call('HEAD', path, headers)
        if status == 200:
            continue
        if status != 404:
            raise RuntimeError('S3 bucket check refused for %s; buckets retained' % bucket)
        headers = signature_headers('PUT', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        if call('PUT', path, headers) != 200:
            raise RuntimeError('S3 bucket creation refused for %s; buckets retained' % bucket)
        headers = signature_headers('HEAD', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        if call('HEAD', path, headers) != 200:
            raise RuntimeError('S3 bucket did not converge for %s; buckets retained' % bucket)
        ensured.append(bucket)
    return ensured


def delete_buckets(document, access, secret, region, transport=None):
    """Delete ONLY approved buckets; absent counts as success, others retained."""
    if not access or not secret:
        raise RuntimeError('S3 admin identity is missing; buckets retained')
    call = transport or (lambda method, path, headers:
                         s3_status(document['s3Host'], method, path, headers))
    deleted = []
    for entry in document['deletions']:
        if entry['kind'] != 'bucket':
            continue
        bucket = entry['name']
        path = '/%s/' % bucket
        headers = signature_headers('HEAD', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        status = call('HEAD', path, headers)
        if status == 404:
            continue
        if status != 200:
            raise RuntimeError('S3 bucket check refused for %s; buckets retained' % bucket)
        headers = signature_headers('DELETE', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        if call('DELETE', path, headers) not in (200, 204):
            raise RuntimeError('S3 bucket deletion refused for %s; buckets retained' % bucket)
        headers = signature_headers('HEAD', path, document['s3Host'], access, secret,
                                    region, datetime.now(timezone.utc))
        if call('HEAD', path, headers) != 404:
            raise RuntimeError('S3 bucket did not converge for %s; buckets retained' % bucket)
        deleted.append(bucket)
    return deleted


def read_secret(directory, name, required=True):
    path = Path(directory) / name
    try:
        value = path.read_text().strip()
    except OSError:
        value = ''
    if not value and required:
        raise RuntimeError('Required S3 credential is missing; buckets retained')
    return value


def main():
    try:
        document = load_desired('/desired/desired.json')
        access = read_secret('/s3config', 'admin_ACCESS_KEY_ID')
        secret = read_secret('/s3config', 'admin_SECRET_ACCESS_KEY')
        region = read_secret('/s3config', 'app_REGION', required=False) or 'us-east-1'
        ensured = ensure_buckets(document, access, secret, region)
        deleted = delete_buckets(document, access, secret, region)
    except (ValueError, RuntimeError) as error:
        print(str(error), file=sys.stderr, flush=True)
        return 1
    if ensured:
        print('Ensured S3 buckets: ' + ', '.join(ensured), flush=True)
    else:
        print('All approved S3 buckets already exist', flush=True)
    if deleted:
        print('Deleted approved S3 buckets: ' + ', '.join(deleted), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
