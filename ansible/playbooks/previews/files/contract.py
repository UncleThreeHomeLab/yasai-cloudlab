"""Immutable approvals for bounded synthetic previews; never interpret PR code."""
import hashlib
import json
import re

OWNER = 'cloudlab-previews'
APPROVALS = 'cloudlab-preview-approvals'
STATE = 'cloudlab-preview-state'
IDENTITY_STATE = 'cloudlab-preview-identity-state'
SOURCE_PATH = 'previews/definition.json'
MAX_LIFETIME = 86400
MAX_ACTIVE = 2
PRIVATE_MAX_LIFETIME = 3000
LEASE_MARGIN = 300
GENERATED_CONFIGMAPS = ('kube-root-ca.crt', 'istio-ca-root-cert', 'istio-ca-crl')
ANONYMOUS_INTERVAL = 900
IMAGE = 'python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed'


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def source(raw):
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 16384:
        raise ValueError('Preview source exceeds its bound')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Preview source requires a supported profile')
    if value.get('profile') == 'synthetic':
        if (set(value) != {'profile', 'message'} or not isinstance(value['message'], str) or
                not re.fullmatch(r'[A-Za-z0-9 ._-]{1,120}', value['message'])):
            raise ValueError('Synthetic preview source permits only a bounded message')
    elif value.get('profile') == 'application':
        if set(value) != {'profile', 'port', 'healthPath', 'environment', 'resources'}:
            raise ValueError('Application previews require a complete restricted declaration')
        if (type(value['port']) is not int or not 1024 <= value['port'] <= 65535 or
                value['healthPath'] != '/healthz'):
            raise ValueError('Preview image must be immutable and use the fixed health endpoint')
        environment = value['environment']
        if (not isinstance(environment, dict) or len(environment) > 16 or any(
                not re.fullmatch('PREVIEW_[A-Z0-9_]{1,40}', key) or
                not isinstance(item, str) or not re.fullmatch(r'[A-Za-z0-9 ._/-]{0,120}', item)
                for key, item in environment.items())):
            raise ValueError('Preview environment permits only bounded non-secret synthetic settings')
        resources = value['resources']
        if not isinstance(resources, dict) or set(resources) != {'requests', 'limits'}:
            raise ValueError('Preview resources require bounded requests and limits')
        amounts = {}
        for kind, maxima in (('requests', (100, 128)), ('limits', (250, 256))):
            if not isinstance(resources[kind], dict) or set(resources[kind]) != {'cpu', 'memory'}:
                raise ValueError('Preview resource dimensions are fixed')
            amounts[kind] = []
            for key, suffix, limit in zip(('cpu', 'memory'), ('m', 'Mi'), maxima):
                match = re.fullmatch(r'([1-9][0-9]*)' + suffix, resources[kind][key])
                if not match or int(match[1]) > limit:
                    raise ValueError('Preview resource budget exceeded')
                amounts[kind].append(int(match[1]))
        if any(a > b for a, b in zip(amounts['requests'], amounts['limits'])):
            raise ValueError('Preview requests exceed limits')
    else:
        raise ValueError('Preview profile must be synthetic or application')
    return value


def repository(value):
    if not isinstance(value, str) or len(value) > 140 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', value):
        raise ValueError('Preview repository must be an explicit GitHub repository')
    return value


def stored_approval(value):
    fields = {'instance', 'repository', 'repositoryId', 'pullRequest', 'sourceSha', 'sourcePath', 'image',
              'sourceDigest', 'definition', 'platformRevision', 'createdAt', 'expiresAt'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('Preview approval requires its complete immutable contract')
    if not isinstance(value['instance'], str) or not re.fullmatch('[a-f0-9]{32}', value['instance']):
        raise ValueError('Preview instance must be an immutable random nonce')
    repository(value['repository'])
    for key in ('repositoryId', 'pullRequest', 'createdAt', 'expiresAt'):
        if type(value[key]) is not int or value[key] < 1:
            raise ValueError('Preview identifiers and times must be positive integers')
    if not 60 <= value['expiresAt'] - value['createdAt'] <= MAX_LIFETIME:
        raise ValueError('Preview lifetime must be between one minute and one day')
    for key, length in (('sourceSha', 40), ('platformRevision', 40), ('sourceDigest', 64)):
        if not isinstance(value[key], str) or not re.fullmatch('[a-f0-9]{' + str(length) + '}', value[key]):
            raise ValueError('Preview source and platform revisions must be immutable')
    if value['sourcePath'] != SOURCE_PATH:
        raise ValueError('Preview source path is platform controlled')
    source(canonical(value['definition']))
    if (not isinstance(value['image'], str) or len(value['image']) > 512 or not re.fullmatch(
            r'[a-z0-9][a-z0-9.-]*(?:/[a-z0-9_./-]+)?(?::[a-zA-Z0-9_.-]+)?@sha256:[a-f0-9]{64}', value['image'])):
        raise ValueError('Preview approval requires an immutable approved image')
    return value


def obsolete(row):
    stored_approval(row)
    return row['definition']['profile'] == 'synthetic' and row['image'] != IMAGE


def approval(value):
    stored_approval(value)
    if obsolete(value):
        raise ValueError('Preview approval requires the current immutable synthetic image')
    return value


def _catalog(value, validate):
    if not isinstance(value, dict) or set(value) != {'hostname', 'issuer', 'approvals', 'privateDiscovery', 'ownership', 'artifacts'}:
        raise ValueError('Preview catalog requires exact private access and approvals')
    origin(value)
    if type(value['privateDiscovery']) is not bool or not isinstance(value['approvals'], list) or len(value['approvals']) > 20:
        raise ValueError('Preview approval catalog exceeds its bound')
    rows = [validate(row) for row in value['approvals']]
    if value['privateDiscovery'] and (len({row['repository'] for row in rows}) > 1 or
            any(row['expiresAt'] - row['createdAt'] > PRIVATE_MAX_LIFETIME for row in rows)):
        raise ValueError('Private previews require one repository and a bounded credential lifetime')
    if len({row['instance'] for row in rows}) != len(rows):
        raise ValueError('Preview instances must be unique')
    ownership = value['ownership']
    if not isinstance(ownership, dict) or len(ownership) > 256:
        raise ValueError('Preview namespace authorization exceeds its bound')
    for namespace, entry in ownership.items():
        if (not isinstance(entry, str) or not re.fullmatch('[a-f0-9]{32}:[a-f0-9]{64}', entry) or
                namespace != 'cloudlab-preview-' + entry[:32]):
            raise ValueError('Preview namespace authorization must bind full instance and approval digest')
    artifacts = value['artifacts']
    if not isinstance(artifacts, dict) or len(artifacts) > 20:
        raise ValueError('Preview artifact trust inventory exceeds its bound')
    for image_repository, trust in artifacts.items():
        if (not re.fullmatch(r'[a-z0-9][a-z0-9.-]+/[a-z0-9_./-]+', image_repository) or
                not isinstance(trust, dict) or set(trust) != {'subject', 'issuer', 'sourceRepository', 'public'} or
                trust['public'] is not True or trust['issuer'] != 'https://token.actions.githubusercontent.com' or
                not isinstance(trust['subject'], str) or not re.fullmatch(
                    r'https://github[.]com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/[.]github/workflows/[A-Za-z0-9_.-]+[.]ya?ml@(?:refs/heads/main|[a-f0-9]{40})', trust['subject'])):
            raise ValueError('Preview artifact trust requires an exact approved public signer')
        repository(trust['sourceRepository'])
    for row in rows:
        if ownership.get(names(row)['namespace']) != row['instance'] + ':' + digest(canonical(row)):
            raise ValueError('Preview execution lacks retained administrator namespace authorization')
        if row['definition']['profile'] == 'application':
            trust = artifacts.get(row['image'].split('@')[0])
            if trust is None or trust['sourceRepository'] != row['repository']:
                raise ValueError('Preview application lacks approved source/signature trust')
    return value


def catalog(value):
    return _catalog(value, approval)


def runtime_catalog(value):
    return _catalog(value, stored_approval)


def origin(value):
    host = value['hostname']
    if (not isinstance(host, str) or len(host) > 253 or
            not re.fullmatch(r'[a-z0-9-]+[.]internal[.][a-z0-9.-]+', host) or
            any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in host.split('.'))):
        raise ValueError('Previews require one explicit private hostname')
    zone = host.split('.internal.', 1)[1]
    if value['issuer'] != 'https://login.' + zone + '/realms/applications':
        raise ValueError('Preview identity must use the accepted applications issuer')
    return value


def names(row):
    stored_approval(row)
    # Nonce prevents namespace reuse; full revisions remain in immutable inventory.
    return {'name': 'preview-' + row['instance'], 'namespace': 'cloudlab-preview-' + row['instance'],
            'client': 'preview-' + row['instance'], 'path': '/previews/' + row['instance'] + '/'}


def client(row, settings):
    approval(row)
    origin(settings)
    n = names(row)
    return {'id': n['client'], 'audience': n['client'], 'public': True,
            'callbacks': ['https://' + settings['hostname'] + n['path'] + 'callback'],
            'roles': [], 'scopes': ['profile', 'email']}


def validate_pull(row, pull):
    repository(row['repository'])
    if (type(row.get('repositoryId')) is not int or row['repositoryId'] < 1 or
            type(row.get('pullRequest')) is not int or row['pullRequest'] < 1 or
            not isinstance(row.get('sourceSha'), str) or not re.fullmatch('[a-f0-9]{40}', row['sourceSha'])):
        raise ValueError('Preview revision identity is invalid')
    if (not isinstance(pull, dict) or pull.get('number') != row['pullRequest'] or
            pull.get('state') != 'open' or pull.get('draft') is not False or
            pull.get('base', {}).get('repo', {}).get('id') != row['repositoryId'] or
            pull.get('head', {}).get('repo', {}).get('id') != row['repositoryId'] or
            pull.get('head', {}).get('repo', {}).get('fork') is not False or
            pull.get('base', {}).get('repo', {}).get('full_name') != row['repository'] or
            pull.get('head', {}).get('repo', {}).get('full_name') != row['repository'] or
            pull.get('head', {}).get('sha') != row['sourceSha']):
        raise ValueError('Preview approval does not match an open same-repository revision')


def verify_blob(row, raw):
    if digest(raw) != row['sourceDigest'] or source(raw) != row['definition']:
        raise ValueError('Preview source differs from its approved blob')


def discovery_lease(value):
    if (not isinstance(value, dict) or set(value) != {'token', 'repository', 'repositoryId', 'permissions', 'expiresAt'} or
            not isinstance(value['token'], str) or not value['token'] or '\n' in value['token'] or '\r' in value['token'] or
            type(value['repositoryId']) is not int or value['repositoryId'] < 1 or
            type(value['expiresAt']) is not int or value['expiresAt'] < 1 or
            value['permissions'] != {'contents': 'read', 'pull_requests': 'read', 'metadata': 'read'}):
        raise ValueError('Private discovery requires its bounded read-only repository lease')
    repository(value['repository'])
    return value
