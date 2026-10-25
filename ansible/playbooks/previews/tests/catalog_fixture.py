"""Explicit fixture journal and catalog deltas; no automatic service operations."""
import base64
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets

from playbooks.previews.files.contract import canonical, digest, names, runtime_catalog, repository as validate_repository
from playbooks.keycloak.files.private_source import decode_contents

JOURNALS = Path('/recovery/previews')


def inspect(api, repository):
    validate_repository(repository)
    prefix = 'repos/' + repository
    revision = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Fixture inspection requires an exact main revision')
    blob = api.request('GET', prefix + '/contents/previews/catalog.json?ref=' + revision, missing=True)
    if blob is None:
        return {'revision': revision, 'blob': None, 'raw': None, 'catalog': None}
    raw = decode_contents(blob)
    expected = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    if blob.get('sha') != expected:
        raise ValueError('Fixture catalog bytes do not match the inspected Git blob')
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {'catalog'}:
        raise ValueError('Fixture catalog document differs from its owning schema')
    runtime_catalog(value['catalog'])
    return {'revision': revision, 'blob': expected, 'raw': base64.b64encode(raw).decode(), 'catalog': value['catalog']}


def journal(path, value, *, expected=None):
    """Durable Linux-volume journal; CAS updates cannot overwrite another observation."""
    target = Path(path)
    if (target.name != 'journal.json' or target.parent.parent != JOURNALS or
            not re.fullmatch('[a-f0-9]{32}', target.parent.name)):
        raise ValueError('Fixture journal requires its nonce-owned recovery directory')
    if JOURNALS.is_symlink() or target.parent.is_symlink() or target.is_symlink():
        raise ValueError('Fixture journal has conflicting filesystem ownership')
    JOURNALS.mkdir(exist_ok=True, mode=0o700)
    target.parent.mkdir(exist_ok=True, mode=0o700)
    lock = os.open(target.parent / 'journal.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = target.read_bytes() if target.exists() else None
        if (expected is None and previous is not None) or (expected is not None and (
                previous is None or digest(previous) != expected)):
            raise ValueError('Fixture journal advanced; overwrite refused')
        temporary = target.with_name(target.name + '.' + secrets.token_hex(8))
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            for path in (target.parent, JOURNALS, JOURNALS.parent):
                directory = os.open(path, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)
        return digest(target.read_bytes())
    finally:
        os.close(lock)


def entries(settings, instances):
    if any(not re.fullmatch('[a-f0-9]{32}', instance) for instance in instances):
        raise ValueError('Fixture instances must be immutable nonces')
    rows = {row['instance']: row for row in settings['approvals']}
    return {instance: {'approval': copy.deepcopy(rows.get(instance)),
        'ownership': settings['ownership'].get('cloudlab-preview-' + instance)} for instance in instances}


def require_fixture_only(settings, owned):
    """Task-driven activation must never activate an unrelated catalog entry."""
    runtime_catalog(settings)
    if (any(row['instance'] not in owned for row in settings['approvals']) or
            any(namespace != 'cloudlab-preview-' + value.split(':')[0] or value.split(':')[0] not in owned
                for namespace, value in settings['ownership'].items())):
        raise ValueError('Unrelated preview activation refused')


def update(snapshot, expected, replacements, *, empty=None, absent=()):
    """Change journaled entries only; preserve every current nonfixture field."""
    settings = copy.deepcopy(snapshot['catalog'] if snapshot['catalog'] is not None else empty)
    runtime_catalog(settings)
    if set(replacements) != set(expected) or entries(settings, expected) != expected:
        raise ValueError('Owned fixture entries changed since inspection')
    if not set(absent) <= set(expected):
        raise ValueError('Absence receipts must belong to this fixture journal')
    untouched = [row for row in settings['approvals'] if row['instance'] not in expected]
    for instance, row in replacements.items():
        namespace = 'cloudlab-preview-' + instance
        if row is None:
            # Withdrawal preserves deletion authorization until both namespace and client are absent.
            if instance in absent:
                settings['ownership'].pop(namespace, None)
        else:
            if row['instance'] != instance:
                raise ValueError('Fixture replacement cannot change instance identity')
            if expected[instance]['approval'] is not None and row != expected[instance]['approval']:
                raise ValueError('Changed fixture approval requires a fresh instance')
            untouched.append(copy.deepcopy(row))
            settings['ownership'][names(row)['namespace']] = instance + ':' + digest(canonical(row))
    settings['approvals'] = untouched
    runtime_catalog(settings)
    return {'catalog': settings, 'expectedBase': snapshot['revision']}


def reviewed(snapshot, current, pull, head):
    if (not isinstance(head, str) or not re.fullmatch('[a-f0-9]{40}', head) or
            snapshot != current or pull.get('state') != 'open' or pull.get('draft') is not False or
            pull.get('head', {}).get('sha') != head or pull.get('base', {}).get('sha') != snapshot['revision']):
        raise ValueError('Fixture review is stale; inspect and regenerate before merge')


def restoration(original, current, expected, *, absent):
    result = update(current, expected, {instance: None for instance in expected}, absent=absent)
    settings = result['catalog']
    if settings == original['catalog']:
        return {'expectedBase': current['revision'], 'raw': original['raw']}
    # In particular an originally absent file must survive concurrent user population.
    return {'expectedBase': current['revision'], 'raw': base64.b64encode(
        (json.dumps({'catalog': settings}, sort_keys=True, indent=2) + '\n').encode()).decode()}
