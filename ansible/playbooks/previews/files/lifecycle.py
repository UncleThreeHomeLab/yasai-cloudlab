"""Irreversible preview retirement decisions and deletion ownership checks."""
import copy

try:
    from .contract import OWNER, MAX_ACTIVE, GENERATED_CONFIGMAPS, approval, stored_approval, obsolete, canonical, digest, names
except ImportError:
    from contract import OWNER, MAX_ACTIVE, GENERATED_CONFIGMAPS, approval, stored_approval, obsolete, canonical, digest, names


def retirement(row, desired, pull, now):
    stored_approval(row)
    if obsolete(row):
        return 'platform-image-changed'
    if now >= row['expiresAt']:
        return 'expired'
    if desired is None:
        return 'orphan'
    if canonical(desired) != canonical(row):
        raise ValueError('Preview approval mutation requires a new instance')
    if pull is None:
        return None
    base = pull.get('base', {}).get('repo', {})
    head = pull.get('head', {}).get('repo', {})
    if (pull.get('number') != row['pullRequest'] or base.get('id') != row['repositoryId'] or
            base.get('full_name') != row['repository'] or pull.get('state') not in ('open', 'closed')):
        raise ValueError('Preview discovery returned incomplete identity')
    if pull['state'] == 'closed':
        return 'closed'
    if (head.get('id') != row['repositoryId'] or head.get('fork') is not False or
            head.get('full_name') != row['repository'] or pull.get('head', {}).get('sha') != row['sourceSha'] or
            pull.get('draft') is not False):
        return 'revision-unapproved'
    return None


def record_approval(instance, record):
    row = stored_approval(record['approval'])
    if instance != row['instance'] or record['approvalDigest'] != digest(canonical(row)):
        raise ValueError('Stored preview instance or approval digest changed')
    return row


def enroll(state, row, now):
    approval(row)
    state = copy.deepcopy(state)
    current = state['entries'].get(row['instance'])
    if current:
        if current['approvalDigest'] != digest(canonical(row)):
            raise ValueError('Preview instance cannot be reused or changed')
        return state
    if not row['createdAt'] <= now < row['expiresAt']:
        raise ValueError('Preview approval is not currently valid')
    if sum(entry['phase'] != 'retired' for entry in state['entries'].values()) >= MAX_ACTIVE:
        raise ValueError('Preview capacity includes pending and retiring instances')
    if len(state['entries']) >= 256:
        raise ValueError('Preview tombstone capacity reached; explicit owner maintenance required')
    state['entries'][row['instance']] = {'approval': row, 'approvalDigest': digest(canonical(row)),
        'phase': 'pending', 'resources': [], 'createdAt': now}
    return state


def owned(obj, row, state_uid, expected_uid=None):
    meta = obj.get('metadata', {})
    n = names(row)
    if (meta.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            meta.get('labels', {}).get('cloudlab.io/preview-instance') != row['instance'] or
            meta.get('annotations', {}).get('cloudlab.io/approval-digest') != digest(canonical(row)) or
            meta.get('annotations', {}).get('cloudlab.io/runtime-state-uid') != state_uid or
            not meta.get('uid') or not meta.get('resourceVersion') or
            (expected_uid is not None and meta['uid'] != expected_uid)):
        raise ValueError('Preview resource identity or ownership changed')
    if obj.get('kind') == 'Namespace' and meta.get('name') != n['namespace']:
        raise ValueError('Preview namespace identity differs')
    return obj


def namespace_disposable(objects, roots, namespace_uid):
    """Every remaining object must follow a verified owner chain; unknown data blocks."""
    if not namespace_uid:
        raise ValueError('Preview namespace inventory requires its immutable UID')
    known = set(roots)
    remaining = list(objects)
    for obj in remaining:
        meta = obj.get('metadata', {})
        if (obj['kind'] in ('PersistentVolumeClaim', 'PersistentVolume', 'ExternalSecret', 'Secret', 'StatefulSet') or
                meta.get('finalizers') not in (None, [], ['foregroundDeletion']) or
                meta.get('annotations', {}).get('cloudlab.io/retention') or
                meta.get('annotations', {}).get('helm.sh/resource-policy') == 'keep' or
                any('retain' in str(value).lower() for key, value in meta.get('annotations', {}).items()
                    if key.endswith('/retention'))):
            raise ValueError('Unexpected data or retained resource blocks preview namespace deletion')
    while remaining:
        progress = False
        for obj in remaining[:]:
            meta = obj['metadata']
            uid = meta.get('uid')
            generated = ((obj['kind'] == 'ServiceAccount' and meta['name'] == 'default') or
                         (obj['kind'] == 'ConfigMap' and meta['name'] in GENERATED_CONFIGMAPS) or
                         obj['kind'] in ('Event',))
            refs = meta.get('ownerReferences', [])
            if uid in known or generated or (refs and all(ref.get('uid') in known for ref in refs)):
                if not uid:
                    raise ValueError('Preview inventory object lacks a UID')
                known.add(uid)
                remaining.remove(obj)
                progress = True
        if not progress:
            raise ValueError('Foreign or untracked objects block preview namespace deletion')
    return True
