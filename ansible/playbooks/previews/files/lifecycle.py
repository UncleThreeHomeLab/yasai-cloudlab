"""Irreversible preview retirement decisions and deletion ownership checks."""
import copy

try:
    from .contract import OWNER, MAX_ACTIVE, GENERATED_CONFIGMAPS, ORIGIN_VERSION, approval, stored_approval, obsolete, canonical, digest, names
    from .kube import NamespaceInventory, POD_METRICS
except ImportError:
    from contract import OWNER, MAX_ACTIVE, GENERATED_CONFIGMAPS, ORIGIN_VERSION, approval, stored_approval, obsolete, canonical, digest, names
    from kube import NamespaceInventory, POD_METRICS


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
        'phase': 'pending', 'resources': [], 'createdAt': now, 'originVersion': ORIGIN_VERSION}
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


def backing_object(objects, kind, namespace, name, known):
    matches = [obj for obj in objects if obj.get('apiVersion') == 'v1' and obj.get('kind') == kind and
               obj.get('metadata', {}).get('namespace') == namespace and obj['metadata'].get('name') == name]
    if len(matches) > 1:
        raise ValueError('Native inventory backing identity is ambiguous')
    if matches and matches[0]['metadata'].get('uid') in known:
        return matches[0]
    return None


def native_endpoints(obj, objects, known):
    meta = obj['metadata']; namespace = meta['namespace']
    labels = meta.get('labels', {})
    if (obj.get('apiVersion') != 'v1' or not isinstance(meta.get('uid'), str) or not meta['uid'] or
            not isinstance(labels, dict) or labels.get('endpoints.kubernetes.io/managed-by') != 'endpoint-controller'):
        raise ValueError('Endpoints lack their exact native identity')
    service = backing_object(objects, 'Service', namespace, meta['name'], known)
    if service is None:
        return False
    spec = service.get('spec', {})
    if not isinstance(spec, dict):
        raise ValueError('Native Endpoints Service is malformed')
    selector = spec.get('selector')
    if (spec.get('type') == 'ExternalName' or not isinstance(selector, dict) or not selector or
            any(not isinstance(key, str) or not key or not isinstance(value, str) for key, value in selector.items())):
        raise ValueError('Native Endpoints require a selector-backed Service')
    subsets = obj.get('subsets', [])
    if not isinstance(subsets, list):
        raise ValueError('Native Endpoints subsets are malformed')
    for subset in subsets:
        if not isinstance(subset, dict):
            raise ValueError('Native Endpoints subset is malformed')
        for field in ('addresses', 'notReadyAddresses'):
            addresses = subset.get(field, [])
            if not isinstance(addresses, list):
                raise ValueError('Native Endpoints addresses are malformed')
            for address in addresses:
                if not isinstance(address, dict) or not isinstance(address.get('targetRef'), dict):
                    raise ValueError('Native Endpoints address target is malformed')
                target = address.get('targetRef', {})
                if (target.get('kind') != 'Pod' or target.get('apiVersion', '') not in ('', 'v1') or
                        target.get('namespace') != namespace or
                        any(not isinstance(target.get(key), str) or not target[key] for key in ('name', 'uid'))):
                    raise ValueError('Native Endpoints target identity differs')
                pod = backing_object(objects, 'Pod', namespace, target['name'], known)
                if pod is None:
                    return False
                pod_labels = pod['metadata'].get('labels', {})
                if (pod['metadata'].get('uid') != target['uid'] or not isinstance(pod_labels, dict) or
                        any(pod_labels.get(key) != value for key, value in selector.items())):
                    raise ValueError('Native Endpoints target differs from its selected Pod')
                status = pod.get('status', {})
                if not isinstance(status, dict):
                    raise ValueError('Native Endpoints Pod status is malformed')
                pod_ips = status.get('podIPs', [])
                if (not isinstance(pod_ips, list) or
                        any(not isinstance(item, dict) or not isinstance(item.get('ip'), str) for item in pod_ips)):
                    raise ValueError('Native Endpoints Pod addresses are malformed')
                if not address.get('ip') or address['ip'] not in [status.get('podIP'), *(item['ip'] for item in pod_ips)]:
                    raise ValueError('Native Endpoints address differs from its Pod')
    return True


def namespace_disposable(objects, roots, namespace_uid):
    """Every remaining object must follow a verified owner chain; unknown data blocks."""
    if not namespace_uid:
        raise ValueError('Preview namespace inventory requires its immutable UID')
    known = set(roots)
    remaining = list(objects)
    for obj in remaining:
        if not isinstance(obj, dict) or not isinstance(obj.get('metadata'), dict):
            raise ValueError('Preview namespace inventory metadata is malformed')
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
            if obj['kind'] in ('Endpoints', 'PodMetrics'):
                if (meta.get('ownerReferences', []) != [] or
                        any(not isinstance(meta.get(key), str) or not meta[key] for key in ('name', 'namespace'))):
                    raise ValueError('Native inventory leaf metadata differs')
                if obj['kind'] == 'PodMetrics':
                    if (not isinstance(objects, NamespaceInventory) or id(obj) not in objects.pod_metrics or
                            (obj.get('apiVersion'), obj['kind']) != POD_METRICS):
                        raise ValueError('Pod metrics lack their accepted discovery identity')
                    accepted = backing_object(objects, 'Pod', meta['namespace'], meta['name'], known) is not None
                else:
                    accepted = native_endpoints(obj, objects, known)
                if accepted:
                    remaining.remove(obj)
                    progress = True
                continue
            generated = ((obj['kind'] == 'ServiceAccount' and meta['name'] == 'default') or
                         (obj['kind'] == 'ConfigMap' and meta['name'] in GENERATED_CONFIGMAPS) or
                         obj['kind'] in ('Event',))
            refs = meta.get('ownerReferences', [])
            if any(ref.get('kind') in ('Endpoints', 'PodMetrics') for ref in refs):
                raise ValueError('Native inventory leaves cannot authorize descendants')
            if uid in known or generated or (refs and all(ref.get('uid') in known for ref in refs)):
                if not uid:
                    raise ValueError('Preview inventory object lacks a UID')
                known.add(uid)
                remaining.remove(obj)
                progress = True
        if not progress:
            raise ValueError('Foreign or untracked objects block preview namespace deletion')
    return True
