"""Read-only administrator preservation before an approved identity binding advances."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re
import stat

APP = 'cloudlab-access'
BINDING = 'cloudlab-tailnet-administrator'
RECEIPT = Path('/var/lib/cloudlab/connectivity/ownership.json')
TRACKING = 'cloudlab-public-root:argoproj.io/Application:argocd/' + APP


def prepare(public, repository, revision, client):
    """Every candidate commit is read, including when native access is disabled."""
    import yaml
    try:
        from .github_setup import repository as repo_name
    except ImportError:
        from github_setup import repository as repo_name
    config = public.get('access', {}).get('configuration', {})
    evidence = {'required': config.get('enabled'), 'enabled': public.get('access', {}).get('enabled'),
        'repository': public.get('repository'), 'revision': config.get('revision'),
        'private_repository': repository, 'private_revision': revision, 'administratorHash': None}
    target = {'valuesRepository': repository, 'valuesRevision': revision}
    validate(evidence, target)
    document = client.request('GET', 'repos/' + repo_name(repository) + '/contents/platform/access.yaml?ref=' + revision, missing=True)
    if document is not None:
        if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
                or type(document.get('size')) is not int or not 0 < document['size'] <= 4096
                or not isinstance(document.get('content'), str) or len(document['content']) > 8192):
            raise RuntimeError('Access declaration requires a bounded regular file')
        try:
            raw = base64.b64decode(document['content'].replace('\r', '').replace('\n', ''), validate=True)
            if len(raw) != document['size'] or len(raw) > 4096:
                raise ValueError()
            node = yaml.compose(raw)
            if not isinstance(node, yaml.MappingNode) or len(node.value) != 1:
                raise ValueError()
            selected = yaml.safe_load(raw)
            if (not isinstance(selected, dict) or set(selected) != {'administrator'}
                    or not isinstance(selected['administrator'], str)
                    or not 3 <= len(selected['administrator']) <= 254
                    or not re.fullmatch(r'[^\s@]+@[^\s@]+', selected['administrator'])):
                raise ValueError()
            evidence['administratorHash'] = hashlib.sha256(selected['administrator'].encode()).hexdigest()
        except Exception:
            raise RuntimeError('Access declaration violates its approved schema') from None
    return validate(evidence, target)


def validate(evidence, target, root=None):
    fields = {'required', 'enabled', 'repository', 'revision', 'private_repository', 'private_revision', 'administratorHash'}
    if (not isinstance(evidence, dict) or not fields <= set(evidence) <= fields | {'authority'}
            or type(evidence['required']) is not bool or type(evidence['enabled']) is not bool
            or not isinstance(target, dict) or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository']
            or evidence['private_revision'] != target['valuesRevision']
            or any(not isinstance(evidence[k], str) or not re.fullmatch('[a-f0-9]{40}', evidence[k])
                   for k in ('revision', 'private_revision'))
            or (evidence['administratorHash'] is not None and (not isinstance(evidence['administratorHash'], str)
                or not re.fullmatch('[a-f0-9]{64}', evidence['administratorHash'])))
            or (evidence['required'] and not evidence['enabled'])):
        raise RuntimeError('Access activation evidence does not match its approved source')
    pattern = r'https://github[.]com/([A-Za-z0-9-]+)/[A-Za-z0-9_.-]+[.]git'
    public = re.fullmatch(pattern, evidence['repository']) if isinstance(evidence['repository'], str) else None
    private = re.fullmatch(pattern, evidence['private_repository']) if isinstance(evidence['private_repository'], str) else None
    if not public or not private or public[1].lower() != private[1].lower() or evidence['repository'].lower() == evidence['private_repository'].lower():
        raise RuntimeError('Access activation requires its designated public and private sources')
    authority = evidence.get('authority')
    if authority is not None and (evidence['administratorHash'] is None or not isinstance(authority, dict)
            or set(authority) != {'application_uid', 'binding_uid'}
            or any(not isinstance(value, str) or not value for value in authority.values())):
        raise RuntimeError('Captured access authority identities are invalid')
    if root is not None:
        source = root.get('spec', {}).get('source', {})
        overrides = source.get('helm', {}).get('valuesObject', {}).get('access', {})
        if (not isinstance(overrides, dict) or source.get('repoURL') != evidence['repository']
                or source.get('path') != 'gitops/roots/public' or root.get('spec', {}).get('sources')
                or ('enabled' in overrides and (type(overrides['enabled']) is not bool or overrides['enabled'] != evidence['enabled']))):
            raise RuntimeError('Access activation differs from the public root')
        config = overrides.get('configuration', {})
        if (not isinstance(config, dict) or any(k in config and (type(config[k]) is not type(v) or config[k] != v)
                for k, v in (('enabled', evidence['required']), ('revision', evidence['revision'])))):
            raise RuntimeError('Access activation conflicts with a public root override')
    return copy.deepcopy(evidence)


def receipt():
    """Only the root-owned, private server checkpoint is an authority source."""
    for path in (*reversed(RECEIPT.parents), RECEIPT):
        info = path.lstat()
        if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode)
                or (path == RECEIPT and (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600))
                or (path != RECEIPT and (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022))):
            raise RuntimeError('Access authority receipt has unsafe ownership or permissions')
    state = json.loads(RECEIPT.read_text())
    if (not isinstance(state, dict) or state.get('phase') != 'configured'
            or not isinstance(state.get('application_uid'), str) or not state['application_uid']
            or not isinstance(state.get('administrator'), str) or not re.fullmatch('[a-f0-9]{64}', state['administrator'])):
        raise RuntimeError('Configured access authority receipt is unavailable')
    return state


def guard(evidence, target, read, root=None):
    evidence = validate(evidence, target, root)
    app = read('application.argoproj.io', APP)
    meta = (app or {}).get('metadata', {})
    tracking = meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id')
    native = (app is not None and 'sources' in app.get('spec', {}) and app['spec']['sources'] is not None) or tracking is not None or meta.get('labels', {}).get('cloudlab.io/owner') == 'access-platform'
    if evidence['administratorHash'] is None:
        if evidence['required'] or native:
            raise RuntimeError('Access declaration absence cannot authorize a native consumer')
        if app and (meta.get('labels', {}).get('cloudlab.io/owner') != 'cloudlab-access-bootstrap'
                or not meta.get('uid') or meta.get('deletionTimestamp') or meta.get('finalizers') or meta.get('ownerReferences')
                or app.get('spec', {}).get('source', {}).get('repoURL') != evidence['repository']
                or app.get('spec', {}).get('source', {}).get('path') != 'platform/connectivity/access'):
            raise RuntimeError('Absent access declaration has an ambiguous consumer')
        return evidence
    state = receipt()
    if (not app or meta.get('uid') != state['application_uid'] or meta.get('deletionTimestamp')
            or meta.get('finalizers') or meta.get('ownerReferences')
            or (native and (not evidence['required'] or tracking != TRACKING or meta.get('labels', {}).get('cloudlab.io/owner') != 'access-platform'))
            or (not native and (meta.get('labels', {}).get('cloudlab.io/owner') != 'cloudlab-access-bootstrap'
                or app.get('spec', {}).get('source', {}).get('repoURL') != evidence['repository']
                or app.get('spec', {}).get('source', {}).get('path') != 'platform/connectivity/access'))
            or state['administrator'] != evidence['administratorHash']):
        raise RuntimeError('Access declaration cannot change the configured administrator or owner')
    metadata = administrator_binding(state, read)
    authority = {'application_uid': meta['uid'], 'binding_uid': metadata['uid']}
    if evidence.get('authority', authority) != authority:
        raise RuntimeError('Captured access authority identity changed')
    evidence['authority'] = authority
    return evidence


def administrator_binding(state, read):
    binding = read('clusterrolebinding.rbac.authorization.k8s.io', BINDING) or {}
    metadata = binding.get('metadata', {})
    subjects = binding.get('subjects', [])
    if (not metadata.get('uid') or metadata.get('deletionTimestamp') or metadata.get('ownerReferences') or metadata.get('finalizers')
            or metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') != APP + ':rbac.authorization.k8s.io/ClusterRoleBinding:tailscale/' + BINDING
            or binding.get('roleRef') != {'apiGroup': 'rbac.authorization.k8s.io', 'kind': 'ClusterRole', 'name': 'cluster-admin'}
            or not isinstance(subjects, list) or len(subjects) != 1 or not isinstance(subjects[0], dict)
            or set(subjects[0]) != {'kind', 'apiGroup', 'name'}
            or subjects[0]['kind'] != 'User' or subjects[0]['apiGroup'] != 'rbac.authorization.k8s.io'
            or not isinstance(subjects[0]['name'], str)
            or hashlib.sha256(subjects[0]['name'].encode()).hexdigest() != state['administrator']):
        raise RuntimeError('Live administrator binding differs from its configured authority')
    return metadata
