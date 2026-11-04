"""Guard private data binding changes before their sole GitOps writer advances."""
from contextlib import contextmanager
import copy
import hashlib
import json
import re
import sys

sys.path.insert(0, "/opt/cloudlab")

APP = 'cloudlab-data-configuration'
SEAWEED = 'cloudlab-seaweedfs'


def prepare(public, repository, revision, client, catalog=None, *, lookup=None):
    from playbooks.argocd.files.source_snapshot import chart_files
    from playbooks.data.files.native import private_file, render_settings, validate_private_input
    config = public.get('data', {}).get('configuration', {})
    evidence = {'required': config.get('enabled', False), 'enabled': public.get('data', {}).get('enabled', False),
        'repository': public['repository'], 'revision': config.get('revision'),
        'seaweedfsRevision': config.get('seaweedfsRevision'),
        'private_repository': repository, 'private_revision': revision, 'settings': None}
    target = {'valuesRepository': repository, 'valuesRevision': revision}
    validate(evidence, target)
    profile = private_file(client, repository, revision, 'platform/data.yaml', missing=True)
    if profile is None:
        if evidence['required']:
            raise RuntimeError('Native data requires its authenticated private profile')
        evidence['absence'] = {'path': 'platform/data.yaml', 'revision': revision, 'authenticated404': True}
        return validate(evidence, target)
    if catalog is None:
        from playbooks.services.files.inputs import validate_catalog
        catalog = validate_catalog(private_file(client, repository, revision, 'services/catalog.json'), public=public)
    validate_private_input('services/catalog.json', catalog)
    certificates = private_file(client, repository, revision, 'platform/certificates.yaml')
    files = chart_files({'repository': public['repository'], 'revision': evidence['revision'], 'path': 'platform/data/configuration'})
    settings = render_settings(files, [certificates, profile, catalog, {'sharedInputs': True, 'maintenance': False, 'hibernated': False}])
    if lookup is None:
        from playbooks.secrets.files.vault import fields
        lookup = fields
    expected = ((lookup('cnpg-notes-production', ('username', 'database')), settings['applicationRole'], settings['database']),
                (lookup('cnpg-notes-migration', ('username', 'database')), settings['migrationRole'], settings['database']),
                (lookup('cnpg-keycloak', ('username', 'database')), settings['identity']['role'], settings['identity']['database']))
    if (any(row != {'username': role, 'database': database} for row, role, database in expected)
            or lookup('cnpg-backup', ('username',)) != {'username': settings['backupRole']}
            or lookup('s3-notes-production', ('BUCKET',)) != {'BUCKET': settings['bucket']}):
        raise RuntimeError('Data profile differs from its scoped vault metadata')
    from playbooks.data.files.requests import request, resolve
    requested = [request(row['approval']['name'], row['definition']['data'], catalog['dataApprovals'])
                 for row in catalog['catalog'] if row['definition']['data']]
    resolve(requested, lookup)
    evidence['settings'] = settings
    return validate(evidence, target)


def validate(evidence, target, root=None):
    fields = {'required', 'enabled', 'repository', 'revision', 'seaweedfsRevision', 'private_repository', 'private_revision', 'settings'}
    if (not isinstance(evidence, dict) or not fields <= set(evidence) <= fields | {'absence', 'authority'}
            or type(evidence['required']) is not bool or type(evidence['enabled']) is not bool
            or not isinstance(target, dict) or set(target) != {'valuesRepository', 'valuesRevision'}
            or evidence['private_repository'] != target['valuesRepository'] or evidence['private_revision'] != target['valuesRevision']
            or not isinstance(evidence['private_revision'], str) or not re.fullmatch('[a-f0-9]{40}', evidence['private_revision'])
            or (evidence['required'] and not evidence['enabled'])):
        raise RuntimeError('Data activation evidence does not match its approved source')
    pattern = r'https://github[.]com/([A-Za-z0-9-]+)/[A-Za-z0-9_.-]+[.]git'
    public = re.fullmatch(pattern, evidence['repository'] or '')
    private = re.fullmatch(pattern, evidence['private_repository'] or '')
    if not public or not private or public[1].lower() != private[1].lower() or evidence['repository'].lower() == evidence['private_repository'].lower():
        raise RuntimeError('Data activation requires distinct designated public and private sources')
    if evidence['settings'] is not None:
        if (not isinstance(evidence['settings'], dict) or 'absence' in evidence
                or any(not isinstance(evidence[k], str) or not re.fullmatch('[a-f0-9]{40}', evidence[k]) for k in ('revision', 'seaweedfsRevision'))):
            raise RuntimeError('Data activation requires its authenticated pinned projection')
    if 'absence' in evidence and evidence['absence'] != {'path': 'platform/data.yaml', 'revision': target['valuesRevision'], 'authenticated404': True}:
        raise RuntimeError('Data profile absence is not exact authenticated historical evidence')
    if root is not None:
        source = root.get('spec', {}).get('source', {})
        values = source.get('helm', {}).get('valuesObject', {}).get('data', {})
        config = values.get('configuration', {}) if isinstance(values, dict) else None
        if (source.get('repoURL') != evidence['repository'] or source.get('path') != 'gitops/roots/public'
                or root.get('spec', {}).get('sources') or not isinstance(values, dict) or not isinstance(config, dict)
                or ('enabled' in values and (type(values['enabled']) is not bool or values['enabled'] != evidence['enabled']))
                or any(key in config and (type(config[key]) is not type(value) or config[key] != value) for key, value in
                       (('enabled', evidence['required']), ('revision', evidence['revision']), ('seaweedfsRevision', evidence['seaweedfsRevision'])))):
            raise RuntimeError('Data activation conflicts with its reviewed root settings')
    return copy.deepcopy(evidence)


@contextmanager
def exclusion(*, held=False):
    if held:
        yield
    else:
        from playbooks.data.files.control import locked
        with locked():
            yield


def guard(evidence, target, read, root=None, *, patched=False, held=False):
    evidence = validate(evidence, target, root)
    from playbooks.data.files import control
    from playbooks.data.files.native import native_application, quiet, quiet_operation, legacy_guard
    with exclusion(held=held):
        app = read('application.argoproj.io', APP)
        seaweed = read('application.argoproj.io', SEAWEED)
        native = native_application(app) or native_application(seaweed)
        if native and not evidence['required']:
            raise RuntimeError('Data native consumer conflicts with disabled activation')
        if native and (not native_application(app) or not native_application(seaweed)):
            raise RuntimeError('Data activation cannot authorize hybrid source owners')
        if evidence['settings'] is None:
            if 'absence' not in evidence or evidence['required'] or native:
                raise RuntimeError('Data profile absence cannot authorize a native or unknown consumer')
            for obj, name, path in ((app, APP, 'configuration'), (seaweed, SEAWEED, 'seaweedfs')):
                if obj and (not quiet(obj) or obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != control.OWNER
                        or obj.get('spec', {}).get('source', {}).get('repoURL') != evidence['repository']
                        or obj['spec']['source'].get('targetRevision') != 'main'
                        or obj['spec']['source'].get('path') != 'platform/data/' + path):
                    raise RuntimeError('Absent data profile has an ambiguous existing consumer')
            path = control.BASE / 'ownership.json'
            if app or seaweed or path.exists():
                legacy_guard(json.loads(path.read_text()), app or {}, seaweed or {})
            return evidence
        if not app or not seaweed:
            raise RuntimeError('Data activation requires its existing shared data owners')
        state = json.loads((control.BASE / 'ownership.json').read_text())
        if not native:
            legacy_guard(state, app, seaweed)
        saved = evidence.get('authority')
        def idle(obj):
            if patched and saved is not None and native:
                sources = obj.get('spec', {}).get('sources')
                revisions = ([source.get('targetRevision') for source in sources] if sources else
                             [obj.get('spec', {}).get('source', {}).get('targetRevision')])
                return quiet_operation(obj, revisions)
            return quiet(obj)
        if any(not idle(obj) or obj['metadata']['uid'] != state.get('applications', {}).get(name)
               for obj, name in ((app, APP), (seaweed, SEAWEED))):
            raise RuntimeError('Data activation owner identities changed')
        for obj, name in ((app, APP), (seaweed, SEAWEED)):
            meta = obj['metadata']
            if (meta.get('labels', {}).get('cloudlab.io/owner') != ('data-platform' if native else control.OWNER)
                    or (native and meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                        'cloudlab-public-root:argoproj.io/Application:argocd/' + name)):
                raise RuntimeError('Data activation source ownership changed')
        if patched and saved is None:
            raise RuntimeError('Patched data binding has no durable pre-effect absence evidence')
        if saved is not None:
            baseline = saved.get('baseline')
            if not isinstance(baseline, dict) or set(saved.get('specs', {})) != {APP, SEAWEED}:
                raise RuntimeError('Data activation captured baseline is unavailable')
            for obj, name in ((app, APP), (seaweed, SEAWEED)):
                old = saved['specs'][name]
                desired = copy.deepcopy(old)
                if native:
                    if name == APP:
                        desired['sources'][0]['targetRevision'] = evidence['revision']
                        desired['sources'][1]['targetRevision'] = target['valuesRevision']
                    else:
                        desired['source']['targetRevision'] = evidence['seaweedfsRevision']
                if obj['spec'] != old and (not patched or obj['spec'] != desired):
                    raise RuntimeError('Data activation source changed outside its captured transition')
            current = baseline
            if native:
                obj = control.get('configmap', 'cloudlab-data-settings', control.NAMESPACE) or {}
                meta = obj.get('metadata', {})
                if (not state.get('settings_uid') or meta.get('uid') != state['settings_uid']
                        or meta.get('deletionTimestamp') or meta.get('ownerReferences') or meta.get('finalizers')
                        or meta.get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                            APP + ':/ConfigMap:cloudlab-data/cloudlab-data-settings'
                        or set(obj.get('data', {})) != {'settings'} or obj.get('binaryData')):
                    raise RuntimeError('Data activation settings identity changed')
                actual = json.loads(obj['data']['settings'])
                canonical = lambda v: json.dumps(v, sort_keys=True)
                accepted = [canonical(baseline)] + ([canonical(evidence['settings'])] if patched else [])
                if canonical(actual) not in accepted:
                    raise RuntimeError('Data activation settings differ from authenticated old and new projections')
        elif native:
            source = control.operation()
            current = source.settings()
        else:
            for obj, name, path in ((app, APP, 'configuration'), (seaweed, SEAWEED, 'seaweedfs')):
                if (obj['metadata'].get('labels', {}).get('cloudlab.io/owner') != control.OWNER
                        or obj.get('spec', {}).get('source', {}).get('repoURL') != evidence['repository']
                        or obj['spec']['source'].get('targetRevision') != 'main'
                        or obj['spec']['source'].get('path') != 'platform/data/' + path):
                    raise RuntimeError('Data activation legacy source owner changed')
            current = control.settings(False)
        if current.get('maintenance') or current.get('hibernated') or (control.BASE / 'cold-maintenance.json').exists():
            raise RuntimeError('Data activation requires completed operational recovery')
        proposed = evidence['settings']
        keys = ('database', 'applicationRole', 'migrationRole', 'backupRole', 'bucket', 'identity', 's3Host')
        if any(current.get(k) != proposed.get(k) for k in keys):
            raise RuntimeError('Data binding cannot change existing shared identities or endpoint')
        from playbooks.data.files.requests import additions, protect
        protect(proposed.get('serviceRequests', []), proposed)
        added = additions(current.get('serviceRequests', []), proposed.get('serviceRequests', []))
        digest = hashlib.sha256(json.dumps(added, sort_keys=True).encode()).hexdigest()
        authority = {'applications': copy.deepcopy(state['applications']), 'additions': digest, 'absent': [],
            'baseline': copy.deepcopy(current), 'specs': {APP: copy.deepcopy(app['spec']), SEAWEED: copy.deepcopy(seaweed['spec'])}}
        if saved is not None:
            authority['specs'] = copy.deepcopy(saved['specs'])
        if patched and saved is None:
            raise RuntimeError('Patched data binding has no durable pre-effect absence evidence')
        if saved is not None:
            if (not isinstance(saved, dict) or set(saved) != set(authority) or saved['applications'] != authority['applications']
                    or saved['additions'] != digest or not isinstance(saved['absent'], list)):
                raise RuntimeError('Data activation captured authority changed')
        for row in added:
            for kind in ('database', 'bucket'):
                if kind not in row:
                    continue
                name = row[kind]['name']; identity = kind + '/' + name
                if kind == 'database':
                    present = control.sql("SELECT count(*) FROM pg_database WHERE datname='" + name.replace("'", "''") + "';") != '0'
                    owner = control.get('database.postgresql.cnpg.io', row['service'], control.NAMESPACE) if present and patched else None
                    metadata = (owner or {}).get('metadata', {})
                    expected_spec = {'name': name, 'owner': row[kind]['migrationRole'],
                                     'cluster': {'name': 'cloudlab-postgres'}, 'databaseReclaimPolicy': 'retain'}
                    if 'ensure' in (owner or {}).get('spec', {}):
                        expected_spec['ensure'] = 'present'
                    owned = (native and owner is not None and owner.get('apiVersion') == 'postgresql.cnpg.io/v1'
                        and owner.get('kind') == 'Database' and metadata.get('name') == row['service']
                        and metadata.get('namespace') == control.NAMESPACE and metadata.get('uid')
                        and not metadata.get('deletionTimestamp') and type(metadata.get('generation')) is int
                        and owner.get('spec') == expected_spec and owner.get('status', {}).get('applied') is True
                        and owner['status'].get('observedGeneration') == metadata['generation']
                        and app['spec'].get('sources', [{}, {}])[0].get('targetRevision') == evidence['revision']
                        and app['spec']['sources'][1].get('targetRevision') == target['valuesRevision']
                        and metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                            APP + ':postgresql.cnpg.io/Database:cloudlab-data/' + row['service'])

                else:
                    try:
                        from playbooks.data.files.s3 import S3
                        config = json.loads(control.secret('cloudlab-s3-config')['seaweedfs_s3_config'])
                        admin = [row for row in config['identities'] if row['name'] == 'data-admin']
                        if len(admin) != 1 or len(admin[0]['credentials']) != 1:
                            raise RuntimeError('Data pre-effect check requires its unique admin identity')
                        credentials = admin[0]['credentials'][0]
                        S3('https://' + current['s3Host'], credentials['accessKey'], credentials['secretKey']).request('HEAD', name)
                        present = True
                    except control.S3Error as error:
                        if error.status != 404:
                            raise
                        present = False
                    # No Kubernetes owner proves a bucket's origin during recovery.
                    owned = False
                if present and not (patched and saved is not None and identity in saved['absent'] and owned):
                    raise RuntimeError('New data request cannot adopt an existing database or bucket')
                authority['absent'].append(identity)
        if saved is not None and saved != authority:
            raise RuntimeError('Data activation absence evidence differs from its captured scopes')
        evidence['authority'] = authority
        return evidence
