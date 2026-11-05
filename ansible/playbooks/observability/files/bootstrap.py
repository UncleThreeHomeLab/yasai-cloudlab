"""Bounded Argo declarations; charts and retained controllers own runtime fields."""
import fcntl
import copy
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from playbooks.istio.files.kube import get, kube, contains, application_ready, wait, condition
try:
    from playbooks.observability.files import writer_guard
except ModuleNotFoundError:
    import writer_guard  # Installed beside this standalone VM module.

NAMESPACE = 'cloudlab-observability'
OWNER = 'observability-platform'
COMPONENTS = ('prometheus', 'loki', 'tempo', 'alloy', 'kiali')


def application(payload, name):
    configuration = name == 'configuration'
    values = payload['configuration'] if configuration else payload['components'][name]
    helm = {'releaseName': 'cloudlab-observability' if configuration else 'cloudlab-' + name}
    if not configuration: helm['valueFiles'] = ['values.json']
    if values: helm['valuesObject'] = values
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': 'cloudlab-observability' if configuration else 'cloudlab-' + name,
                     'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': 'cloudlab-observability', 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['revision'], 'path': 'platform/observability' + ('' if configuration else '/' + name),
            'helm': helm},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'revisionHistoryLimit': 0 if name == 'prometheus' else 10,
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '10s', 'factor': 2, 'maxDuration': '1m'}}}}}


def history_patches(current):
    """Retain newest controller history; Git remains the recovery source."""
    history = current.get('status', {}).get('history', [])
    metadata, spec = current['metadata'], current['spec']
    source = spec['source']
    if (metadata.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            metadata.get('ownerReferences') or metadata.get('finalizers') or metadata.get('deletionTimestamp') or
            metadata.get('namespace') != 'argocd' or metadata.get('name') != 'cloudlab-prometheus' or
            spec.get('project') != 'cloudlab-observability' or
            source.get('path') != 'platform/observability/prometheus' or
            spec.get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE} or
            any(row.get('source', {}).get('repoURL') != source.get('repoURL') or
                row.get('source', {}).get('path') != source['path'] for row in history)):
        raise RuntimeError('Telemetry history retention refuses foreign ownership or source')
    changes = ([{'op': 'add', 'path': '/spec/revisionHistoryLimit', 'value': 0}]
               if spec.get('revisionHistoryLimit') != 0 else [])
    changes += [{'op': 'remove', 'path': '/status/history/0'} for _ in history[:-1]]
    if not changes:
        return []
    return [{'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']}] + changes


def compact_history():
    # Recovery can unblock the controller while the normal owner waits for sync.
    with Path(writer_guard.HISTORY_LOCK).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inspected = writer_guard.inspect(get)['cloudlab-prometheus']
        if inspected is None:
            raise RuntimeError('Telemetry history Application absent; retry after bootstrap')
        current = get('application.argoproj.io', 'cloudlab-prometheus', 'argocd')
        writer_guard.check_child(current, 'cloudlab-prometheus', inspected['spec']['source']['repoURL'])
        if current is None:
            raise RuntimeError('Telemetry history Application absent; retry after bootstrap')
        if current['metadata']['uid'] != inspected['metadata']['uid']:
            raise RuntimeError('Telemetry history Application replaced; inspect ownership before retrying')
        patches = history_patches(current)
        if patches:
            writer_guard.check_fence()
            kube('patch', 'application.argoproj.io', 'cloudlab-prometheus', '-n', 'argocd',
                 '--type=json', '-p', json.dumps(patches))
        return {'changed': bool(patches), 'controller_history_disabled': True}


def seed(payload, name):
    desired = application(payload, name)
    if len(json.dumps(desired['spec']['source']).encode()) > 320 * 1024:
        raise ValueError('Telemetry inline source exceeds its bounded controller update budget')
    writer_guard.inspect(get, payload['repository'])
    current = get('application.argoproj.io', desired['metadata']['name'], 'argocd')
    writer_guard.check_child(current, desired['metadata']['name'], payload['repository'])
    changed = not current or not contains(current, desired)
    if changed:
        writer_guard.check_fence()
        if not current:
            kube('create', '--field-manager=' + OWNER, '-f', '-', document=desired)
        else:
            # Large historical objects can lose SSA metadata; update only our declared fields.
            patches = [{'op': 'test', 'path': '/metadata/uid', 'value': current['metadata']['uid']},
                       {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']}]
            patches += [{'op': 'add', 'path': '/spec/' + key, 'value': value}
                        for key, value in desired['spec'].items() if not contains(current['spec'].get(key), value)]
            kube('patch', 'application.argoproj.io', desired['metadata']['name'], '-n', 'argocd',
                 '--type=json', '--field-manager=' + OWNER, '--patch-file', '/dev/stdin', document=patches)
    def ready():
        if name != 'configuration': return application_ready(desired['metadata']['name'], payload['revision'])
        # Private routes cannot resolve backend references before child charts exist.
        actual = get('application.argoproj.io', desired['metadata']['name'], 'argocd') or {}
        return (actual.get('status', {}).get('sync', {}).get('status') == 'Synced' and
                actual.get('status', {}).get('sync', {}).get('revision') == payload['revision'] and
                contains(actual.get('status', {}).get('sync', {}).get('comparedTo', {}).get('source', {}), desired['spec']['source']) and
                actual.get('status', {}).get('operationState', {}).get('phase') == 'Succeeded' and not actual.get('operation') and
                not any(condition['type'].endswith('Error') for condition in actual.get('status', {}).get('conditions', [])))
    wait(ready, 'telemetry chart convergence', timeout=900)
    return changed


def run(payload):
    if set(payload) != {'repository', 'revision', 'configuration', 'components'} or set(payload['components']) != set(COMPONENTS):
        raise ValueError('Telemetry requires its complete committed configuration')
    payload = copy.deepcopy(payload)
    with Path(writer_guard.MAIN_LOCK).open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        writer_guard.inspect(get, payload['repository'])
        for kind, name in (('namespace', NAMESPACE), ('storageclass', 'cloudlab-telemetry')):
            current = get(kind, name)
            if current and current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
                raise RuntimeError('Existing telemetry boundary has another owner')
        # First configuration cannot create monitors before their retained APIs exist.
        payload['configuration']['monitoringEnabled'] = bool(get('crd', 'podmonitors.monitoring.coreos.com') and
                                                            get('crd', 'servicemonitors.monitoring.coreos.com'))
        changed = seed(payload, 'configuration')
        wait(lambda: all(condition(get('externalsecret.external-secrets.io', name, NAMESPACE), 'Ready')
                         for name in ('grafana-emergency', 'grafana-oidc', 'kiali-signing-key', 'kiali-oidc')),
             'telemetry ESO credentials', timeout=300)
        for name in COMPONENTS:
            changed = seed(payload, name) or changed
        if not payload['configuration']['monitoringEnabled']:
            payload['configuration']['monitoringEnabled'] = True
            changed = seed(payload, 'configuration') or changed
        wait(lambda: application_ready('cloudlab-observability', payload['revision']),
             'complete telemetry boundaries', timeout=300)
        return {'changed': changed, 'owner': 'argocd', 'components': len(COMPONENTS), 'offsite_backup': False}


if __name__ == '__main__':
    try:
        if sys.argv[1:] == ['--guard-probe']:
            with Path(writer_guard.MAIN_LOCK).open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                writer_guard.inspect(get)
            result = {'changed': False, 'legacy_writer_authorized': True}
        else:
            result = compact_history() if sys.argv[1:] == ['--compact-history'] else run(json.load(sys.stdin))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        raise SystemExit('Telemetry authority or convergence check failed; inspect ownership and locks before retrying; existing state retained') from None
