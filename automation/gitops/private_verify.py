"""Private GitOps convergence and retained-resource fixtures; sanitized output only."""
import copy
import base64
import fcntl
import json
import os
import sys
import time
import uuid

from bootstrap import BASE, get, kube
from private_bootstrap import run as configure, remove
from private_sources import resources
from source_transition import record
from controller_stability import fingerprint, sample as foundation_sample


def wait(check, description, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(3)
    raise RuntimeError('Private GitOps ' + description + ' failed; diagnostics withheld')


def healthy(name):
    app = get('application.argoproj.io', name) or {}
    status = app.get('status', {})
    return (status.get('sync', {}).get('status') == 'Synced' and
            bool(status.get('sync', {}).get('revision')) and
            status.get('health', {}).get('status') == 'Healthy' and
            not app.get('operation') and
            not any(c['type'].endswith('Error') for c in status.get('conditions', [])) and
            # Reattaching retained, already matching resources needs no sync
            # operation. A resolved revision and converged comparison suffice.
            status.get('operationState', {}).get('phase') in (None, 'Succeeded'))


def mutate(name, document):
    kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=merge', '-p', json.dumps(document))


def credential_failure(name, workload, uid):
    """Use an isolated project/credential; never corrupt an ESO-owned Secret."""
    probe = 'cloudlab-private-credential-check'
    label = {'cloudlab.io/verification': 'private-credential-check'}
    kinds = ('application.argoproj.io', 'secret', 'appproject.argoproj.io', 'namespace')

    def cleanup():
        # Inspect all owners before deleting anything, including interrupted runs.
        existing = [(kind, get(kind, probe)) for kind in kinds]
        for kind, obj in existing:
            if obj and (obj['metadata'].get('labels', {}).get('cloudlab.io/verification') !=
                        'private-credential-check' or obj['metadata'].get('ownerReferences') or
                        (kind != 'namespace' and obj['metadata'].get('finalizers'))):
                raise RuntimeError('Private credential fixture cleanup ownership mismatch')
        for kind, obj in existing:
            if obj:
                kube('delete', kind, probe, '-n', 'argocd', '--wait=true', '--timeout=60s')

    def metadata(namespace=True):
        return {'name': probe, 'labels': label, **({'namespace': 'argocd'} if namespace else {})}

    def retained():
        raw = kube('get', 'configmap', 'cloudlab-private-fixture', '-n', probe,
                   '--ignore-not-found', '-o', 'json')
        return json.loads(raw) if raw.strip() else {}

    cleanup()
    secret = get('secret', name)
    app = get('application.argoproj.io', name)
    if not secret or not healthy(name):
        raise RuntimeError('Private credential fixture requires a healthy source')
    original_data = copy.deepcopy(secret['data'])
    probe_data = dict(original_data, project=base64.b64encode(probe.encode()).decode())
    invalid = 'intentionally-invalid-private-fixture-key'
    invalid_data = base64.b64encode(invalid.encode()).decode()
    try:
        namespace = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': metadata(False)}
        namespace['metadata']['labels'] = dict(label, **{'pod-security.kubernetes.io/enforce': 'restricted'})
        project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': metadata(),
                   'spec': {'sourceRepos': [app['spec']['source']['repoURL']],
                            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': probe}],
                            'clusterResourceWhitelist': [],
                            'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}}
        credential = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata(),
                      'type': 'Opaque', 'data': probe_data}
        credential['metadata']['labels'] = dict(label, **{'argocd.argoproj.io/secret-type': 'repository'})
        application = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(),
                       'spec': {'project': probe, 'source': copy.deepcopy(app['spec']['source']),
                                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': probe},
                                'syncPolicy': {'automated': {'prune': False, 'selfHeal': True}}}}
        for obj in (namespace, project, credential, application):
            kube('create', '-f', '-', document=obj)
        wait(lambda: healthy(probe) and retained().get('data') == {'proof': 'private-source-converged'},
             'isolated credential baseline')
        probe_uid = retained()['metadata']['uid']
        mutate(probe, {'spec': {'syncPolicy': {'automated': None}}})
        kube('patch', 'secret', probe, '-n', 'argocd', '--type=merge',
             '-p', json.dumps({'data': {'githubAppPrivateKey': invalid_data}}))
        mutate(probe, {'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
        wait(lambda: any(c['type'] == 'ComparisonError' and
                        any(text in c.get('message', '').lower() for text in
                            ('private key', 'pem encoded', 'invalid key')) for c in
                        (get('application.argoproj.io', probe) or {}).get('status', {}).get('conditions', [])),
             'credential failure detection')
        if retained().get('metadata', {}).get('uid') != probe_uid or (workload() or {}).get('metadata', {}).get('uid') != uid:
            raise RuntimeError('Private credential failure did not retain its workload')
        if not all(healthy(root) for root in ('cloudlab-public-root', 'cloudlab-argocd', name)):
            raise RuntimeError('Private credential failure disrupted public convergence')
        kube('patch', 'secret', probe, '-n', 'argocd', '--type=merge',
             '-p', json.dumps({'data': probe_data}))
        mutate(probe, {'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
        wait(lambda: healthy(probe), 'isolated credential recovery')
        if retained().get('metadata', {}).get('uid') != probe_uid:
            raise RuntimeError('Private credential recovery replaced its workload')
        if (get('secret', name) or {}).get('data') != original_data:
            raise RuntimeError('Working private credential changed during isolated proof')
    finally:
        cleanup()


def fixture(entry, payload):
    name = 'cloudlab-private-' + entry['name']
    def configmap():
        raw = kube('get', 'configmap', 'cloudlab-private-fixture', '-n', name, '--ignore-not-found', '-o', 'json')
        return json.loads(raw) if raw.strip() else None
    current = configmap()
    if (not current or current['metadata'].get('labels', {}).get('cloudlab.io/verification') != 'gitops-private-fixture'
            or current.get('data') != {'proof': 'private-source-converged'}):
        raise RuntimeError('Private fixture content or ownership is invalid')
    uid = current['metadata']['uid']
    kube('patch', 'configmap', 'cloudlab-private-fixture', '-n', name, '--type=merge',
         '-p', '{"data":{"proof":"drift-fixture"}}')
    wait(lambda: (configmap() or {}).get('data') == {'proof': 'private-source-converged'}, 'drift repair')
    try:
        mutate(name, {'spec': {'source': {'path': 'intentionally-missing-private-fixture'}},
                      'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
        wait(lambda: any(c['type'] == 'ComparisonError' for c in
                         (get('application.argoproj.io', name) or {}).get('status', {}).get('conditions', [])),
             'source failure detection')
        if (configmap() or {}).get('metadata', {}).get('uid') != uid:
            raise RuntimeError('Private source failure did not retain its workload')
    finally:
        mutate(name, {'spec': {'source': {'path': entry['path']}},
                      'metadata': {'annotations': {'argocd.argoproj.io/refresh': 'hard'}}})
    wait(lambda: healthy(name), 'source recovery')
    credential_failure(name, configmap, uid)
    for denial in ('source', 'namespace'):
        app = copy.deepcopy(resources(entry, payload['store'])[-1])
        app['metadata']['name'] = 'cloudlab-private-denied-' + uuid.uuid4().hex[:8]
        app['spec'].pop('syncPolicy')
        if denial == 'source':
            app['spec']['source']['repoURL'] = 'https://github.com/example/forbidden.git'
            expected = 'is not permitted in project'
        else:
            app['spec']['destination']['namespace'] = 'argocd'
            expected = 'do not match any of the allowed destinations'
        kube('create', '-f', '-', document=app)
        try:
            wait(lambda: any(c['type'] == 'InvalidSpecError' and expected in c.get('message', '') for c in
                (get('application.argoproj.io', app['metadata']['name']) or {}).get('status', {}).get('conditions', [])),
                denial + ' denial')
        finally:
            kube('delete', 'application.argoproj.io', app['metadata']['name'], '-n', 'argocd', '--wait=true')
    try:
        configure(dict(payload, sources=[]))
        if not get('application.argoproj.io', name):
            raise RuntimeError('Omitting private input deleted its root')
        remove(dict(payload, sources=[x for x in payload['sources'] if x['name'] != entry['name']], remove=entry['name']))
        if (configmap() or {}).get('metadata', {}).get('uid') != uid:
            raise RuntimeError('Private root removal did not retain its workload')
    finally:
        configure(payload)
    wait(lambda: healthy(name), 'reattachment')
    if (configmap() or {}).get('metadata', {}).get('uid') != uid:
        raise RuntimeError('Private reattachment replaced its workload')


def run(payload):
    if not payload['sources']:
        return {'private_sources_configured': 0, 'private_sources_required_by_base': False}
    for entry in payload['sources']:
        name = 'cloudlab-private-' + entry['name']
        wait(lambda: healthy(name), 'convergence')
        secret = get('secret', name)
        external = get('externalsecret.external-secrets.io', name)
        if not secret or not external or not any(
                owner.get('kind') == 'ExternalSecret' and owner.get('uid') == external['metadata']['uid']
                for owner in secret['metadata'].get('ownerReferences', [])):
            raise RuntimeError('Private repository credential lacks its ESO owner')
    fixtures = [entry for entry in payload['sources'] if entry['repository'] == payload.get('fixture_repository')]
    for entry in fixtures:
        fixture(entry, payload)
    def controllers():
        argo = json.loads(kube('get', 'deployments,daemonsets,statefulsets,pods', '-n', 'argocd', '-o', 'json'))
        return foundation_sample(), fingerprint(argo['items'])
    baseline = controllers()
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if controllers() != baseline or not all(healthy('cloudlab-private-' + entry['name']) for entry in payload['sources']):
            raise RuntimeError('Controllers or private convergence changed during stability observation')
    for entry in payload['sources']:
        checkpoint = BASE / ('private-' + entry['name'] + '.json')
        state = json.loads(checkpoint.read_text())
        state['phase'] = 'accepted'
        record(checkpoint, state)
    return {'private_roots_converged': len(payload['sources']), 'private_fixtures_verified': len(fixtures),
            'controllers_stable_after_private_fixtures': True,
            'stability_seconds': round(time.monotonic() - started, 1),
            'fixture_checks': ['drift', 'source-failure-retention', 'credential-failure-retention',
                               'public-convergence-during-credential-failure', 'source-denial', 'namespace-denial',
                               'omission-retention', 'removal-retention', 'reattachment'] if fixtures else []}


if __name__ == '__main__':
    try:
        os.umask(0o077)
        with (BASE / 'verification.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(run(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private GitOps verification failed; diagnostics withheld') from None
