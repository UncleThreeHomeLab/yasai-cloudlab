"""Private GitOps convergence and retained-resource fixtures; sanitized output only."""
import copy
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
            status.get('health', {}).get('status') == 'Healthy' and
            status.get('operationState', {}).get('phase') == 'Succeeded')


def mutate(name, document):
    kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=merge', '-p', json.dumps(document))


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
    for entry in payload['sources']:
        checkpoint = BASE / ('private-' + entry['name'] + '.json')
        state = json.loads(checkpoint.read_text())
        state['phase'] = 'accepted'
        record(checkpoint, state)
    return {'private_roots_converged': len(payload['sources']), 'private_fixtures_verified': len(fixtures),
            'fixture_checks': ['drift', 'source-failure-retention', 'source-denial', 'namespace-denial',
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
