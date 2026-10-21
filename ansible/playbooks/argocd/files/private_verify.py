"""Observe actual private configuration reconciliation without changing sources or data."""
import base64
import fcntl
import json
import os
import sys
import time

from bootstrap import BASE, get, kube, matches_revision
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
    sync = status.get('sync', {})
    revision = sync.get('revision') or next(iter(sync.get('revisions', [])), None)
    return (status.get('sync', {}).get('status') == 'Synced' and
            bool(revision) and matches_revision(app, revision) and
            status.get('health', {}).get('status') == 'Healthy' and
            not app.get('operation') and
            not any(c['type'].endswith('Error') for c in status.get('conditions', [])) and
            # Reattaching retained, already matching resources needs no sync
            # operation. A resolved revision and converged comparison suffice.
            status.get('operationState', {}).get('phase') in (None, 'Succeeded'))


def credential_owner(app, repository, secrets, externals):
    project = app['spec']['project']
    def decoded(secret, key):
        return base64.b64decode(secret.get('data', {}).get(key, '')).decode()
    credentials = [secret for secret in secrets if
        secret['metadata'].get('labels', {}).get('argocd.argoproj.io/secret-type') == 'repository' and
        decoded(secret, 'url') == repository and decoded(secret, 'project') == project]
    if len(credentials) != 1:
        raise RuntimeError('Private configuration requires one project-scoped repository credential')
    secret = credentials[0]
    owners = secret['metadata'].get('ownerReferences', [])
    if not any(owner.get('kind') == 'ExternalSecret' and owner.get('uid') == external['metadata']['uid'] and
               external['metadata']['name'] == secret['metadata']['name'] and
               any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                   for condition in external.get('status', {}).get('conditions', []))
               for owner in owners for external in externals):
        raise RuntimeError('Private repository credential lacks its ready ESO owner')
    if not all(decoded(secret, field) for field in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey')):
        raise RuntimeError('Private repository credential is incomplete')


def configuration_healthy(name, repository, revision):
    if not healthy(name):
        return False
    app = get('application.argoproj.io', name)
    sources = app['spec'].get('sources', [app['spec'].get('source', {})])
    sync = app['status']['sync']
    revisions = sync.get('revisions', [sync.get('revision')])
    return len(sources) == len(revisions) and any(source.get('repoURL') == repository for source in sources) and all(
        resolved == (revision if source['targetRevision'] == 'main' else source['targetRevision'])
        for source, resolved in zip(sources, revisions) if source.get('repoURL') == repository)


def run(payload):
    repository = payload.get('configuration_repository')
    if not repository:
        if payload['sources']:
            raise RuntimeError('Private verification requires the actual configuration repository')
        return {'private_sources_configured': 0, 'private_access_verified': False}
    applications = json.loads(kube('get', 'applications.argoproj.io', '-n', 'argocd', '-o', 'json'))['items']
    consumers = [app for app in applications if any(source.get('repoURL') == repository for source in
                 app['spec'].get('sources', [app['spec'].get('source', {})]))]
    if not consumers:
        raise RuntimeError('Actual private configuration source has no reconciled consumers')
    revision = payload.get('configuration_revision')
    if not revision:
        raise RuntimeError('Private verification requires an authenticated configuration revision')
    secrets = json.loads(kube('get', 'secrets', '-n', 'argocd', '-o', 'json'))['items']
    externals = json.loads(kube('get', 'externalsecrets.external-secrets.io', '-n', 'argocd', '-o', 'json'))['items']
    for app in consumers:
        wait(lambda: configuration_healthy(app['metadata']['name'], repository, revision), 'configuration convergence')
        credential_owner(app, repository, secrets, externals)
    for entry in payload['sources']:
        if entry['repository'] != repository:
            raise RuntimeError('Private verification accepts only the actual configuration source')
        wait(lambda: healthy('cloudlab-private-' + entry['name']), 'convergence')
    def controllers():
        argo = json.loads(kube('get', 'deployments,daemonsets,statefulsets,pods', '-n', 'argocd', '-o', 'json'))
        return foundation_sample(), fingerprint(argo['items'])
    baseline = controllers()
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if controllers() != baseline or not all(configuration_healthy(app['metadata']['name'], repository, revision) for app in consumers):
            raise RuntimeError('Controllers or private convergence changed during stability observation')
    for entry in payload['sources']:
        checkpoint = BASE / ('private-' + entry['name'] + '.json')
        state = json.loads(checkpoint.read_text())
        state['phase'] = 'accepted'
        record(checkpoint, state)
    return {'private_roots_converged': len(payload['sources']), 'private_configuration_consumers': len(consumers),
            'private_access_verified': True, 'eso_credentials_verified': True,
            'controllers_stable': True, 'stability_seconds': round(time.monotonic() - started, 1),
            'failure_injection': False}



if __name__ == '__main__':
    try:
        os.umask(0o077)
        with (BASE / 'verification.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(run(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private GitOps verification failed; diagnostics withheld') from None
