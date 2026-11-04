"""Observe actual private configuration reconciliation without changing sources or data."""
import base64
import copy
import fcntl
import json
import os
import re
import sys
import time

from bootstrap import BASE, get, kube, matches_revision
from private_activation import APP, OWNER, TRACKING, sources_match
from controller_stability import fingerprint, sample as foundation_sample


def wait(check, description, timeout=240):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(3)
    raise RuntimeError('Private GitOps ' + description + ' failed; diagnostics withheld')


def healthy(name):
    return application_healthy(get('application.argoproj.io', name) or {})


def application_healthy(app):
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
    if not any(owner.get('kind') == 'ExternalSecret' and owner.get('name') == external['metadata']['name'] and
               owner.get('controller') is True and owner.get('uid') == external['metadata']['uid'] and
               external['metadata']['name'] == secret['metadata']['name'] and
               any(condition.get('type') == 'Ready' and condition.get('status') == 'True'
                   for condition in external.get('status', {}).get('conditions', []))
               for owner in owners for external in externals):
        raise RuntimeError('Private repository credential lacks its ready ESO owner')
    if not all(decoded(secret, field) for field in ('githubAppID', 'githubAppInstallationID', 'githubAppPrivateKey')):
        raise RuntimeError('Private repository credential is incomplete')


def configuration_healthy(name, repository, revision):
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        return False
    app = get('application.argoproj.io', name) or {}
    if not app:
        return False
    sources = app['spec'].get('sources', [app['spec'].get('source', {})])
    sync = app.get('status', {}).get('sync', {})
    revisions = sync.get('revisions', [sync.get('revision')])
    if not (len(sources) == len(revisions) and any(source.get('repoURL') == repository for source in sources) and all(
        resolved == (revision if source['targetRevision'] == 'main' else source['targetRevision'])
        for source, resolved in zip(sources, revisions) if source.get('repoURL') == repository)):
        return False
    # Compare mutable configuration references against the authenticated head, preserving other source pin checks.
    compared = copy.deepcopy(app)
    for source in compared['spec'].get('sources', [compared['spec'].get('source', {})]):
        if source.get('repoURL') == repository and source.get('targetRevision') == 'main':
            source['targetRevision'] = revision
    return application_healthy(compared)


def controller_items(items):
    """Exclude scheduled Jobs and only Pods proven to belong to a listed Job."""
    jobs = set()
    for obj in items:
        if obj.get('kind') == 'Job' and obj.get('apiVersion') == 'batch/v1':
            metadata = obj.get('metadata', {})
            identity = tuple(metadata.get(key) for key in ('namespace', 'name', 'uid'))
            if all(isinstance(value, str) and value for value in identity):
                jobs.add(identity)
    result = []
    for obj in items:
        if obj.get('kind') == 'Job':
            continue
        metadata = obj.get('metadata', {})
        owners = metadata.get('ownerReferences') or []
        if obj.get('kind') == 'Pod' and isinstance(owners, list) and any(
                isinstance(owner, dict) and owner.get('apiVersion') == 'batch/v1'
                and owner.get('kind') == 'Job' and owner.get('controller') is True
                and all(isinstance(value, str) and value for value in
                        (metadata.get('namespace'), owner.get('name'), owner.get('uid')))
                and (metadata['namespace'], owner['name'], owner['uid']) in jobs for owner in owners):
            continue
        result.append(obj)
    return result


def run(payload):
    repository = payload.get('configuration_repository')
    if not repository:
        raise RuntimeError('Private verification requires the actual configuration repository')
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
    if payload.get('catalog_enabled'):
        catalog = get('application.argoproj.io', APP) or {}
        evidence = {'repository': payload['public_repository'], 'revision': payload['platform_revision'],
                    'private_repository': repository}
        if (catalog.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER
                or catalog.get('metadata', {}).get('annotations', {}).get('argocd.argoproj.io/tracking-id') != TRACKING
                or catalog.get('metadata', {}).get('finalizers') or not sources_match(catalog, evidence)
                or catalog.get('metadata', {}).get('ownerReferences') or catalog.get('metadata', {}).get('deletionTimestamp')
                or catalog.get('spec', {}).get('project') != APP
                or catalog.get('spec', {}).get('destination') != {'server': 'https://kubernetes.default.svc', 'namespace': 'argocd'}
                or catalog.get('spec', {}).get('syncPolicy', {}).get('automated') !=
                    {'enabled': True, 'prune': True, 'selfHeal': True, 'allowEmpty': True}
                or catalog.get('spec', {}).get('syncPolicy', {}).get('syncOptions') !=
                    ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true', 'PruneLast=true']):
            raise RuntimeError('Private catalog ownership or source differs from reviewed declarations')
        for desired in payload['objects']:
            kind = desired['kind']
            name = desired['metadata']['name']
            group = desired['apiVersion'].split('/')[0] if '/' in desired['apiVersion'] else ''
            resource = kind.lower() + ('.' + group if group else '')
            raw = kube('get', resource, name, *(['-n', 'argocd'] if kind != 'Namespace' else []), '-o', 'json')
            actual = json.loads(raw)
            expected_tracking = APP + ':' + group + '/' + kind + ':argocd/' + name
            if (actual['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != expected_tracking
                    or actual['metadata'].get('deletionTimestamp') or actual['metadata'].get('ownerReferences')
                    or (kind == 'Application' and actual['metadata'].get('finalizers'))
                    or not contains(actual, desired)):
                raise RuntimeError('Private registration differs from its native declaration')
    def child_healthy(entry):
        name = 'cloudlab-private-' + entry['name']
        return configuration_healthy(name, repository, revision) if entry['repository'] == repository else healthy(name)
    for entry in payload['sources']:
        name = 'cloudlab-private-' + entry['name']
        wait(lambda: child_healthy(entry), 'convergence')
        credential_owner(get('application.argoproj.io', name), entry['repository'], secrets, externals)
    def controllers():
        argo = json.loads(kube('get', 'deployments,daemonsets,statefulsets,jobs,pods', '-n', 'argocd', '-o', 'json'))
        return foundation_sample(), fingerprint(controller_items(argo['items']))
    baseline = controllers()
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if (controllers() != baseline
                or not all(configuration_healthy(app['metadata']['name'], repository, revision) for app in consumers)
                or not all(child_healthy(entry) for entry in payload['sources'])):
            raise RuntimeError('Controllers or private convergence changed during stability observation')
    return {'private_roots_converged': len(payload['sources']), 'private_configuration_consumers': len(consumers),
            'private_access_verified': True, 'eso_credentials_verified': True,
            'controllers_stable': True, 'stability_seconds': round(time.monotonic() - started, 1),
            'failure_injection': False}


def contains(actual, desired):
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(key in actual and contains(actual[key], value)
                                               for key, value in desired.items())
    return actual == desired



if __name__ == '__main__':
    try:
        os.umask(0o077)
        with (BASE / 'verification.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print(json.dumps(run(json.load(sys.stdin))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError)
                         else 'Private GitOps verification failed; diagnostics withheld') from None
