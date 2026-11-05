"""Declare only Harbor Applications; Argo owns installation and transient replica changes."""
import copy
import fcntl
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from playbooks.istio.files.kube import get, kube, contains, application_ready, wait, condition

NAMESPACE, OWNER = 'cloudlab-harbor', 'harbor-platform'
SECRETS = ('harbor-emergency', 'harbor-database', 'harbor-runtime', 'harbor-token-signing', 'harbor-oidc',
           'harbor-browser-key', 'harbor-browser-oidc', 'harbor-recovery-verifier')


def application(payload, configuration=False):
    name = 'cloudlab-harbor' + ('-configuration' if configuration else '')
    helm = {'releaseName': 'cloudlab-harbor', 'valuesObject': payload['configuration'] if configuration else payload['server']}
    if not configuration:
        helm['valueFiles'] = ['values.json']
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': 'cloudlab-harbor', 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['revision'], 'path': 'platform/harbor' + ('' if configuration else '/server'), 'helm': helm},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'ServerSideApply=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '10s', 'factor': 2, 'maxDuration': '1m'}}}}}


def seed(payload, configuration=False):
    from playbooks.harbor.files.native import receipt
    if receipt():
        raise RuntimeError('Harbor native ownership intent forbids the legacy Application writer')
    desired = application(payload, configuration)
    name = desired['metadata']['name']
    current = get('application.argoproj.io', name, 'argocd')
    if current and (current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
            current['metadata'].get('ownerReferences') or current['metadata'].get('finalizers') or
            any(current['spec'].get(field) != desired['spec'][field] for field in ('project', 'destination')) or
            any(current['spec']['source'].get(field) != desired['spec']['source'][field] for field in ('repoURL', 'path'))):
        raise RuntimeError('Harbor Application has another owner; adoption refused')
    changed = not current or not contains(current, desired)
    if changed:
        kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
    def ready():
        if not configuration:
            return application_ready(name, payload['revision'])
        # Its route backend does not exist until the server chart converges.
        actual = get('application.argoproj.io', name, 'argocd') or {}
        status = actual.get('status', {})
        return (status.get('sync', {}).get('status') == 'Synced' and
                status.get('sync', {}).get('revision') == payload['revision'] and not actual.get('operation') and
                status.get('operationState', {}).get('phase') == 'Succeeded' and
                contains(status.get('sync', {}).get('comparedTo', {}).get('source', {}), desired['spec']['source']) and
                not any(row['type'].endswith('Error') for row in status.get('conditions', [])))
    wait(ready, 'Harbor chart convergence', timeout=900)
    return changed


def run(payload):
    if (set(payload) - {'native_handoff', 'native_initial'} != {'repository', 'revision', 'configuration', 'server', 'identity_client'} or
            any(type(payload.get(key, False)) is not bool for key in ('native_handoff', 'native_initial')) or
            not re.fullmatch('[a-f0-9]{40}', payload['revision']) or
            payload['configuration'].get('enabled') is not True or
            set(payload['server']) != {'harbor'}):
        raise ValueError('Harbor requires its complete published installation declaration')
    payload = copy.deepcopy(payload)
    with Path('/run/lock/cloudlab-harbor.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if Path('/var/lib/cloudlab/harbor/maintenance.json').exists():
            raise RuntimeError('Finish or resume coordinated Harbor recovery before applying setup')
        from playbooks.harbor.files import native
        if payload.get('native_handoff'):
            changed = native.prepare(initial=payload.get('native_initial', False))
            return {'changed': changed, 'owner': 'argocd', 'native_handoff': True}
        if native.receipt():
            snapshot = native.context()
            if snapshot is None: raise RuntimeError('Complete prepared Harbor native handoff before normal setup')
            native.observe(snapshot, native.receipt())
            return {'changed': False, 'owner': 'argocd', 'native_installation': True}
        if native.context() is not None:
            raise RuntimeError('Harbor native installation requires its protected initial or adoption intent')
        for name in native.APPS:
            current = get('application.argoproj.io', name, 'argocd')
            if current and current.get('spec', {}).get('source', {}).get('targetRevision') != native.REVISION:
                raise RuntimeError('Harbor setup cannot promote or silently freeze another installation revision')
        installation_payload = dict(payload, revision=native.REVISION)
        private = get('configmap', 'identity-private-state', 'cloudlab-identity') or {}
        source = json.loads(private.get('data', {}).get('desired_state', '{}'))
        revoked = json.loads(private.get('data', {}).get('revocations', '{}')).get('realms', {}).get('platform', {})
        clients = source.get('realms', {}).get('platform', {}).get('clients', [])
        if ([entry for entry in clients if entry.get('id') == 'harbor'] != [payload['identity_client']] or
                'harbor' in revoked.get('clients', []) + revoked.get('removed_clients', [])):
            raise RuntimeError('Harbor requires its exact active client from the retained Keycloak owner')
        for kind, name in (('namespace', NAMESPACE), ('storageclass', NAMESPACE)):
            existing = get(kind, name)
            if existing and existing['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER:
                raise RuntimeError('Existing Harbor boundary has another owner')
        changed = seed(installation_payload, True)
        wait(lambda: all(condition(get('externalsecret.external-secrets.io', name, NAMESPACE), 'Ready')
                         for name in SECRETS), 'Harbor vault delivery', timeout=300)
        changed = seed(installation_payload) or changed
        wait(lambda: application_ready('cloudlab-harbor-configuration', native.REVISION),
             'complete private Harbor route', timeout=300)
        return {'changed': changed, 'owner': 'argocd', 'components': 7, 'offsite_backup': False}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin)), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor installation incomplete; secrets, data and existing owners retained') from None
