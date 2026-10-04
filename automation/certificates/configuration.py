"""Serialize staging-before-production issuance through one runtime Application."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys

from inputs import zone
from kube import application_ready, contains, get, kube, ready, wait

BASE = Path('/var/lib/cloudlab/certificates')
OWNER = 'cloudlab-certificates-bootstrap'
APP = 'cloudlab-certificates'


def record(state):
    temporary = BASE / 'ownership.tmp'
    with temporary.open('w') as stream:
        json.dump(state, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(BASE / 'ownership.json')
    directory = os.open(BASE, os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def application(payload, name, production):
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'],
            'targetRevision': payload['branch'], 'path': 'platform/certificates/configuration',
            'helm': {'releaseName': APP, 'valuesObject': {'zone': name, 'production': production}}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'cert-manager'},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}


def configure(payload, name, production, state):
    desired = application(payload, name, production)
    before = get('application.argoproj.io', APP, 'argocd')
    if state.get('application_uid') and not before:
        raise RuntimeError('Certificate Application is missing; retained ownership receipt requires recovery review')
    if before and (before['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                   or before['metadata'].get('finalizers') or before['metadata'].get('ownerReferences')
                   or state.get('application_uid', before['metadata']['uid']) != before['metadata']['uid']):
        raise RuntimeError('Certificate Application has a conflicting owner or replaced identity')
    changed = not before or not contains(before, desired)
    if changed:
        wait(lambda: not (get('application.argoproj.io', APP, 'argocd') or {}).get('operation'),
             'previous Application operation', timeout=300)
        kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
    current = get('application.argoproj.io', APP, 'argocd')
    if before and current['metadata']['uid'] != before['metadata']['uid']:
        raise RuntimeError('Certificate Application identity changed')
    if state.get('application_uid') != current['metadata']['uid']:
        state['application_uid'] = current['metadata']['uid']
        record(state)
    wait(lambda: application_ready(APP, payload['revision']), 'certificate Application convergence')
    return changed


def certificate(name, namespace):
    obj = wait(lambda: (current if ready(current := get('certificate.cert-manager.io', name, namespace)) else None),
               'certificate issuance')
    secret = get('secret', obj['spec']['secretName'], namespace)
    if not secret or secret.get('type') != 'kubernetes.io/tls' or not {'tls.crt', 'tls.key'} <= secret.get('data', {}).keys():
        raise RuntimeError('Issued certificate Secret is incomplete')
    if secret['metadata'].get('annotations', {}).get('cert-manager.io/certificate-name') != name:
        raise RuntimeError('Certificate Secret lacks its controller association')
    return {'certificate_uid': obj['metadata']['uid'], 'secret_uid': secret['metadata']['uid']}


def run(payload):
    os.umask(0o077)
    if BASE.resolve() != BASE.absolute():
        raise RuntimeError('Certificate state directory must not be a symlink')
    with (BASE / 'ownership.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        wait(lambda: application_ready('cloudlab-cert-manager', payload['revision']), 'operator convergence')
        for deployment in ('cert-manager', 'cert-manager-webhook', 'cert-manager-cainjector'):
            kube('rollout', 'status', 'deployment/' + deployment, '-n', 'cert-manager', '--timeout=300s', timeout=330)
        selected_zone = zone()
        zone_hash = hashlib.sha256(selected_zone.encode()).hexdigest()
        path = BASE / 'ownership.json'
        if not path.exists() and get('application.argoproj.io', APP, 'argocd'):
            raise RuntimeError('Certificate Application exists without its durable ownership checkpoint')
        if not path.exists():
            protected = [('namespace', 'cloudlab-gateway-public', None),
                         ('namespace', 'cloudlab-gateway-private', None),
                         ('certificate.cert-manager.io', 'cloudlab-staging', 'cert-manager')]
            for stage in ('staging', 'production'):
                protected.extend([('clusterissuer.cert-manager.io', 'cloudlab-acme-' + stage, None),
                                  ('secret', 'cloudlab-acme-' + stage, 'cert-manager')])
            if any(get(*identity) for identity in protected):
                raise RuntimeError('Certificate configuration refuses existing resources without an ownership checkpoint')
        state = json.loads(path.read_text()) if path.exists() else {'phase': 'staging', 'zone_hash': zone_hash}
        if state.get('zone_hash') != zone_hash or state.get('phase') not in ('staging', 'production', 'accepted'):
            raise RuntimeError('DNS zone or certificate checkpoint changed; preserve issued credentials and review migration')
        changed = False
        if state['phase'] == 'staging':
            record(state)
            changed |= configure(payload, selected_zone, False, state)
            state['staging'] = certificate('cloudlab-staging', 'cert-manager')
            state['phase'] = 'production'
            record(state)
            changed = True
        changed |= configure(payload, selected_zone, True, state)
        if certificate('cloudlab-staging', 'cert-manager') != state['staging']:
            raise RuntimeError('Staging certificate or Secret identity changed')
        identities = {kind: certificate('cloudlab-gateway', 'cloudlab-gateway-' + kind)
                      for kind in ('public', 'private')}
        accounts = {}
        for stage in ('staging', 'production'):
            secret = get('secret', 'cloudlab-acme-' + stage, 'cert-manager')
            if not secret or not secret.get('data'):
                raise RuntimeError('Certificate account credential is missing')
            accounts[stage] = {'uid': secret['metadata']['uid'],
                'content': hashlib.sha256(json.dumps(secret['data'], sort_keys=True).encode()).hexdigest()}
        if 'accounts' in state and state['accounts'] != accounts:
            raise RuntimeError('Certificate account credential identity or content changed')
        if 'identities' in state and state['identities'] != identities:
            raise RuntimeError('Gateway certificate or Secret identity changed')
        if state['phase'] != 'accepted':
            state.update(phase='accepted', identities=identities, accounts=accounts)
            record(state)
            changed = True
        return {'changed': changed, 'phase': state['phase'], 'production_certificates': 2,
                'staging_preceded_production': True, 'credential_owner': 'external-secrets'}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Certificate configuration failed; checkpoint retained, private diagnostics withheld') from None
