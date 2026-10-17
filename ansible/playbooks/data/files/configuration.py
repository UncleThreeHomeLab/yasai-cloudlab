"""Atomic data Application adoption and UID receipts under the shared runtime lock."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from playbooks.data.files.control import (
    APP, BASE, NAMESPACE, OWNER, S3Error, application_ready, atomic, condition,
    get, kube, locked, primary, s3, sql, wait,
)
from playbooks.istio.files.kube import contains

def application(payload, component, values=None):
    name = 'cloudlab-' + component
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
            'metadata': {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
            'spec': {'project': name, 'source': {'repoURL': payload['repository'],
                'targetRevision': payload['branch'], 'path': 'platform/data/' + ('configuration' if component == 'data-configuration' else component),
                'helm': {'releaseName': name, 'valuesObject': values or {}}},
                'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
                'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                    'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                    'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}


def configure(payload):
    with locked():
        for name, path in [('Longhorn', '/var/lib/cloudlab/longhorn/ownership.json'),
                           ('ESO', '/var/lib/cloudlab/external-secrets/ownership.json'),
                           ('backup', '/var/lib/cloudlab/longhorn/backup-ownership.json')]:
            if json.loads(Path(path).read_text()).get('phase') != 'accepted':
                raise RuntimeError(name + ' ownership must be accepted before data services')
        wait(lambda: application_ready('cloudlab-cnpg', payload['revision']), 'CNPG operator convergence')
        private_cert = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
        private_zone = payload['values']['s3Host'].split('.', 1)[1]
        if not condition(private_cert, 'Ready') or private_cert['spec']['dnsNames'] != ['*.' + private_zone, 'login.' + private_zone.removeprefix('internal.')]:
            raise RuntimeError('Data endpoint must belong to the existing ready private certificate zone')
        receipt = BASE / 'ownership.json'
        state = json.loads(receipt.read_text()) if receipt.exists() else {'applications': {}}
        existing = get('application.argoproj.io', APP, 'argocd')
        from playbooks.data.files.requests import additions, protect
        supplied = payload['values'].get('serviceRequests', [])
        protect(supplied, payload['values'])
        if existing:
            retained = existing['spec']['source']['helm']['valuesObject'].get('serviceRequests', [])
            for row in additions(retained, supplied):
                if 'database' in row and sql('SELECT count(*) FROM pg_database WHERE datname=' +
                                            "'" + row['database']['name'].replace("'", "''") + "';") != '0':
                    raise ValueError('New service request cannot adopt an existing database')
                if 'bucket' in row:
                    try:
                        s3().request('HEAD', row['bucket']['name'])
                    except S3Error as error:
                        if error.status != 404: raise
                    else:
                        raise ValueError('New service request cannot adopt an existing bucket')
        if existing and (existing['spec']['source']['helm']['valuesObject'].get('maintenance')
                         or (BASE / 'cold-maintenance.json').exists()):
            raise RuntimeError('Data capture was interrupted; run data-resume before apply')
        changed = False
        for component in ('data-configuration', 'seaweedfs'):
            desired = application(payload, component, payload['values'] if component == 'data-configuration' else None)
            name = desired['metadata']['name']
            current = get('application.argoproj.io', name, 'argocd')
            uid = state['applications'].get(name)
            if (uid and (not current or current['metadata']['uid'] != uid)) or (current and (
                    current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                    or current['metadata'].get('finalizers') or current['metadata'].get('ownerReferences'))):
                raise RuntimeError('Data Application identity or ownership changed')
            if not current or not contains(current, desired):
                kube('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-', document=desired)
                changed = True
            state['applications'][name] = get('application.argoproj.io', name, 'argocd')['metadata']['uid']
            state['revision'] = payload['revision']
            changed = atomic(receipt, state) or changed
        # Routes depend on the service, while SeaweedFS depends on config Secrets.
        # Declare both owners before waiting for either health graph to converge.
        for component in ('data-configuration', 'seaweedfs'):
            name = 'cloudlab-' + component
            wait(lambda: application_ready(name, payload['revision']), 'data Application convergence', timeout=900)
        for name in ('notes-application', 'notes-migration', 'database-backup', 'cloudlab-s3-config', 'data-offsite'):
            wait(lambda: condition(get('externalsecret.external-secrets.io', name, NAMESPACE), 'Ready'), 'data credential readiness')
        primary()
        for row in payload['values'].get('serviceRequests', []):
            if 'database' in row:
                def database_ready():
                    obj = get('database.postgresql.cnpg.io', row['service'], NAMESPACE)
                    return bool(obj and obj.get('status', {}).get('applied') is True and
                                obj['status'].get('observedGeneration') == obj['metadata']['generation'])
                wait(database_ready, 'service database owner convergence', timeout=600)
        from playbooks.data.files.volumes import inventory
        inventory()
        changed = atomic(BASE / 'desired.json', payload['values']) or changed
        # The next native stage reconciles through both configured private resolvers.
        return changed


if __name__ == '__main__':
    try:
        print(json.dumps({'changed': configure(json.load(sys.stdin))}))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else
                         'Data ownership transaction failed; private diagnostics withheld') from None
