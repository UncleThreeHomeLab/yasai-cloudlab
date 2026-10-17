"""Coordinated Harbor snapshots with chart-owned writer shutdown and repeat recovery."""
from contextlib import contextmanager
import base64
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from automation.harbor.bootstrap import OWNER, NAMESPACE, SECRETS
from playbooks.istio.files.kube import get, kube, condition, wait, application_ready

BASE = Path('/var/lib/cloudlab/harbor')
CLAIMS = {'database': 'harbor-database', 'registry': 'harbor-registry', 'redis': 'harbor-redis'}
APPS = ('cloudlab-harbor', 'cloudlab-harbor-configuration')
LABEL = {'cloudlab.io/owner': OWNER}
ARTIFACTS = Path(__file__).resolve().parents[2] / 'platform/harbor'


def atomic(path, value):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


@contextmanager
def locked():
    os.umask(0o077)
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    with Path('/run/lock/cloudlab-harbor.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def secret(name, namespace=NAMESPACE):
    obj = get('secret', name, namespace)
    external = get('externalsecret.external-secrets.io', name, namespace)
    if not obj or not condition(external, 'Ready') or not any(
            ref.get('uid') == external['metadata']['uid'] and ref.get('kind') == 'ExternalSecret'
            for ref in obj['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Harbor recovery requires current ESO-owned credentials')
    return obj['data']


def fingerprints():
    return {name: hashlib.sha256(json.dumps(secret(name), sort_keys=True).encode()).hexdigest() for name in SECRETS}


def installation():
    revisions = {application(name)['spec']['source']['targetRevision'] for name in APPS}
    if len(revisions) != 1:
        raise RuntimeError('Harbor recovery requires one converged installation revision')
    return {'revision': revisions.pop(),
            'chart_sha256': json.loads((ARTIFACTS / 'server/artifact.lock.json').read_text())['sha256'],
            'images': sorted(json.loads((ARTIFACTS / 'images.lock.json').read_text()).values())}


def freshness(now=None):
    receipt, attempt = BASE / 'monthly-receipt.json', BASE / 'monthly-attempt.json'
    if not receipt.exists():
        raise RuntimeError('No successful monthly Harbor recovery point exists')
    value = json.loads(receipt.read_text())
    age = (time.time() if now is None else now) - value['captured_at']
    maximum = json.loads((ARTIFACTS / 'policy.json').read_text())['remote_max_age_seconds']
    if (not 0 <= age <= maximum or not value.get('retention_complete') or
            (attempt.exists() and json.loads(attempt.read_text()).get('success') is not True)):
        raise RuntimeError('Monthly Harbor recovery point is stale or its last attempt failed')
    return {'monthly_age_hours': round(age / 3600, 2), 'retained_local_generations': 0, 'b2_reads': 0}


def sources():
    result = {}
    for component, name in CLAIMS.items():
        claim = get('pvc', name, NAMESPACE)
        pv = get('pv', claim['spec']['volumeName']) if claim else None
        volume = get('volumes.longhorn.io', pv['spec']['csi']['volumeHandle'], 'longhorn-system') if pv else None
        if (not volume or claim['status'].get('phase') != 'Bound' or claim['spec']['storageClassName'] != NAMESPACE or
                pv['spec']['claimRef']['uid'] != claim['metadata']['uid'] or
                volume['status'].get('robustness') != 'healthy' or volume['spec']['numberOfReplicas'] != 2 or
                volume['spec'].get('backupCompressionMethod') != 'lz4' or
                volume['spec'].get('backupTargetName') != 'default'):
            raise RuntimeError('Harbor recovery source identity, health or storage policy changed')
        result[component] = {'claim': name, 'claim_uid': claim['metadata']['uid'],
            'volume': volume['metadata']['name'], 'volume_uid': volume['metadata']['uid'],
            'size': claim['spec']['resources']['requests']['storage'], 'actual_bytes': int(volume['status']['actualSize'])}
    return result


def application(name):
    app = get('application.argoproj.io', name, 'argocd')
    if (not app or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or
            app['spec'].get('project') != 'cloudlab-harbor' or
            app['spec']['destination'] != {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE}):
        raise RuntimeError('Cannot suspend or resume a foreign Harbor Application')
    return app


def patch_values(name, values, expected_uid):
    app = application(name)
    if app['metadata']['uid'] != expected_uid:
        raise RuntimeError('Harbor Application changed during coordinated maintenance')
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': expected_uid},
             {'op': 'test', 'path': '/metadata/resourceVersion', 'value': app['metadata']['resourceVersion']},
             {'op': 'replace', 'path': '/spec/source/helm/valuesObject', 'value': values}]
    kube('patch', 'application.argoproj.io', name, '-n', 'argocd', '--type=json',
         '--field-manager=' + OWNER, '-p', json.dumps(patch))


def pods(component, namespace=NAMESPACE):
    return [pod for pod in (get('pods', namespace=namespace) or {}).get('items', [])
            if pod['metadata'].get('labels', {}).get('component') == component]


def command(component, arguments, namespace):
    candidates = [pod for pod in pods(component, namespace) if condition(pod, 'Ready')]
    if len(candidates) != 1:
        raise RuntimeError('Expected one ready Harbor recovery component')
    return ['/usr/local/bin/k3s', 'kubectl', 'exec', '-n', namespace,
            candidates[0]['metadata']['name'], '-c', component, '--', *arguments]


def execute(component, arguments, namespace=NAMESPACE):
    result = subprocess.run(command(component, arguments, namespace), capture_output=True, timeout=900)
    if result.returncode:
        raise RuntimeError('Harbor recovery component inspection failed; private diagnostics withheld')
    return result.stdout


def stream_hash(arguments):
    digest = hashlib.sha256()
    with tempfile.TemporaryFile() as diagnostic:
        process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=diagnostic)
        failures = []
        def consume():
            try:
                for chunk in iter(lambda: process.stdout.read(1024 * 1024), b''):
                    digest.update(chunk)
            except Exception:
                failures.append(True)
        reader = threading.Thread(target=consume, daemon=True)
        reader.start()
        try:
            result = process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError('Harbor inventory exceeded its bounded inspection time') from None
        finally:
            reader.join(timeout=5)
            process.stdout.close()
        if result or failures or reader.is_alive():
            raise RuntimeError('Harbor inventory failed; diagnostic values withheld')
    return digest.hexdigest()


def inventory(namespace=NAMESPACE):
    # PostgreSQL 18's fixed restrict key keeps the protected in-memory dump deterministic.
    tables = ('project', 'project_member', 'user_group', 'repository', 'artifact', 'tag', 'accessory',
              'robot', 'harbor_user', 'oidc_user')
    arguments = ['pg_dump', '-U', 'postgres', '-d', 'registry', '--data-only', '--no-owner',
                 '--no-privileges', '--restrict-key=CloudlabHarborRecovery']
    for table in tables:
        arguments += ['--table=public.' + table]
    database = stream_hash(command('database', arguments, namespace))
    blobs = stream_hash(command('registry', ['bash', '-euo', 'pipefail', '-c',
        "if test -d /storage/docker/registry/v2; then find /storage/docker/registry/v2 -type d -name _uploads -prune -o -type f -exec sha256sum '{}' '+' | LC_ALL=C sort; fi"], namespace))
    digests = execute('database', ['psql', '-X', '-At', '-U', 'postgres', '-d', 'registry',
        '-v', 'ON_ERROR_STOP=1', '-c', "SELECT coalesce(json_agg(digest ORDER BY digest),'[]'::json) FROM artifact"], namespace)
    artifact_digests = json.loads(digests)
    if not isinstance(artifact_digests, list) or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', digest) for digest in artifact_digests):
        raise RuntimeError('Invalid Harbor artifact digest inventory')
    return {'database_sha256': database, 'blobs_sha256': blobs, 'artifact_digests': artifact_digests}


def resume():
    receipt = BASE / 'maintenance.json'
    if not receipt.exists():
        return
    state = json.loads(receipt.read_text())
    if set(state['applications']) != set(APPS):
        raise RuntimeError('Harbor maintenance receipt is incomplete')
    # Start persistent dependencies, registry and core through their original chart inputs.
    for name in APPS:
        original = state['applications'][name]
        app = application(name)
        if app['spec']['source']['targetRevision'] != original['revision']:
            raise RuntimeError('Harbor source changed during maintenance; retain recovery receipt')
        patch_values(name, original['values'], original['uid'])
        wait(lambda: application_ready(name, original['revision']), 'resume Harbor owner', timeout=1200)
    receipt.unlink()


def validate_sources(manifest):
    if (set(manifest['volumes']) != set(CLAIMS) or not re.fullmatch(r'harbor-[a-f0-9]{24}', manifest['generation'])):
        raise ValueError('Invalid Harbor generation identity')
    for component, row in manifest['volumes'].items():
        if (row['claim'] != CLAIMS[component] or not re.fullmatch(r'pvc-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}', row['volume']) or
                row['snapshot'] != manifest['generation'] + '-' + component or
                not re.fullmatch(r'[1-9][0-9]*(Gi|Mi)', row['size']) or
                type(row['actual_bytes']) is not int or row['actual_bytes'] < 0):
            raise ValueError('Harbor recovery source escaped its recorded volume')
        for field in ('claim_uid', 'volume_uid'):
            if str(uuid.UUID(row[field])) != row[field]:
                raise ValueError('Invalid Harbor source UID')


def validate(manifest):
    validate_sources(manifest)
    if (
            manifest.get('format') != 1 or manifest.get('captured') is not True or
            manifest.get('operation') not in ('monthly', 'check-local') or
            manifest.get('consistency') != 'all-writers-stopped' or set(manifest['secrets']) != set(SECRETS)):
        raise ValueError('Incomplete coordinated Harbor generation')
    for value in [*manifest['secrets'].values(), manifest['inventory']['database_sha256'], manifest['inventory']['blobs_sha256']]:
        if not re.fullmatch('[a-f0-9]{64}', value):
            raise ValueError('Invalid Harbor recovery checksum')
    if any(not re.fullmatch(r'sha256:[a-f0-9]{64}', value) for value in manifest['inventory']['artifact_digests']):
        raise ValueError('Invalid Harbor recovery artifact digest')
    if manifest.get('signatures') is not None:
        signature_record(manifest['signatures'], manifest['inventory'])
    source = manifest['installation']
    if (set(source) != {'revision', 'chart_sha256', 'images'} or
            not re.fullmatch('[a-f0-9]{40}', source['revision']) or
            not re.fullmatch('[a-f0-9]{64}', source['chart_sha256']) or
            len(source['images']) != 9 or len(set(source['images'])) != 9 or
            any(not re.fullmatch(r'(docker.io/goharbor/[a-z-]+|quay.io/oauth2-proxy/oauth2-proxy):v[0-9]+[.][0-9]+[.][0-9]+@sha256:[a-f0-9]{64}', value)
                for value in source['images'])):
        raise ValueError('Harbor recovery requires immutable independently available bootstrap artifacts')
    return manifest


def signature_record(value, inventory):
    image = json.loads((ARTIFACTS / 'cosign.lock.json').read_text())['image']
    if (not isinstance(value, dict) or set(value) != {'format', 'verifier_sha256', 'image', 'projects'} or
            value.get('format') != 1 or value.get('image') != image or
            not re.fullmatch('[a-f0-9]{64}', value.get('verifier_sha256', '')) or
            not isinstance(value.get('projects'), dict) or
            set(value['projects']) != {'cloudlab-public', 'cloudlab-private'}):
        raise ValueError('Invalid recovery signer or independent verifier image')
    for digests in value['projects'].values():
        if (not isinstance(digests, list) or len(digests) != 6 or len(set(digests)) != 6 or
                digests != sorted(digests) or any(not re.fullmatch(r'sha256:[a-f0-9]{64}', digest) for digest in digests) or
                not set(digests).issubset(inventory['artifact_digests'])):
            raise ValueError('Recovery signatures must retain deployment and five rollback digests per project')
    return value


def signature_binding(value):
    public = secret('harbor-recovery-verifier')
    if set(public) != {'public_key'} or hashlib.sha256(base64.b64decode(public['public_key'], validate=True)).hexdigest() != value['verifier_sha256']:
        raise RuntimeError('Delivered public recovery verifier changed; preserve the original signer')


def cleanup_snapshots(manifest):
    validate_sources(manifest)
    for component, row in manifest['volumes'].items():
        if row['snapshot'] != manifest['generation'] + '-' + component or component not in CLAIMS:
            raise ValueError('Unexpected Harbor snapshot identity')
        snapshot = get('snapshots.longhorn.io', row['snapshot'], 'longhorn-system')
        if snapshot:
            if snapshot['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER or snapshot['spec']['volume'] != row['volume']:
                raise RuntimeError('Refusing to remove a foreign Harbor snapshot')
            kube('delete', 'snapshots.longhorn.io', row['snapshot'], '-n', 'longhorn-system', '--wait=false')
            wait(lambda: not (obj := get('snapshots.longhorn.io', row['snapshot'], 'longhorn-system')) or
                 obj.get('status', {}).get('markRemoved'), 'remove temporary Harbor snapshot', timeout=600)


def capture(monthly=False):
    started = time.monotonic()
    applications = {name: application(name) for name in APPS}
    state = {'applications': {name: {'uid': app['metadata']['uid'], 'revision': app['spec']['source']['targetRevision'],
             'values': app['spec']['source']['helm']['valuesObject']} for name, app in applications.items()}}
    if any(not application_ready(name, entry['revision']) for name, entry in state['applications'].items()):
        raise RuntimeError('Harbor must converge before coordinated capture')
    manifest = {'format': 1, 'generation': 'harbor-' + uuid.uuid4().hex[:24], 'captured': False,
                'operation': 'monthly' if monthly else 'check-local', 'installation': installation(),
                'consistency': 'all-writers-stopped', 'volumes': sources(), 'secrets': fingerprints()}
    for component, row in manifest['volumes'].items():
        row['snapshot'] = manifest['generation'] + '-' + component
    atomic(BASE / 'pending-volume.json', manifest)
    atomic(BASE / 'maintenance.json', state)
    server = copy.deepcopy(state['applications']['cloudlab-harbor']['values'])
    boundary = copy.deepcopy(state['applications']['cloudlab-harbor-configuration']['values'])
    boundary['maintenance'] = True
    try:
        manifest['phase'] = 'stop-browser'
        atomic(BASE / 'pending-volume.json', manifest)
        patch_values('cloudlab-harbor-configuration', boundary, state['applications']['cloudlab-harbor-configuration']['uid'])
        wait(lambda: not pods('browser'),
             'stop Harbor browser admission', timeout=600)
        for component in ('nginx', 'portal', 'jobservice', 'core'):
            manifest['phase'] = 'stop-' + component
            atomic(BASE / 'pending-volume.json', manifest)
            server['harbor'][component]['replicas'] = 0
            patch_values('cloudlab-harbor', server, state['applications']['cloudlab-harbor']['uid'])
            wait(lambda: not pods(component), 'stop Harbor ' + component, timeout=600)
        manifest['phase'] = 'inventory'
        atomic(BASE / 'pending-volume.json', manifest)
        manifest['inventory'] = inventory()
        signed = BASE / 'signed-artifacts.json'
        if signed.exists():
            manifest['signatures'] = signature_record(json.loads(signed.read_text()), manifest['inventory'])
            signature_binding(manifest['signatures'])
        for component in ('registry', 'database', 'redis'):
            manifest['phase'] = 'stop-' + component
            atomic(BASE / 'pending-volume.json', manifest)
            if component == 'registry':
                server['harbor']['registry']['replicas'] = 0
            else:
                server['harbor'][component]['internal']['replicas'] = 0
            patch_values('cloudlab-harbor', server, state['applications']['cloudlab-harbor']['uid'])
            wait(lambda: not pods(component), 'stop Harbor ' + component, timeout=600)
        if [pod for pod in (get('pods', namespace=NAMESPACE) or {}).get('items', [])
                if pod['status'].get('phase') not in ('Succeeded', 'Failed')]:
            raise RuntimeError('Harbor writers remain at the snapshot boundary')
        for row in manifest['volumes'].values():
            manifest['phase'] = 'snapshot'
            atomic(BASE / 'pending-volume.json', manifest)
            volume = get('volumes.longhorn.io', row['volume'], 'longhorn-system')
            if not volume or volume['metadata']['uid'] != row['volume_uid']:
                raise RuntimeError('Harbor volume identity changed before capture')
            kube('create', '-f', '-', document={'apiVersion': 'longhorn.io/v1beta2', 'kind': 'Snapshot',
                'metadata': {'name': row['snapshot'], 'namespace': 'longhorn-system', 'labels': LABEL},
                'spec': {'volume': row['volume'], 'createSnapshot': True, 'labels': {'cloudlab-generation': manifest['generation']}}})
            wait(lambda: (get('snapshots.longhorn.io', row['snapshot'], 'longhorn-system') or {}).get('status', {}).get('readyToUse'),
                 'coordinated Harbor snapshot', timeout=600)
        manifest.update(captured=True, captured_at=time.time(), capture_seconds=round(time.monotonic() - started, 3))
        atomic(BASE / 'pending-volume.json', manifest)
    finally:
        resume()
    return validate(manifest)


def run(action):
    if action == 'freshness':
        return freshness()
    monthly = action == 'monthly'
    if monthly:
        from playbooks.data.files.remote import require_window
        require_window(reserve=4 * 3600)
    with locked():
        resume()
        if action == 'resume':
            return {'maintenance_resumed': True, 'b2_reads': 0}
        if action == 'record-signatures':
            proof = signature_record(json.load(sys.stdin), inventory())
            signature_binding(proof)
            previous = BASE / 'signed-artifacts.json'
            if previous.exists() and json.loads(previous.read_text()) != proof:
                raise RuntimeError('Original recovery signature evidence changed; replacement refused')
            atomic(previous, proof)
            return {'signature_digests_recorded': sum(map(len, proof['projects'].values())), 'private_key_received': False}
        if action not in ('check-local', 'monthly', 'cleanup-fixtures'):
            raise ValueError('Unknown Harbor recovery action')
        if action == 'cleanup-fixtures':
            from automation.harbor.restore import cleanup
            cleanup()
            return {'owned_restore_removed': True, 'production_data_removed': False, 'b2_reads': 0}
        receipt = BASE / 'monthly-receipt.json'
        if monthly and receipt.exists() and not (BASE / 'pending-volume.json').exists():
            previous = json.loads(receipt.read_text())
            captured = datetime.fromtimestamp(previous['captured_at'], timezone.utc)
            if previous.get('retention_complete') and captured.strftime('%Y-%m') == datetime.now(timezone.utc).strftime('%Y-%m'):
                return {'already_verified_this_month': True, 'b2_reads': 0}
        pending = BASE / 'pending-volume.json'
        manifest = json.loads(pending.read_text()) if pending.exists() else None
        if manifest and manifest.get('operation') != ('monthly' if monthly else 'check-local'):
            raise RuntimeError('Finish the recorded Harbor recovery operation before starting another')
        if monthly:
            atomic(BASE / 'monthly-attempt.json', {'success': False, 'started_at': time.time()})
        if manifest and not manifest.get('captured'):
            cleanup_snapshots(manifest)
            pending.unlink()
            manifest = None
        manifest = validate(manifest) if manifest else capture(monthly=monthly)
        from automation.harbor.restore import run as restore
        if monthly:
            from automation.harbor.remote import Repository
            repository = Repository()
            repository.upload(manifest)
            result = repository.accept(manifest, restore(manifest, offsite=True))
            cleanup_snapshots(manifest)
            pending.unlink()
            atomic(BASE / 'monthly-attempt.json', {'success': True, 'verified_at': result['verified_at']})
            return result
        try:
            proof = restore(manifest)
            return {'capture_seconds': manifest['capture_seconds'], 'restore': proof,
                    'retained_local_generations': 0, 'b2_reads': 0}
        finally:
            cleanup_snapshots(manifest)
            pending.unlink()


if __name__ == '__main__':
    try:
        print(json.dumps(run(sys.argv[1]), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor recovery incomplete; existing data and protected maintenance receipts retained') from None
