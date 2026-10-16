"""Restore only isolated Harbor copies and verify database, blobs and vault binding."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import time

import yaml

from automation.harbor import recovery
from automation.mesh.kube import get, kube, condition, wait

NAMESPACE = 'cloudlab-harbor-restore'
LABEL = {'cloudlab.io/fixture': 'harbor-restore'}
PYTHON = 'docker.io/library/python:3.13-slim-bookworm@sha256:5024f48ba9441d4b13a95d3945abc6365538e3a31109833367a1923523c6efed'


def metadata(name):
    return {'name': name, 'namespace': NAMESPACE, 'labels': LABEL}


def cleanup():
    receipt = recovery.BASE / 'restore-owned.json'
    if not receipt.exists():
        if get('namespace', NAMESPACE):
            raise RuntimeError('Unrecorded Harbor restore namespace requires ownership review')
        return
    record = json.loads(receipt.read_text())
    namespace = get('namespace', NAMESPACE)
    if namespace:
        if namespace['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture'] or namespace['metadata']['uid'] != record['uid']:
            raise RuntimeError('Harbor restore namespace identity changed; cleanup refused')
        # Persist bindings even if interruption happened before readiness was observed.
        for claim in get('pvc', namespace=NAMESPACE)['items']:
            if claim['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture']:
                raise RuntimeError('Foreign claim found in Harbor restore namespace')
            if claim['spec'].get('volumeName'):
                pv = get('pv', claim['spec']['volumeName'])
                if (pv['spec']['claimRef']['uid'] != claim['metadata']['uid'] or
                        pv['spec']['storageClassName'] not in record['classes'] or pv['spec']['persistentVolumeReclaimPolicy'] != 'Delete'):
                    raise RuntimeError('Harbor restore volume binding changed; cleanup refused')
                volume = pv['spec']['csi']['volumeHandle']
                if volume not in record['volumes']:
                    record['volumes'].append(volume)
        recovery.atomic(receipt, record)
        kube('delete', 'namespace', NAMESPACE, '--wait=true', '--timeout=600s', timeout=630)
    for name in record['classes']:
        obj = get('storageclass', name)
        if obj:
            if obj['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture'] or obj.get('reclaimPolicy') != 'Delete':
                raise RuntimeError('Harbor restore StorageClass ownership changed')
            kube('delete', 'storageclass', name)
    wait(lambda: not [volume for volume in get('volumes.longhorn.io', namespace='longhorn-system')['items']
                      if volume['metadata']['name'] in record.get('volumes', [])],
         'remove disposable Harbor volumes', timeout=900)
    receipt.unlink()


def render(values):
    chart = Path('/opt/cloudlab/platform/harbor/server')
    lock = json.loads((chart / 'artifact.lock.json').read_text())
    if hashlib.sha256((chart / lock['archive']).read_bytes()).hexdigest() != lock['sha256']:
        raise RuntimeError('Harbor restore chart checksum changed')
    result = subprocess.run(['helm', 'template', 'harbor-restore', str(chart), '-n', NAMESPACE,
                             '--kube-version', '1.36.5', '-f', str(chart / 'values.json'), '-f', '-'],
                            input=yaml.safe_dump(values), capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise RuntimeError('Pinned isolated Harbor rendering failed')
    objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
    if any(obj['kind'] not in ('ConfigMap', 'Secret', 'Service', 'Deployment', 'StatefulSet') for obj in objects):
        raise RuntimeError('Isolated Harbor render escaped its namespace')
    for obj in objects:
        obj['metadata']['namespace'] = NAMESPACE
        obj['metadata'].setdefault('labels', {}).update(LABEL)
    return objects


def apply(objects):
    kube('apply', '--server-side', '--field-manager=harbor-restore', '-f', '-',
         document={'apiVersion': 'v1', 'kind': 'List', 'items': objects})


def run(manifest, offsite=False):
    recovery.validate(manifest)
    if offsite:
        from automation.data.remote import require_window
        from automation.harbor.remote import Repository
        require_window(reserve=3600)
        repository = Repository()
        for row in manifest['volumes'].values():
            repository.validate_url(row)
    if recovery.fingerprints() != manifest['secrets']:
        raise RuntimeError('Harbor recovery credentials changed; explicit mapping required before restore')
    if get('namespace', NAMESPACE) or (recovery.BASE / 'restore-owned.json').exists():
        raise RuntimeError('Previous Harbor restore fixture must be cleaned by its recorded owner')
    started = time.monotonic()
    kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {
        'name': NAMESPACE, 'labels': dict(LABEL, **{'istio.io/dataplane-mode': 'ambient', 'istio-injection': 'disabled',
                                                  'pod-security.kubernetes.io/enforce': 'restricted',
                                                  'pod-security.kubernetes.io/enforce-version': 'v1.36'})}})
    record = {'uid': get('namespace', NAMESPACE)['metadata']['uid'], 'classes': [], 'volumes': []}
    recovery.atomic(recovery.BASE / 'restore-owned.json', record)
    try:
        kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ResourceQuota',
            'metadata': metadata('restore-budget'), 'spec': {'hard': {'limits.cpu': '2', 'limits.memory': '4Gi',
                'requests.storage': '62Gi', 'persistentvolumeclaims': '3', 'pods': '9'}}})
        kube('create', '-f', '-', document={'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
            'metadata': metadata('restore-isolation'), 'spec': {'podSelector': {}, 'policyTypes': ['Ingress', 'Egress'],
                'ingress': [{'from': [{'podSelector': {}}, {'ipBlock': {'cidr': '169.254.7.127/32'}},
                    {'ipBlock': {'cidr': 'fd16:9254:7127:1337:ffff:ffff:ffff:ffff/128'}}]}],
                'egress': [{'to': [{'podSelector': {}}]}, {'to': [{'namespaceSelector': {
                    'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}}, 'podSelector': {
                    'matchLabels': {'k8s-app': 'kube-dns'}}}], 'ports': [{'protocol': protocol, 'port': 53}
                    for protocol in ('TCP', 'UDP')]}]}})
        kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ServiceAccount',
            'metadata': metadata('cloudlab-harbor'), 'automountServiceAccountToken': False})
        for name in recovery.SECRETS:
            kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret',
                'metadata': metadata(name), 'type': 'Opaque', 'data': recovery.secret(name)})
        base = get('storageclass', recovery.NAMESPACE)['parameters']
        for component, row in manifest['volumes'].items():
            name = NAMESPACE + '-' + component
            record['classes'].append(name)
            recovery.atomic(recovery.BASE / 'restore-owned.json', record)
            parameters = dict(base)
            parameters['fromBackup' if offsite else 'dataSource'] = row['url'] if offsite else 'snap://' + row['volume'] + '/' + row['snapshot']
            kube('create', '-f', '-', document={'apiVersion': 'storage.k8s.io/v1', 'kind': 'StorageClass',
                'metadata': {'name': name, 'labels': LABEL}, 'provisioner': 'driver.longhorn.io',
                'allowVolumeExpansion': True, 'reclaimPolicy': 'Delete', 'volumeBindingMode': 'Immediate',
                'parameters': parameters})
            kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'PersistentVolumeClaim',
                'metadata': metadata(row['claim']), 'spec': {'accessModes': ['ReadWriteOnce'], 'storageClassName': name,
                    'resources': {'requests': {'storage': row['size']}}}})
        original = recovery.application('cloudlab-harbor')['spec']['source']['helm']['valuesObject']
        values = copy.deepcopy(original)
        values['harbor']['externalURL'] = 'http://harbor.' + NAMESPACE + '.svc'
        for name in ('core', 'nginx', 'portal', 'jobservice'):
            values['harbor'][name]['replicas'] = 0
        objects = render(values)
        apply(objects)
        for component in ('database', 'registry', 'redis'):
            wait(lambda: len(ready := [pod for pod in recovery.pods(component, NAMESPACE) if condition(pod, 'Ready')]) == 1,
                 'restored Harbor ' + component, timeout=900)
        for row in manifest['volumes'].values():
            claim = get('pvc', row['claim'], NAMESPACE)
            pv = get('pv', claim['spec']['volumeName'])
            volume = pv['spec']['csi']['volumeHandle']
            if claim['metadata']['uid'] == row['claim_uid'] or volume == row['volume']:
                raise RuntimeError('Harbor fixture resolved to a production volume')
            record['volumes'].append(volume)
        recovery.atomic(recovery.BASE / 'restore-owned.json', record)
        if recovery.inventory(NAMESPACE) != manifest['inventory']:
            raise RuntimeError('Restored Harbor database, artifact references or blob/signature bytes differ')
        # Restored browser sessions are never valid recovery material.
        recovery.execute('redis', ['valkey-cli', 'FLUSHALL'], NAMESPACE)
        for name in ('core', 'nginx', 'portal'):
            values['harbor'][name]['replicas'] = 1
        apply(render(values))
        for component in ('core', 'nginx', 'portal'):
            wait(lambda: len([pod for pod in recovery.pods(component, NAMESPACE) if condition(pod, 'Ready')]) == 1,
                 'restored Harbor independent access ' + component, timeout=900)
        script = """import os,json,base64,urllib.request
try:
 auth=base64.b64encode((os.environ['USERNAME']+':'+os.environ['PASSWORD']).encode()).decode()
 req=urllib.request.Request('http://harbor.cloudlab-harbor-restore.svc/api/v2.0/users/current',headers={'Authorization':'Basic '+auth})
 with urllib.request.urlopen(req,timeout=30) as response: user=json.load(response)
 if user['username']!=os.environ['USERNAME'] or not user['sysadmin_flag']:raise RuntimeError()
 print(json.dumps({'independent_emergency_api':True}))
except Exception:raise SystemExit('Isolated Harbor recovery authentication failed') from None
"""
        kube('create', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Pod', 'metadata': metadata('restore-probe'),
            'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                'securityContext': {'runAsNonRoot': True, 'runAsUser': 65532, 'runAsGroup': 65532,
                                    'seccompProfile': {'type': 'RuntimeDefault'}},
                'containers': [{'name': 'probe', 'image': PYTHON, 'command': ['python', '-c', script],
                    'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                    'resources': {'requests': {'cpu': '10m', 'memory': '32Mi'}, 'limits': {'cpu': '50m', 'memory': '64Mi'}},
                    'env': [{'name': name, 'valueFrom': {'secretKeyRef': {'name': 'harbor-emergency', 'key': key}}}
                            for name, key in (('USERNAME', 'username'), ('PASSWORD', 'password'))]}]}})
        def complete():
            phase = get('pod', 'restore-probe', NAMESPACE)['status'].get('phase')
            if phase == 'Failed':
                raise RuntimeError('Restored Harbor emergency API rejected current vault credentials')
            return phase == 'Succeeded'
        wait(complete, 'independent restored Harbor API', timeout=180)
        return {'restored': True, 'database_and_blob_checksums': True, 'signing_inputs_preserved': True,
                'artifact_digests_verified': len(manifest['inventory']['artifact_digests']),
                'independent_emergency_api': True, 'restored_sessions_invalidated': True,
                'offsite_reads': offsite, 'restore_seconds': round(time.monotonic() - started, 3)}
    finally:
        cleanup()
