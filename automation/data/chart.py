"""Offline data chart contracts: exact artifacts, owners, storage and hooks."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.data.vendor_cnpg import patched
from automation.gitops.render import images


def render(name, values=None):
    command = ['helm', 'template', 'cloudlab-' + name, str(ROOT / 'platform/data' / name),
               '--namespace', 'cnpg-system' if name == 'cnpg' else 'cloudlab-data',
               '--kube-version', '1.36.5', '--include-crds']
    if values:
        command += ['--values', '-']
    first = subprocess.run(command, input=json.dumps(values) if values else None, capture_output=True, text=True, timeout=90)
    second = subprocess.run(command, input=json.dumps(values) if values else None, capture_output=True, text=True, timeout=90)
    if first.returncode or second.returncode or first.stdout != second.stdout:
        raise ValueError('Data chart render failed or is nondeterministic: ' + name)
    return [obj for obj in yaml.safe_load_all(first.stdout) if obj]


def check():
    records = {}
    for name in ('cnpg', 'seaweedfs'):
        base = ROOT / 'platform/data' / name
        lock = json.loads((base / 'artifact.lock.json').read_text())
        artifact = (base / lock['archive']).read_bytes()
        if hashlib.sha256(artifact).hexdigest() != lock['sha256']:
            raise ValueError('Data chart artifact checksum mismatch')
        if name == 'cnpg' and patched((base / 'upstream.tgz').read_bytes()) != artifact:
            raise ValueError('CNPG patch differs from its source')
        records[name] = render(name)
        if set(images(records[name])) != {lock['image']}:
            raise ValueError('Data chart image differs from its lock')
        if any('helm.sh/hook' in obj['metadata'].get('annotations', {}) for obj in records[name]):
            raise ValueError('Steady-state data charts must not rely on Helm hooks')
        for obj in records[name]:
            if obj['kind'] == 'Secret':
                raise ValueError('Data chart must not own controller-generated Secret values')
            if obj['kind'] == 'CustomResourceDefinition' and obj['metadata'].get('annotations', {}).get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false':
                raise ValueError('CNPG CRD retention is missing')
            if obj['kind'] == 'Service' and obj['spec'].get('type', 'ClusterIP') != 'ClusterIP':
                raise ValueError('Data service is publicly exposed')
            if obj['kind'] in ('StatefulSet', 'Deployment'):
                if obj['spec']['replicas'] != 1:
                    raise ValueError('Selected data topology has changed')
                pod = obj['spec']['template']['spec']
                if any('hostPath' in volume for volume in pod.get('volumes', [])):
                    raise ValueError('Data state must not use hostPath')
                for container in pod['containers'] + pod.get('initContainers', []):
                    if not container.get('resources', {}).get('limits'):
                        raise ValueError('Data container lacks resource limits')
    claims = [claim for obj in records['seaweedfs'] if obj['kind'] == 'StatefulSet'
              for claim in obj['spec'].get('volumeClaimTemplates', [])]
    if len(claims) != 3 or any(claim['spec'].get('storageClassName') != 'cloudlab-data' for claim in claims):
        raise ValueError('SeaweedFS must persist master, filer and object state explicitly')
    config = render('configuration')
    cluster = next(obj for obj in config if obj['kind'] == 'Cluster')
    if cluster['spec']['instances'] != 1 or cluster['spec']['storage']['storageClass'] != 'cloudlab-data' or cluster['spec'].get('backup'):
        raise ValueError('CNPG topology or no-WAL policy changed')
    storage = next(obj for obj in config if obj['kind'] == 'StorageClass')
    if (storage['parameters']['numberOfReplicas'] != '2' or json.loads(storage['parameters']['recurringJobSelector']) != [{'name': 'application-logical-only', 'isGroup': True}]
            or storage['metadata']['annotations']['storageclass.kubernetes.io/is-default-class'] != 'false'):
        raise ValueError('Explicit two-replica logical-only storage contract changed')
    # Upstream post-install/post-upgrade hooks map to Argo PostSync; they do not
    # provide periodic drift reconciliation. Keep them disabled and assert absence.
    return {'operator_resources': len(records['cnpg']), 'seaweedfs_resources': len(records['seaweedfs']),
            'configuration_resources': len(config), 'helm_hooks': 0, 'persistent_seaweedfs_claims': len(claims)}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
