"""Check the native admission chart and digest-locked controller envelope."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[4]
BASE = ROOT / 'platform/delivery/admission'


def render(policies=False, values=None):
    command = ['helm', 'template', 'cloudlab-workload-policy' if policies else 'cloudlab-kyverno',
               str(BASE / 'policies' if policies else BASE), '--namespace', 'cloudlab-policy',
               '--kube-version', '1.36.5', '--skip-tests']
    if not policies:
        command += ['-f', str(BASE / 'values.json')]
    command += ['-f', '-']
    results = [subprocess.run(command, input=yaml.safe_dump(values or {}), capture_output=True,
                              text=True, timeout=90, check=True).stdout for _ in range(2)]
    if results[0] != results[1]:
        raise ValueError('Admission chart rendering must not generate secrets or random inputs')
    return [row for row in yaml.safe_load_all(results[0]) if row]


def check():
    lock = json.loads((BASE / 'artifact.lock.json').read_text())
    if hashlib.sha256((BASE / lock['archive']).read_bytes()).hexdigest() != lock['sha256']:
        raise ValueError('Admission chart checksum differs from its upstream lock')
    pins = json.loads((BASE / 'images.lock.json').read_text())
    if any(not re.fullmatch(r'.+@sha256:[a-f0-9]{64}', value) for value in pins.values()):
        raise ValueError('Admission tools require independent immutable image pins')
    dockerfile = (ROOT / 'ansible/runner/Dockerfile').read_text()
    if 'FROM ' + pins['kyverno-cli'] + ' AS kyverno' not in dockerfile:
        raise ValueError('Native policy test tool differs from its source lock')
    cpu, memory, images, crds = 0, 0, set(), []
    for row in render():
        kind, metadata = row['kind'], row['metadata']
        if kind in ('Secret', 'Job', 'PersistentVolumeClaim') or 'helm.sh/hook' in (metadata.get('annotations') or {}):
            raise ValueError('Admission must not depend on generated credentials, hooks or persistent data')
        if kind == 'CustomResourceDefinition':
            crds.append(row)
            if (metadata.get('annotations') or {}).get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false':
                raise ValueError('Admission APIs require explicit retention and server-side apply')
        if kind != 'Deployment':
            continue
        pod = row['spec']['template']['spec']
        if row['spec']['template']['metadata']['labels']['app.kubernetes.io/component'] == 'admission-controller':
            if (row['spec']['replicas'] != 2 or
                    row['spec']['strategy']['rollingUpdate'] != {'maxSurge': 0, 'maxUnavailable': 1} or
                    not pod.get('affinity', {}).get('podAntiAffinity', {}).get('requiredDuringSchedulingIgnoredDuringExecution')):
                raise ValueError('Admission requires two distinct nodes and a rollout that fits both nodes')
        if pod.get('hostNetwork') or pod.get('hostPID') or any('hostPath' in volume for volume in pod.get('volumes', [])):
            raise ValueError('Admission cannot use host privileges or mounts')
        for field in ('containers', 'initContainers'):
            for container in pod.get(field, []):
                images.add(container['image'])
                profile = container.get('securityContext', {})
                if (profile.get('allowPrivilegeEscalation') is not False or profile.get('privileged') or
                        profile.get('runAsNonRoot') is not True or profile.get('readOnlyRootFilesystem') is not True or
                        profile.get('capabilities', {}).get('drop') != ['ALL'] or
                        profile.get('seccompProfile', {}).get('type') != 'RuntimeDefault'):
                    raise ValueError('Admission container lacks the restricted profile')
                if field == 'containers':
                    limits = container['resources']['limits']
                    cpu += int(limits['cpu'].removesuffix('m')) * row['spec']['replicas']
                    memory += int(limits['memory'].removesuffix('Mi')) * row['spec']['replicas']
    if images != {value for key, value in pins.items() if key != 'kyverno-cli'} or cpu > 1200 or memory > 1024:
        raise ValueError('Admission exceeds its image or steady-state resource envelope')
    for name in ('validatingpolicies', 'imagevalidatingpolicies'):
        crd = next(row for row in crds if row['metadata']['name'] == name + '.policies.kyverno.io')
        if not any(version['name'] == 'v1' and version['served'] for version in crd['spec']['versions']):
            raise ValueError('Native admission API does not serve the selected policy version')
    policies = render(True)
    actions = yaml.safe_load((BASE / 'policies/values.yaml').read_text())['validationActions']
    if actions not in (['Audit', 'Warn'], ['Deny']) or len(policies) != 2 or any(
            policy['spec']['validationActions'] != actions for policy in policies):
        raise ValueError('Workload policies must use their declared audit or enforcement mode')
    return {'runtime_images': len(images), 'cpu_limit_millicores': cpu, 'memory_limit_mib': memory,
            'retained_crds': len(crds), 'policy_mode': 'enforce' if actions == ['Deny'] else 'audit'}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
