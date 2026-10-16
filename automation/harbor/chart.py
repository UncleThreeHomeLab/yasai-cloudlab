"""Check deterministic Harbor rendering, bounded resources and retained storage."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

from automation.harbor.package import patched
from automation.harbor.values import values, POLICY

BASE = Path(__file__).resolve().parents[2] / 'platform/harbor'


def render(component='server', runtime=None, *, namespace='cloudlab-harbor', release='cloudlab-harbor'):
    command = ['helm', 'template', release, str(BASE / component if component else BASE),
               '-n', namespace, '--kube-version', '1.36.5']
    if component:
        command += ['-f', str(BASE / 'server/values.json')]
    command += ['-f', '-']
    outputs = [subprocess.run(command, input=yaml.safe_dump(runtime or {}), capture_output=True,
                              text=True, timeout=90) for _ in range(2)]
    if any(output.returncode for output in outputs) or outputs[0].stdout != outputs[1].stdout:
        raise ValueError('Harbor rendering failed or contains generated credentials')
    return [obj for obj in yaml.safe_load_all(outputs[0].stdout) if obj]


def check():
    lock = json.loads((BASE / 'server/artifact.lock.json').read_text())
    raw = (BASE / 'server/upstream.tgz').read_bytes()
    archive = (BASE / 'server' / lock['archive']).read_bytes()
    if (hashlib.sha256(raw).hexdigest() != lock['upstream_sha256'] or
            hashlib.sha256(archive).hexdigest() != lock['sha256'] or patched(raw) != archive or
            json.loads((BASE / 'server/values.json').read_text()) != {'harbor': values()}):
        raise ValueError('Harbor artifacts or compiled values changed')
    image_lock = json.loads((BASE / 'images.lock.json').read_text())
    pins = {image for name, image in image_lock.items() if name != 'browser-gate'}
    actual_images, cpu, memory = set(), 0, 0
    for obj in render():
        if obj['kind'] == 'Secret' and any(value for field in ('data', 'stringData') for value in (obj.get(field) or {}).values()):
            raise ValueError('Harbor must consume vault secrets without rendering values')
        if obj['kind'] in ('PersistentVolumeClaim', 'Ingress', 'HTTPRoute', 'ClusterRole', 'ClusterRoleBinding'):
            raise ValueError('Server chart crossed the configuration owner boundary')
        if obj['kind'] in ('Deployment', 'StatefulSet'):
            if obj['spec'].get('replicas') != 1 or obj['spec'].get('volumeClaimTemplates'):
                raise ValueError('Harbor requires one instance and independently retained claims')
            if obj['kind'] == 'Deployment' and obj['spec']['strategy']['type'] != 'Recreate':
                raise ValueError('Harbor rollout exceeds its bounded single-instance envelope')
            pod = obj['spec']['template']['spec']
            if pod.get('automountServiceAccountToken') is not False or pod.get('serviceAccountName') != 'cloudlab-harbor':
                raise ValueError('Harbor workloads must not mount deployment credentials')
            main_cpu, main_memory, init_cpu, init_memory = 0, 0, 0, 0
            for kind in ('containers', 'initContainers'):
                for container in pod.get(kind, []):
                    pin = container['image']
                    if pin not in pins or not re.fullmatch(r'docker.io/goharbor/[a-z-]+:v2[.]15[.]4@sha256:[a-f0-9]{64}', pin):
                        raise ValueError('Harbor bootstrap image must have an independent immutable upstream pin')
                    actual_images.add(pin)
                    profile = container.get('securityContext', {})
                    if (profile.get('privileged') or profile.get('allowPrivilegeEscalation') is not False or
                            profile.get('capabilities', {}).get('drop') != ['ALL']):
                        raise ValueError('Harbor container lacks its restricted security profile')
                    limits = container['resources']['limits']
                    container_cpu = int(limits['cpu'].removesuffix('m'))
                    container_memory = int(limits['memory'].removesuffix('Mi'))
                    if kind == 'containers':
                        main_cpu += container_cpu
                        main_memory += container_memory
                    else:
                        init_cpu, init_memory = max(init_cpu, container_cpu), max(init_memory, container_memory)
            cpu += max(main_cpu, init_cpu)
            memory += max(main_memory, init_memory)
    if actual_images != pins or cpu > POLICY['cpu_limit_millicores'] or memory > POLICY['memory_limit_mib']:
        raise ValueError('Harbor image inventory or resource envelope changed')
    configuration = render('', {'enabled': True})
    browser = next(obj for obj in configuration if obj['kind'] == 'Deployment')
    container = browser['spec']['template']['spec']['containers'][0]
    if container['image'] != image_lock['browser-gate'] or not re.fullmatch(
            r'quay.io/oauth2-proxy/oauth2-proxy:v7[.]15[.]5@sha256:[a-f0-9]{64}', container['image']):
        raise ValueError('Browser gate requires its independent immutable upstream pin')
    cpu += int(container['resources']['limits']['cpu'].removesuffix('m'))
    memory += int(container['resources']['limits']['memory'].removesuffix('Mi'))
    if cpu > POLICY['cpu_limit_millicores'] or memory > POLICY['memory_limit_mib']:
        raise ValueError('Browser session gate exceeds the Harbor envelope')
    claims = [obj for obj in configuration if obj['kind'] == 'PersistentVolumeClaim']
    if len(claims) != 3 or any(obj['spec']['storageClassName'] != 'cloudlab-harbor' for obj in claims):
        raise ValueError('Harbor storage must remain separate from shared SQL/S3')
    if render(''):
        raise ValueError('Disabled Harbor configuration must create nothing')
    return {'immutable_bootstrap_images': len(pins) + 1, 'cpu_limit_millicores': cpu,
            'memory_limit_mib': memory, 'independent_claims': len(claims), 'secret_values_rendered': 0}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
