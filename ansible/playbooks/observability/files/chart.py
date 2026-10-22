"""Verify exact chart inputs, images, resources, retention and native ownership."""
import hashlib
import json
from pathlib import Path
import re
import subprocess

import yaml

from playbooks.argocd.files.render import images
from playbooks.observability.files.package import retained, kiali_declarative, tempo_protocols
from playbooks.observability.files.values import values
from playbooks.observability.files.configuration import POLICY

BASE = Path(__file__).resolve().parents[4] / 'platform/observability'
COMPONENTS = ('prometheus', 'loki', 'tempo', 'alloy', 'kiali')


def render(name, runtime=None):
    command = ['helm', 'template', 'cloudlab-' + name, str(BASE / name), '-n', POLICY['namespace'],
               '--kube-version', '1.36.5', '--include-crds', '-f', str(BASE / name / 'values.json')]
    if runtime is not None:
        command += ['-f', '-']
    results = [subprocess.run(command, input=yaml.safe_dump(runtime) if runtime is not None else None,
                              capture_output=True, text=True, timeout=90) for _ in range(2)]
    if any(r.returncode for r in results) or results[0].stdout != results[1].stdout:
        raise ValueError('Telemetry chart failed or is nondeterministic: ' + name)
    return [o for o in yaml.safe_load_all(results[0].stdout) if o]


def configuration(enabled=False):
    result = subprocess.run(['helm', 'template', 'cloudlab-observability', str(BASE),
        '-n', POLICY['namespace'], '--kube-version', '1.36.5', '--set', 'enabled=' + str(enabled).lower(),
        '--set', 'monitoringEnabled=' + str(enabled).lower()],
        capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError('Telemetry boundary chart failed')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]


def check():
    pins = json.loads((BASE / 'images.lock.json').read_text())
    expected = {value.rsplit('@', 1)[1] for value in pins.values()}
    cpu, memory, crds = 0, 0, 0
    identities = set()
    for name in COMPONENTS:
        path = BASE / name
        lock = json.loads((path / 'artifact.lock.json').read_text())
        raw = (path / lock['archive']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != lock['sha256']:
            raise ValueError('Telemetry chart artifact checksum mismatch')
        patcher = {'prometheus': retained, 'kiali': kiali_declarative, 'tempo': tempo_protocols}.get(name)
        if patcher:
            upstream = (path / 'upstream.tgz').read_bytes()
            if hashlib.sha256(upstream).hexdigest() != lock['upstream_sha256'] or patcher(upstream) != raw:
                raise ValueError('Telemetry declarative patch differs from pinned upstream')
        if json.loads((path / 'values.json').read_text()) != {lock['chart']: values(name)}:
            raise ValueError('Telemetry settings differ from their policy compiler')
        objects = render(name)
        for ref in images(objects):
            if not re.search(r'@sha256:[a-f0-9]{64}$', ref) or ref.rsplit('@', 1)[1] not in expected:
                raise ValueError('Telemetry image differs from the pin inventory: ' + name)
        for obj in objects:
            meta, kind = obj['metadata'], obj['kind']
            identity = (obj['apiVersion'], kind, meta.get('namespace', POLICY['namespace']), meta['name'])
            if identity in identities: raise ValueError('Telemetry has competing object owners')
            identities.add(identity)
            configuration_secret = (kind == 'Secret' and meta['name'] == 'alertmanager-cloudlab' and
                                    set(obj.get('data', {})) == {'alertmanager.yaml'})
            if (kind == 'Secret' and not configuration_secret) or kind == 'Job' or 'helm.sh/hook' in (meta.get('annotations') or {}):
                raise ValueError('Steady telemetry charts cannot generate credentials or depend on hooks')
            if kind == 'CustomResourceDefinition':
                crds += 1
                if meta.get('annotations', {}).get('argocd.argoproj.io/sync-options') != 'ServerSideApply=true,Prune=false,Delete=false':
                    raise ValueError('Monitoring API retention missing')
            if kind == 'Service' and obj['spec'].get('type', 'ClusterIP') != 'ClusterIP':
                raise ValueError('Telemetry service is publicly exposed')
            if kind in ('Deployment', 'DaemonSet', 'StatefulSet'):
                copies = 2 if kind == 'DaemonSet' else obj['spec'].get('replicas', 1)
                containers = obj['spec']['template']['spec'].get('containers', [])
                for container in containers:
                    limits = container.get('resources', {}).get('limits', {})
                    if set(limits) != {'cpu', 'memory'}:
                        raise ValueError('Telemetry container lacks explicit resource limits: ' + container['name'])
                    cpu += int(limits['cpu'].removesuffix('m')) * copies
                    memory += int(limits['memory'].removesuffix('Mi')) * copies
                for claim in obj['spec'].get('volumeClaimTemplates', []):
                    if claim['spec'].get('storageClassName') != POLICY['storage_class']:
                        raise ValueError('Telemetry PVC lacks its backup-excluded storage class')
            if kind in ('Prometheus', 'Alertmanager'):
                limits = obj['spec']['resources']['limits']
                cpu += int(limits['cpu'].removesuffix('m'))
                memory += int(limits['memory'].removesuffix('Mi'))
                # Operator creates one main plus one bounded reloader per CR.
                cpu += 25
                memory += 48
            if kind == 'PersistentVolumeClaim' and obj['spec'].get('storageClassName') != POLICY['storage_class']:
                raise ValueError('Telemetry PVC can inherit monthly backups')
    if cpu > POLICY['cpu_limit_millicores'] or memory > POLICY['memory_limit_mib']:
        raise ValueError('Telemetry exceeds its agreed domain envelope')
    prometheus = values('prometheus')['prometheus']['prometheusSpec']
    if prometheus['retention'] != '7d' or prometheus['retentionSize'] != '25GB' or prometheus.get('remoteWrite'):
        raise ValueError('Metrics local retention or no-offsite policy changed')
    return {'objects': len(identities), 'crds': crds, 'cpu_limit_millicores': cpu,
            'memory_limit_mib': memory, 'offsite_backups': 0, 'deterministic': True}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
