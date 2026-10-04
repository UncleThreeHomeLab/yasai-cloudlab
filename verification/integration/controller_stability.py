"""Observe healthy foundation controllers without exporting object metadata."""
import json
import subprocess
import sys
import time

NAMESPACES = ('kube-system', 'external-secrets', 'longhorn-system')


def fingerprint(items):
    controllers, pods = {}, {}
    for obj in items:
        meta, status = obj['metadata'], obj.get('status', {})
        kind = obj['kind']
        key = (meta['namespace'], kind, meta['uid'])
        if meta.get('deletionTimestamp'):
            raise RuntimeError('Controller or pod deletion during stability observation')
        if kind == 'Pod':
            if status.get('phase') == 'Succeeded':
                continue
            if (status.get('phase') != 'Running' or not any(
                    c['type'] == 'Ready' and c['status'] == 'True' for c in status.get('conditions', []))):
                raise RuntimeError('Foundation pod is not ready')
            containers = status.get('containerStatuses', []) + status.get('initContainerStatuses', [])
            pods[key] = tuple(sorted((c['name'], c.get('restartCount', 0), c.get('containerID', '')) for c in containers))
        else:
            if status.get('observedGeneration', 0) < meta['generation']:
                raise RuntimeError('Controller has not observed its declared generation')
            if kind == 'DaemonSet':
                desired = status.get('desiredNumberScheduled', 0)
                ready = status.get('numberReady', 0)
                updated = status.get('updatedNumberScheduled', 0)
            else:
                desired = obj['spec'].get('replicas', 1)
                ready = status.get('readyReplicas', 0)
                updated = status.get('updatedReplicas', 0)
            if desired < 1 or ready != desired or updated != desired:
                raise RuntimeError('Foundation controller rollout is not complete')
            controllers[key] = (meta['generation'], desired)
    if not controllers or not pods:
        raise RuntimeError('Stability observation requires controllers and pods')
    return controllers, pods


def sample(namespaces=NAMESPACES):
    items = []
    for namespace in namespaces:
        result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', 'get',
            'deployments,daemonsets,statefulsets,pods', '-n', namespace, '-o', 'json'],
            capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('Controller stability query failed; private output withheld')
        current = json.loads(result.stdout)['items']
        if not current:
            raise RuntimeError('Required foundation namespace has no controllers')
        items.extend(current)
    return fingerprint(items)


def main(namespaces=NAMESPACES):
    baseline = sample(namespaces)
    started = time.monotonic()
    while time.monotonic() - started < 60:
        time.sleep(10)
        if sample(namespaces) != baseline:
            raise RuntimeError('Controller rollout, pod replacement or restart during stability observation')
    print(json.dumps({'stable': True, 'seconds': round(time.monotonic() - started, 1),
                      'controllers': len(baseline[0]), 'pods': len(baseline[1])}))


if __name__ == '__main__':
    try:
        main(tuple(sys.argv[1:]) or NAMESPACES)
    except (RuntimeError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Controller stability check failed') from None
