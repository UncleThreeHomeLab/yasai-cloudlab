"""Crash one verified proxy container without overlapping StatefulSet identities."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def validate(payload, container):
    status = container['status']
    labels = status['labels']
    if (payload['name'] not in ('cloudlab-ingress-0', 'cloudlab-ingress-1', 'cloudlab-api-0', 'cloudlab-api-1')
            or labels.get('io.kubernetes.pod.namespace') != 'tailscale'
            or labels.get('io.kubernetes.pod.name') != payload['name']
            or labels.get('io.kubernetes.pod.uid') != payload['uid']
            or status.get('id') != payload['container_id']
            or status.get('state') != 'CONTAINER_RUNNING'
            or status.get('metadata', {}).get('name') not in ('tailscale', 'k8s-proxy')):
        raise RuntimeError('Crash target is not the selected running access proxy container')


def run(payload):
    identity = payload['container_id']
    if len(identity) != 64 or any(char not in '0123456789abcdef' for char in identity):
        raise RuntimeError('Invalid container identity')
    result = subprocess.run(['/usr/local/bin/k3s', 'crictl', 'inspect', identity],
                            capture_output=True, text=True, timeout=30, check=True)
    container = json.loads(result.stdout)
    validate(payload, container)
    pid = int(container['info']['pid'])
    if pid <= 1:
        raise RuntimeError('Refuse host init or an invalid container process')
    descriptor = os.pidfd_open(pid)
    try:
        if identity not in Path('/proc/' + str(pid) + '/cgroup').read_text():
            raise RuntimeError('Process does not belong to the selected container cgroup')
        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
    finally:
        os.close(descriptor)
    return {'crashed_container': identity, 'retained_pod_uid': payload['uid']}


if __name__ == '__main__':
    try:
        print(json.dumps(run(json.load(sys.stdin))))
    except Exception:
        raise SystemExit('Proxy crash fixture refused or failed; host and control-plane processes retained.') from None
