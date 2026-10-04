"""Check the backup chart with Argo's embedded Helm before enabling its writer."""
import base64
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile

import yaml

from backup_chart import ROOT, render

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tailscale'))
from verify_access import ssh


def verify():
    # No real destination or credential needs to enter the repo-server fixture.
    expected, values = render({'store': 'cloudlab', 'bucket': 'parity-fixture', 'region': 'fixture-region'})
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name in ('Chart.yaml', 'values.yaml', 'values.schema.json', 'policy.json', 'templates/resources.yaml'):
            tar.add(ROOT / name, arcname='chart/' + name, recursive=False)
        raw = json.dumps(values).encode()
        item = tarfile.TarInfo('values.json')
        item.size = len(raw)
        item.mode = 0o600
        tar.addfile(item, io.BytesIO(raw))
    script = '''set -eu
directory=$(mktemp -d /tmp/cloudlab-backup-parity.XXXXXX)
trap 'rm -rf -- "$directory"' EXIT
base64 -d | tar -xz -C "$directory"
helm template cloudlab-longhorn-backup "$directory/chart" --namespace longhorn-system --values "$directory/values.json"
'''
    output = ssh('VM', os.environ['VM_HOST'],
                 '/usr/local/bin/k3s kubectl exec -i -n argocd deployment/argocd-repo-server -- sh -c ' + shlex.quote(script),
                 input=base64.b64encode(archive.getvalue()).decode(), timeout=180)
    actual = [obj for obj in yaml.safe_load_all(output) if obj]
    canonical = lambda items: sorted(json.dumps(obj, sort_keys=True) for obj in items)
    if canonical(actual) != canonical(expected):
        raise RuntimeError('Embedded Helm backup declarations differ; adoption refused')
    print(json.dumps({'backup_embedded_helm_parity': True, 'objects': len(actual), 'private_inputs_used': False}))


if __name__ == '__main__':
    try:
        verify()
    except Exception:
        raise SystemExit('Backup embedded Helm parity failed; diagnostics withheld') from None
