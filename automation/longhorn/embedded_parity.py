"""Compare pinned Argo's embedded Helm render before permitting Longhorn adoption."""
import base64
import io
import json
import os
from pathlib import Path
import shlex
import sys
import tarfile

import yaml

from chart import ROOT, render

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tailscale'))
from verify_access import ssh


def canonical(objects):
    return sorted((json.dumps(obj, sort_keys=True) for obj in objects))


def main():
    objects = render()  # Validate the archive and image locks before transmission.
    lock = json.loads((ROOT / 'artifact.lock.json').read_text())
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        for name in ('Chart.yaml', 'Chart.lock', 'values.json', lock['archive'],
                     'templates/config.yaml'):
            tar.add(ROOT / name, arcname='chart/' + name, recursive=False)
    script = '''set -eu
directory=$(mktemp -d /tmp/cloudlab-longhorn-parity.XXXXXX)
trap 'rm -rf -- "$directory"' EXIT
base64 -d | tar -xz -C "$directory"
helm template longhorn "$directory/chart" --namespace longhorn-system --include-crds --kube-version KUBE_VERSION --values "$directory/chart/values.json"
'''.replace('KUBE_VERSION', shlex.quote(lock['kube_version']))
    command = ('/usr/local/bin/k3s kubectl exec -i -n argocd deployment/argocd-repo-server '
               '-- sh -c ' + shlex.quote(script))
    output = ssh('VM', os.environ['VM_HOST'], command,
                 input=base64.b64encode(archive.getvalue()).decode(), timeout=180)
    actual = [item for item in yaml.safe_load_all(output) if item]
    if canonical(actual) != canonical(objects):
        raise RuntimeError('Argo embedded Helm differs from the bootstrap Longhorn render; adoption refused')
    ssh('VM', os.environ['VM_HOST'],
        '/usr/local/bin/k3s kubectl apply --server-side --dry-run=server --field-manager=cloudlab -f -',
        input=json.dumps({'apiVersion': 'v1', 'kind': 'List', 'items': objects}), timeout=180)
    print(json.dumps({'embedded_helm_parity': True, 'server_dry_run': True,
                      'objects': len(actual), 'resources_applied': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Longhorn embedded-render parity failed; adoption remains blocked, diagnostics withheld') from None
