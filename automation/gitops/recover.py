"""Recover only accepted Argo controller memory from published, pinned code."""
import json
import os
from pathlib import Path
import shlex

from dotenv import dotenv_values

from automation.connectivity.preflight import ssh
from automation.gitops.render import committed_payload


def local():
    payload = committed_payload()
    payload['operator'] = [o for o in payload['operator'] if o['kind'] == 'StatefulSet' and
                           o['metadata']['name'] == 'argocd-application-controller']
    payload = {key: payload[key] for key in ('operator', 'version', 'revision', 'repository', 'branch')}
    environment = dotenv_values(Path(__file__).resolve().parents[2] / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        if not environment.get(key):
            raise RuntimeError('Controller recovery requires existing VM SSH inputs')
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    script = "import sys;sys.path.insert(0,'/opt/cloudlab/gitops');__file__='/opt/cloudlab/gitops/bootstrap.py';\n"
    script += Path(__file__).with_name('bootstrap.py').read_text()
    return json.loads(ssh('VM', os.environ['VM_HOST'],
        'python3 -c ' + shlex.quote(script) + ' --recover-controller', input=json.dumps(payload), timeout=1500))


if __name__ == '__main__':
    try:
        print(json.dumps(local(), sort_keys=True))
    except Exception:
        raise SystemExit('Argo controller recovery incomplete; retained credentials and checkpoint preserved') from None
