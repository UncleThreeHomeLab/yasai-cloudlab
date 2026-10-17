"""Recover only accepted Argo controller memory from published, pinned code."""
import json
import os
from pathlib import Path
import shlex

from dotenv import dotenv_values

from playbooks.access.files.preflight import ssh
from playbooks.argocd.files.render import committed_payload


def local():
    payload = committed_payload()
    payload['operator'] = [o for o in payload['operator'] if o['kind'] == 'StatefulSet' and
                           o['metadata']['name'] == 'argocd-application-controller']
    payload = {key: payload[key] for key in ('operator', 'version', 'revision', 'repository', 'branch')}
    environment = dotenv_values(Path(__file__).resolve().parents[4] / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        if not environment.get(key):
            raise RuntimeError('Controller recovery requires existing VM SSH inputs')
        os.environ[key] = environment[key]
    os.environ['VM_PORT'] = environment.get('VM_PORT') or '22'
    # Load the reviewed transaction and repair code in memory, even when host
    # bootstrap tooling predates this runner. No controller or Git fetch is needed.
    remote_path = '/opt/cloudlab/gitops/'
    script = "import sys,types;sys.path.insert(0," + repr(remote_path) + ");"
    script += "bootstrap=types.ModuleType('bootstrap');bootstrap.__file__=" + repr(remote_path + 'bootstrap.py') + ";"
    script += "sys.modules['bootstrap']=bootstrap;exec(" + repr(Path(__file__).with_name('bootstrap.py').read_text()) + ",bootstrap.__dict__);\n"
    script += "__file__=" + repr(remote_path + 'controller_recovery.py') + ";\n"
    script += Path(__file__).with_name('controller_recovery.py').read_text()
    script += "\nprint(json.dumps(recover_controller(json.load(sys.stdin))))\n"
    return json.loads(ssh('VM', os.environ['VM_HOST'],
        'python3 -c ' + shlex.quote(script), input=json.dumps(payload), timeout=1500))


if __name__ == '__main__':
    try:
        print(json.dumps(local(), sort_keys=True))
    except Exception:
        raise SystemExit('Argo controller recovery incomplete; retained credentials and checkpoint preserved') from None
