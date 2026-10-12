"""Offline service and notes packaging checks, shared by Compose and clean clones."""
import json
from pathlib import Path
import subprocess

import yaml

from automation.services.contract import validate
from automation.services.package import check
from automation.services.gitops import resources

ROOT = Path(__file__).resolve().parents[2]


def run():
    check()
    synthetic = validate(yaml.safe_load((ROOT / 'apps/synthetic.yaml').read_text()))
    resources(synthetic, {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic',
                         'repository': 'https://github.com/example/platform.git', 'revision': 'a' * 40,
                         'valuesPath': 'apps/synthetic.yaml', 'secretReferences': [], 'configMaps': []},
              'https://github.com/example/platform.git', 'a' * 40)
    notes = yaml.safe_load((ROOT / 'apps/notes/values.yaml').read_text())
    for definition in notes.values():
        validate(definition)
    command = ['helm', 'template', 'notes', str(ROOT / 'apps/notes'), '-n', 'cloudlab-app-notes',
               '--kube-version', '1.36.5']
    first = subprocess.run(command, capture_output=True, check=True, timeout=90).stdout
    second = subprocess.run(command, capture_output=True, check=True, timeout=90).stdout
    if first != second:
        raise ValueError('Notes render is nondeterministic')
    objects = [o for o in yaml.safe_load_all(first) if o]
    if len([o for o in objects if o['kind'] == 'Deployment']) != 2:
        raise ValueError('Notes requires exactly two services')
    if {o['kind'] for o in objects} != {'ConfigMap', 'Deployment', 'Service', 'ServiceAccount'}:
        raise ValueError('Notes chart must not own shared resources or secret values')
    return {'service_schema': True, 'source_artifacts': True, 'notes_services': 2,
            'shared_resources_installed': 0, 'render_deterministic': True}


if __name__ == '__main__':
    print(json.dumps(run(), sort_keys=True))
