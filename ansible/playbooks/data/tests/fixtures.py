"""Synthetic shared data inputs and service approvals."""
import copy
from pathlib import Path
import yaml


def shared_data():
    root = Path(__file__).resolve().parents[4]
    base = yaml.safe_load((root / 'charts/service/values.yaml').read_text())
    catalog, approvals = [], {}
    for name in ('notes', 'fixture'):
        definition = copy.deepcopy(base)
        definition['name'] = name
        definition['data'] = {kind: {'name': name, 'credentialReference': name + '-' + kind, 'retention': 'retain'} for kind in ('database', 'bucket')}
        approval = {'name': name, 'namespace': 'cloudlab-app-' + name, 'repository': 'https://github.com/example/application.git',
            'revision': 'b' * 40, 'valuesPath': 'apps/' + name + '.yaml', 'secretReferences': [name + '-database', name + '-bucket'], 'configMaps': []}
        catalog.append({'definition': definition, 'approval': approval, 'publication': 'retired' if name == 'fixture' else 'published'})
        approvals[name + '-database'] = {'kind': 'database', 'service': name, 'name': name, 'item': 'cnpg-' + name + '-production',
            'migrationItem': 'cnpg-' + name + '-migration', 'applicationRole': name + '_app', 'migrationRole': name + '_migration'}
        approvals[name + '-bucket'] = {'kind': 'bucket', 'service': name, 'name': name, 'item': 's3-' + name + '-production'}
    return {'sharedInputs': True, 'zone': 'example.invalid', 'production': True,
        'database': 'notes', 'applicationRole': 'notes_app', 'migrationRole': 'notes_migration', 'backupRole': 'backup', 'bucket': 'notes',
        'identity': {'enabled': True, 'database': 'keycloak', 'role': 'keycloak'}, 'catalog': catalog, 'dataApprovals': approvals}
