"""Administrator-owned namespace budgets and fixed ApplicationSet destinations."""
import re

from playbooks.services.files.contract import validate

def resources(definition, approval, platform_repository, platform_revision):
    definition = validate(definition)
    required = {'name', 'repository', 'revision', 'valuesPath', 'namespace', 'secretReferences', 'configMaps'}
    if not required <= set(approval) <= required | {'visibility', 'chartPath'} or approval.get('visibility', 'public') not in ('public', 'private'):
        raise ValueError('Administrator approval requires an exact source and namespace')
    if approval.get('chartPath', 'charts/service') not in ('charts/service', 'apps/notes'):
        raise ValueError('Service chart source is not approved')
    name, namespace = approval['name'], approval['namespace']
    if (not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', name) or
            namespace != 'cloudlab-app-' + name or
            not re.fullmatch(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git', approval['repository']) or
            not re.fullmatch(r'[a-f0-9]{40}', approval['revision']) or
            not re.fullmatch(r'[a-f0-9]{40}', platform_revision) or
            not re.fullmatch(r'apps/[a-z0-9/-]+[.]yaml', approval['valuesPath']) or
            '..' in approval['valuesPath']):
        raise ValueError('Unapproved service source or destination')
    if set(s['name'] for s in definition['secrets']) - set(approval['secretReferences']):
        raise ValueError('Service cannot select unapproved or privileged credentials')
    if set(s['name'] for s in definition['configMaps']) - set(approval['configMaps']):
        raise ValueError('Service cannot select unapproved configuration')
    for request in definition['data'].values():
        if request['credentialReference'] not in approval['secretReferences']:
            raise ValueError('Data requests require approved scoped credentials')
    import json
    import subprocess
    import yaml
    from playbooks.services.files.contract import ROOT
    validation_approval = dict(approval)
    # Workload-independent validation of the admin boundary; runtime notes values
    # are compiled by the notes adapter from the existing identity and data owners.
    validation_approval['chartPath'] = 'charts/service'
    result = subprocess.run(['helm', 'template', 'services', str(ROOT / 'platform/delivery/services'),
                             '-n', 'argocd', '-f', '-'], input=json.dumps({
                                 'repository': platform_repository, 'revision': platform_revision,
                                 'catalog': [{'definition': definition, 'approval': validation_approval}],
                                 'dataApprovals': {r['credentialReference']: {'service': name, 'kind': kind, 'name': r['name'],
                                     'item': ('cnpg' if kind == 'database' else 's3') + '-' + name + '-production'}
                                     for kind, r in definition['data'].items()}}),
                            capture_output=True, text=True, timeout=90)
    if result.returncode:
        raise ValueError('Administrator service catalog failed validation')
    return [obj for obj in yaml.safe_load_all(result.stdout) if obj]
