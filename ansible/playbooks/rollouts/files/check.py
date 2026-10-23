"""Check pinned controller packaging and the single traffic provider."""
import hashlib
import json
from pathlib import Path
import subprocess

import yaml

ROOT = Path(__file__).resolve().parents[4]
CHART = ROOT / 'platform/delivery/rollouts'


def check():
    lock = json.loads((CHART / 'artifact.lock.json').read_text())
    if hashlib.sha256((CHART / lock['chart']['archive']).read_bytes()).hexdigest() != lock['chart']['sha256']:
        raise ValueError('Rollouts chart checksum differs')
    command = ['helm', 'template', 'argo-rollouts', str(CHART), '-n', 'argo-rollouts', '--kube-version', '1.36.5']
    first = subprocess.check_output(command, timeout=90)
    if first != subprocess.check_output(command, timeout=90):
        raise ValueError('Rollouts chart render is not deterministic')
    objects = [o for o in yaml.safe_load_all(first) if o]
    deployment = next(o for o in objects if o['kind'] == 'Deployment')
    image = deployment['spec']['template']['spec']['containers'][0]['image']
    if image not in [name + '@' + digest for name, digest in lock['images'].items()]:
        raise ValueError('Rollouts controller image differs from its lock')
    config = next(o for o in objects if o['kind'] == 'ConfigMap' and o['metadata']['name'] == 'argo-rollouts-config')
    plugins = yaml.safe_load(config['data']['trafficRouterPlugins'])
    if plugins != [{'name': 'argoproj-labs/gatewayAPI', 'location': lock['plugin']['url'], 'sha256': lock['plugin']['sha256']}]:
        raise ValueError('Gateway plugin version or checksum differs')
    roles = [o for o in objects if o['kind'] in ('Role', 'ClusterRole')]
    for role in roles:
        for rule in role['rules']:
            if '*' in rule['resources'] or '*' in rule['verbs']:
                raise ValueError('Rollouts permissions must name resources and verbs')
            if 'secrets' in rule['resources'] and not (
                    role['kind'] == 'Role' and role['metadata'].get('namespace') == 'argo-rollouts' and
                    rule.get('resourceNames') == ['argo-rollouts-notification-secret'] and
                    set(rule['verbs']) <= {'get', 'list', 'watch'}):
                raise ValueError('Rollouts must not read application or arbitrary Secrets')
            if set(rule['resources']) & {'ingresses', 'virtualservices', 'destinationrules', 'jobs'} and not set(rule['verbs']) <= {'get', 'list', 'watch'}:
                raise ValueError('Alternate providers and Job analysis must remain read-only')
    return {'controller_objects': len(objects), 'deterministic': True, 'pinned_plugin_checksum': True}


if __name__ == '__main__':
    print(json.dumps(check()))
