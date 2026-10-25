"""Require published platform code and versioned private preview inputs."""
import json
from playbooks.argocd.files.render import committed_payload
from playbooks.previews.files.source import read
from playbooks.argocd.files.github_setup import repository


def payload():
    platform = committed_payload()
    settings, revision, values = read()
    private_label = settings['hostname'].split('.internal.')[0]
    if private_label not in json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]'):
        raise ValueError('Preview hostname must be declared through the private access owner')
    if settings['privateDiscovery'] and any(row['repository'] != repository(values['PRIVATE_CONFIG_REPOSITORY'])
            for row in settings['approvals']):
        raise ValueError('Private preview catalog must use its designated configuration repository')
    return {'repository': platform['repository'], 'revision': platform['revision'],
            'privateRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'privateRevision': revision, 'catalog': settings}


if __name__ == '__main__':
    try:
        print(json.dumps(payload(), sort_keys=True))
    except Exception:
        raise SystemExit('Preview prerequisites unavailable; private diagnostics withheld') from None
