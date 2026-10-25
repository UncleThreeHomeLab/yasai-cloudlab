"""Require published platform code and versioned private preview inputs."""
import json
from pathlib import Path
import yaml
from dotenv import dotenv_values
from playbooks.argocd.files.render import committed_payload
from playbooks.previews.files.source import read
from playbooks.argocd.files.github_setup import repository

ROOT = Path(__file__).resolve().parents[4]


def payload():
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if public.get('previews', {}).get('enabled') is not True or public.get('identity', {}).get('enabled') is not True:
        raise ValueError('Reviewed previews and identity must be enabled before private preview discovery')
    platform = committed_payload()
    values = dotenv_values(ROOT / '.env', interpolate=False)
    public_repo = repository(platform['repository'])
    private_repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    if public_repo.lower() == private_repo.lower() or public_repo.split('/')[0].lower() != private_repo.split('/')[0].lower():
        raise ValueError('Previews require a distinct designated private repository under the approved owner')
    settings, revision, values = read(values)
    private_label = settings['hostname'].split('.internal.')[0]
    if private_label not in json.loads(values.get('PRIVATE_ACCESS_HOSTS') or '[]'):
        raise ValueError('Preview hostname must be declared through the private access owner')
    if settings['privateDiscovery'] and any(row['repository'] != repository(values['PRIVATE_CONFIG_REPOSITORY'])
            for row in settings['approvals']):
        raise ValueError('Private preview catalog must use its designated configuration repository')
    return {'repository': platform['repository'], 'branch': platform['branch'], 'revision': platform['revision'],
            'privateRepository': values['PRIVATE_CONFIG_REPOSITORY'], 'privateRevision': revision, 'catalog': settings}


if __name__ == '__main__':
    try:
        print(json.dumps(payload(), sort_keys=True))
    except Exception:
        raise SystemExit('Preview prerequisites unavailable; private diagnostics withheld') from None
