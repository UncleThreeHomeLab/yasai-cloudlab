"""Resolve reviewed source coordinates; Argo reads the complete private Git values."""
import json
import re
import yaml
from dotenv import dotenv_values
from playbooks.argocd.files.render import committed_payload
from playbooks.services.files.contract import ROOT
from playbooks.services.files.inputs import catalog


def payload():
    source = committed_payload()
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    # Validate the complete private contract before bootstrap; never inject it.
    value, private_revision = catalog(required=True, coordinates=True)
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    revision = public.get('services', {}).get('revision', '')
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Service catalog requires its declared immutable platform revision')
    return {'repository': source['repository'], 'revision': revision,
            'private_repository': environment['PRIVATE_CONFIG_REPOSITORY'], 'private_revision': private_revision,
            'telemetry': public['observability']['enabled'],
            'values': value}


if __name__ == '__main__':
    print(json.dumps(payload()))
