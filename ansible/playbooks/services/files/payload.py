"""Resolve reviewed source coordinates; Argo reads the complete private Git values."""
import json
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
    return {'repository': source['repository'], 'revision': source['revision'],
            'private_repository': environment['PRIVATE_CONFIG_REPOSITORY'], 'private_revision': private_revision,
            'telemetry': yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['observability']['enabled'],
            'values': value}


if __name__ == '__main__':
    print(json.dumps(payload()))
