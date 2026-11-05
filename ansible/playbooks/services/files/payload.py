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
    path = ROOT / 'gitops/roots/public/values.yaml'
    raw = path.read_bytes()
    public = yaml.safe_load(raw)
    from playbooks.services.files.owner import chart
    from playbooks.services.files.gitops import authorization_policies
    # Validation and verification use one immutable owner, never the checkout chart.
    with chart(public) as selected:
        value, private_revision = catalog(required=True, coordinates=True, public=public, chart_root=selected)
        authorization = authorization_policies(value, public, selected)
    if path.read_bytes() != raw or source['repository'] != public['repository']:
        raise ValueError('Public service source changed while resolving verification evidence')
    revision = public.get('services', {}).get('revision', '')
    if not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Service catalog requires its declared immutable platform revision')
    result = {'repository': source['repository'], 'revision': revision,
            'private_repository': environment['PRIVATE_CONFIG_REPOSITORY'], 'private_revision': private_revision,
            'telemetry': public['observability']['enabled'],
            'values': value, 'authorization': authorization}
    if 'catalogPath' in public.get('services', {}):
        from playbooks.argocd.files.service_activation import catalog_path
        result['catalogPath'] = catalog_path(public['services']['catalogPath'])
    return result


if __name__ == '__main__':
    print(json.dumps(payload()))
