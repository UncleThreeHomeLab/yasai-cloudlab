"""Compile the administrator catalog from one private input and committed sources."""
import json

from playbooks.argocd.files.render import committed_payload
from automation.services.inputs import catalog


def payload():
    source = committed_payload()
    import yaml
    from automation.services.contract import ROOT
    settings = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    telemetry = settings.get('observability', {}).get('enabled', False)
    value = catalog(required=True)
    from automation.data.requests import request
    for entry in value['catalog']:
        requested = request(entry['approval']['name'], entry['definition']['data'], value['dataApprovals'])
        entry['dataBindings'] = [
            {'name': row['credentialReference'], 'item': row['item'],
             'fields': ['username', 'password'] if kind == 'database' else
                       ['BUCKET', 'ACCESS_KEY_ID', 'SECRET_ACCESS_KEY', 'ENDPOINT', 'REGION']}
            for kind, row in requested.items() if kind in ('database', 'bucket')]
        if entry['approval'].get('chartPath') == 'apps/notes':
            from automation.services.notes import values as notes_values
            from automation.connectivity.preflight import ssh
            import os
            script = "import sys,json,base64;sys.path.insert(0,'/opt/cloudlab');from automation.mesh.kube import get;app=get('application.argoproj.io','cloudlab-identity','argocd');ca=get('secret','cloudlab-postgres-ca','cloudlab-data');print(json.dumps({'issuer':'https://'+app['spec']['source']['helm']['valuesObject']['loginHost']+'/realms/applications','ca':base64.b64decode(ca['data']['ca.crt']).decode()}))"
            import shlex
            metadata = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script), timeout=60))
            entry['notesValues'] = notes_values(entry['definition'], metadata['issuer'], metadata['ca'], telemetry=telemetry)
    return {'repository': source['repository'], 'revision': source['revision'], 'values': {
        'repository': source['repository'], 'revision': source['revision'], 'catalog': value['catalog']}}


if __name__ == '__main__':
    print(json.dumps(payload()))
