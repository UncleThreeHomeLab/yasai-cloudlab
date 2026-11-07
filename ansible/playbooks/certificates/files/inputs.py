"""Read the selected DNS zone from the ESO credential without persisting tokens."""
import base64
import json
import re
import urllib.request

from kube import get, ready, wait


def zone():
    wait(lambda: ready(get('externalsecret.external-secrets.io', 'cloudlab-dns01', 'cert-manager')),
         'DNS credential synchronization', timeout=300)
    secret = get('secret', 'cloudlab-dns01', 'cert-manager')
    external = get('externalsecret.external-secrets.io', 'cloudlab-dns01', 'cert-manager')
    if not any(x.get('kind') == 'ExternalSecret' and x.get('uid') == external['metadata']['uid']
               for x in secret['metadata'].get('ownerReferences', [])):
        raise RuntimeError('DNS credential lacks its ESO owner')
    values = {key: base64.b64decode(secret['data'][key], validate=True).decode().strip()
              for key in ('API_TOKEN', 'ZONE_ID')}
    if not re.fullmatch('[0-9a-f]{32}', values['ZONE_ID']) or not values['API_TOKEN'] or any(
            c in values['API_TOKEN'] for c in '\r\n'):
        raise RuntimeError('DNS credential fields are invalid')
    request = urllib.request.Request('https://api.cloudflare.com/client/v4/zones/' + values['ZONE_ID'],
        headers={'Authorization': 'Bearer ' + values['API_TOKEN'], 'Accept': 'application/json'})
    # No redirects: a credential must never follow an external redirect target.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args):
            return None
    response = json.load(urllib.request.build_opener(NoRedirect()).open(request, timeout=30))
    result = response.get('result', {})
    if not response.get('success') or result.get('id') != values['ZONE_ID'] or result.get('status') != 'active':
        raise RuntimeError('Selected DNS zone is not active or accessible')
    name = result.get('name', '')
    if len(name) > 253 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+', name):
        raise RuntimeError('Selected DNS zone name is invalid')
    return name


def prepare(values, public, binding, active_revision, *, expected_revision=None):
    """Read bounded certificate values at one authenticated private Git revision."""
    import subprocess
    from pathlib import Path
    import yaml
    from playbooks.argocd.files.github_app import configuration_revision
    from playbooks.argocd.files.github_setup import repository
    from playbooks.argocd.files.private_sources import decode_contents
    private = values.get('PRIVATE_CONFIG_REPOSITORY')
    pin = public.get('certificates', {}).get('configuration', {}).get('revision')
    if (not isinstance(binding, dict) or set(binding) != {'valuesRepository', 'valuesRevision'}
            or binding['valuesRepository'] != private or not re.fullmatch('[a-f0-9]{40}', binding['valuesRevision'])
            or not re.fullmatch('[a-f0-9]{40}', pin or '') or not re.fullmatch('[a-f0-9]{40}', active_revision or '')):
        raise ValueError('Native certificate source bindings are invalid')
    root = Path(__file__).resolve().parents[4]
    def render(chart, content):
        result = subprocess.run(['helm', 'template', 'cloudlab-certificates', str(root / chart), '-n', 'argocd', '-f', '-'],
            input=json.dumps(content), capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError('Native certificate declarations cannot be rendered')
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj]
    def read(client, revision):
        if expected_revision is not None and revision != expected_revision:
            raise ValueError('Private certificate revision changed after approval')
        document = client.request('GET', 'repos/' + repository(private) + '/contents/platform/certificates.yaml?ref=' + revision)
        if (not isinstance(document, dict) or document.get('type') != 'file' or document.get('encoding') != 'base64'
                or type(document.get('size')) is not int or not 0 <= document['size'] <= 65536):
            raise ValueError('Private certificate values require a bounded regular file')
        raw = decode_contents(document)
        if len(raw) > 65536 or len(raw) != document['size']:
            raise ValueError('Private certificate values exceed their bounded file contract')
        selected = yaml.safe_load(raw)
        if (not isinstance(selected, dict) or set(selected) != {'zone', 'production'}
                or selected['production'] is not True or not isinstance(selected['zone'], str)):
            raise ValueError('Private certificate values violate their native schema')
        resources = render('platform/certificates/configuration', selected)
        configuration = dict(public, identity=dict(public['identity'], argo=binding))
        objects = render('gitops/roots/public', configuration)
        def owned(kind, name):
            return next(obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name)
        return {'repository': public['repository'], 'public_revision': active_revision,
            'configuration_revision': pin, 'private_repository': private, 'private_revision': revision,
            'values': selected, 'resources': resources, 'application': owned('Application', 'cloudlab-certificates'),
            'project': owned('AppProject', 'cloudlab-certificates'),
            'reader': owned('ExternalSecret', 'cloudlab-certificates-source')}
    try:
        return configuration_revision(values, read=read)
    except Exception:
        raise ValueError('Authenticated certificate values are unavailable or invalid') from None


if __name__ == '__main__':
    try:
        import os
        from pathlib import Path
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        import yaml
        from dotenv import dotenv_values
        envelope = json.load(sys.stdin)
        native = None
        identity = envelope['root'].get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('identity', {})
        if 'argo' in identity:
            root = Path(__file__).resolve().parents[4]
            values = dotenv_values(root / '.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            native = prepare(values, yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text()),
                             identity['argo'], envelope['public']['revision'])
        print(json.dumps({'native': native}))
    except Exception:
        raise SystemExit('Native certificate inputs unavailable; private diagnostics withheld') from None
