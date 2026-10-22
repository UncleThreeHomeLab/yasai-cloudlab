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
