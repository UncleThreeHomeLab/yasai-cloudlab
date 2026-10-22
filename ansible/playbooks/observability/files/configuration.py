"""Native, free Grafana authentication and local telemetry policy."""
import json
from pathlib import Path
from urllib.parse import urlsplit, quote

from playbooks.keycloak.files.integrations import issuer
from playbooks.keycloak.files.configuration import exact_url

ROOT = Path(__file__).resolve().parents[4]
POLICY = json.loads((ROOT / 'platform/observability/policy.json').read_text())


def grafana(identity_issuer, origin):
    issuer(identity_issuer)
    callback = exact_url(origin + '/login/generic_oauth')
    if urlsplit(callback).path != '/login/generic_oauth' or '.internal.' not in urlsplit(origin).hostname:
        raise ValueError('Grafana requires its exact private HTTPS origin')
    protocol = identity_issuer + '/protocol/openid-connect'
    ini = json.loads((ROOT / 'platform/observability/prometheus/values.json').read_text())['kube-prometheus-stack']['grafana']['grafana.ini']
    ini['server']['root_url'] = origin
    ini['auth']['signout_redirect_url'] = protocol + '/logout?post_logout_redirect_uri=' + quote(origin + '/login', safe='')
    ini['auth.generic_oauth'].update(auth_url=protocol + '/auth', token_url=protocol + '/token', api_url=protocol + '/userinfo')
    return {'client': {'id': 'grafana', 'public': False, 'audience': 'grafana',
                       'callbacks': [callback], 'logout_callbacks': [origin + '/login'],
                       'scopes': ['profile', 'email']},
            'ini': ini}


def kiali(identity_issuer, origin):
    issuer(identity_issuer)
    callback = exact_url(origin + '/kiali')
    if urlsplit(callback).path != '/kiali' or '.internal.' not in urlsplit(origin).hostname:
        raise ValueError('Kiali requires its exact private HTTPS origin')
    return {'id': 'kiali', 'public': False, 'audience': 'kiali', 'callbacks': [callback], 'scopes': ['profile', 'email']}
