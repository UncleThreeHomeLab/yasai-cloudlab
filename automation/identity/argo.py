"""Enable native Argo OIDC only from validated private and public interfaces."""
import fcntl
import json

import yaml

from automation.identity.bootstrap import prerequisites, private_inputs
from automation.identity.configuration import private_request
from automation.identity.health import check, proxy_privacy
from automation.identity.integrations import argo
from automation.identity.maintenance import APP, BASE, OWNER
from automation.gitops.source_transition import bind_identity
from automation.mesh.kube import application_ready, get


def validate(payload, source, revoked, private_revision):
    proposed = payload['argo']
    cm = proposed['configuration']['argo-cd']['configs']['cm']
    origins = yaml.safe_load(cm['additionalUrls'])
    if origins != ['https://cd.internal.' + payload['values']['loginHost'][6:]]:
        raise ValueError('Native Argo requires its independent exact private origin')
    contract = argo('https://' + payload['values']['loginHost'] + '/realms/platform', cm['url'], origins)
    if proposed['configuration'] != contract['helm'] or proposed['client'] != contract['client']:
        raise ValueError('Native Argo configuration differs from its scoped producer')
    if proposed['target']['valuesRevision'] != private_revision:
        raise RuntimeError('Private identity inputs advanced during native Argo preparation; repeat validation')
    clients = [client for client in source['realms'].get('platform', {}).get('clients', []) if client.get('id') == 'argocd']
    denied = revoked['realms'].get('platform', {})
    if (clients != [contract['client']] or 'argocd' in denied.get('clients', []) or
            'argocd' in denied.get('removed_clients', [])):
        raise RuntimeError('Native Argo requires the current active exact-callback public client')
    return proposed['target']


def run(payload):
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prerequisites(payload)
        receipt = json.loads((BASE / 'ownership.json').read_text())
        current = get('application.argoproj.io', APP, 'argocd') or {}
        if (receipt.get('phase') != 'scoped' or current.get('metadata', {}).get('uid') != receipt.get('uid') or
                current.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
                not application_ready(APP, payload['revision'])):
            raise RuntimeError('Native Argo requires converged scoped identity reconciliation')
        target = validate(payload, *private_inputs(payload))
        origin = 'https://' + payload['values']['loginHost']
        for realm in ('platform', 'applications'):
            check(origin + '/realms/' + realm)
        proxy_privacy(payload['values']['loginHost'])
        response = private_request(origin + '/realms/platform/protocol/openid-connect/token',
            form={'grant_type': 'authorization_code', 'client_id': 'argocd', 'code': 'invalid-disposable-probe',
                  'redirect_uri': payload['argo']['client']['callbacks'][0], 'code_verifier': 'x' * 64},
            accepted_statuses=(400,))
        if response.get('error') != 'invalid_grant':
            raise RuntimeError('Native Argo client token endpoint is unavailable or disabled')
        result = bind_identity(payload, target)
        return dict(result, independent_repair_preserved=True, prior_access_provider_preserved=True,
                    browser_and_offboarding_acceptance=False)
