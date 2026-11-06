"""Enable native Argo OIDC only from validated private and public interfaces."""
import fcntl
import copy
import json
import re

import yaml

from playbooks.keycloak.files.bootstrap import prerequisites, private_inputs
from playbooks.keycloak.files.configuration import private_request
from playbooks.keycloak.files.health import check, proxy_privacy
from playbooks.access.files.dns_wire import public_address
from playbooks.keycloak.files.integrations import argo
from playbooks.keycloak.files.maintenance import APP, BASE, OWNER
from playbooks.argocd.files.source_transition import bind_identity, pending_identity_target, pending_identity_checkpoint, binding_source
from playbooks.istio.files.kube import application_ready, get


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


def recovery_revision(payload):
    """Historical binding inputs never replace current Git authorization."""
    proposed = payload['argo']
    projection = proposed.get('currentSecurityProjection')
    if (not isinstance(projection, dict) or set(projection) != {'revision', 'configuration', 'client'}
            or not isinstance(projection['revision'], str)
            or not re.fullmatch('[a-f0-9]{40}', projection['revision'])
            or projection['configuration'] != proposed['configuration']
            or projection['client'] != proposed['client']):
        raise RuntimeError('Native Argo recovery requires validated current private Git authorization')
    return pending_identity_target(proposed['target'])


def run(payload):
    with (BASE / 'owner.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        recovery = None
        if payload['argo'].get('recovery') is True:
            private_revision = recovery_revision(payload)
            source, revoked, _ = private_inputs(payload)
            target = validate(payload, source, revoked, private_revision)
            checkpoint = pending_identity_checkpoint(target)
            root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
            recovery = {'checkpoint': checkpoint, 'sourceState': binding_source(checkpoint, root),
                        'rootSource': copy.deepcopy(root['spec']['source'])}
            prerequisites(payload, access_recovery=recovery)
        else:
            prerequisites(payload)
        receipt = json.loads((BASE / 'ownership.json').read_text())
        current = get('application.argoproj.io', APP, 'argocd') or {}
        from playbooks.keycloak.files.ownership import accepted_application
        identity_revision = accepted_application(current, base=BASE, recovery=recovery) or payload['revision']
        if (receipt.get('phase') != 'scoped' or current.get('metadata', {}).get('uid') != receipt.get('uid') or
                current.get('metadata', {}).get('labels', {}).get('cloudlab.io/owner') != OWNER or
                not application_ready(APP, identity_revision)):
            raise RuntimeError('Native Argo requires converged scoped identity reconciliation')
        if recovery is None:
            source, revoked, private_revision = private_inputs(payload)
            target = validate(payload, source, revoked, private_revision)
        origin = 'https://' + payload['values']['loginHost']
        for realm in ('platform', 'applications'):
            check(origin + '/realms/' + realm)
        proxy_privacy(payload['values']['loginHost'], address=public_address(payload['values']['loginHost']))
        response = private_request(origin + '/realms/platform/protocol/openid-connect/token',
            form={'grant_type': 'authorization_code', 'client_id': 'argocd', 'code': 'invalid-disposable-probe',
                  'redirect_uri': payload['argo']['client']['callbacks'][0], 'code_verifier': 'x' * 64},
            accepted_statuses=(400,))
        if response.get('error') != 'invalid_grant':
            raise RuntimeError('Native Argo client token endpoint is unavailable or disabled')
        result = bind_identity(payload, target)
        return dict(result, independent_repair_preserved=True, prior_access_provider_preserved=True,
                    browser_and_offboarding_acceptance=False)
