"""Private integration inputs for the native, free OIDC implementations."""
import re
import yaml
from urllib.parse import urlsplit

from automation.identity.configuration import exact_url


def issuer(value):
    parsed = urlsplit(exact_url(value))
    if parsed.path != '/realms/platform':
        raise ValueError('Administrative applications require the platform issuer')
    return value


def argo(identity_issuer, origin, additional_origins=None):
    issuer(identity_issuer)
    additional_origins = [] if additional_origins is None else additional_origins
    if (not isinstance(origin, str) or not isinstance(additional_origins, list) or
            len(additional_origins) != 1 or any(not isinstance(address, str) for address in additional_origins)):
        raise ValueError('Argo requires distinct bounded public/private origins')
    origins = [origin] + additional_origins
    if len(set(origins)) != len(origins):
        raise ValueError('Argo requires distinct bounded public/private origins')
    for address in origins:
        if urlsplit(exact_url(address + '/auth/callback')).path != '/auth/callback':
            raise ValueError('Argo origin must contain no path')
    return {
        'client': {'id': 'argocd', 'public': True, 'audience': 'argocd',
                   'callbacks': [address + callback for address in origins for callback in ('/auth/callback', '/pkce/verify')],
                   'scopes': ['profile', 'email']},
        'helm': {'argo-cd': {'configs': {
            'cm': {'url': origin, 'additionalUrls': yaml.safe_dump(origins[1:], sort_keys=True), 'users.session.duration': '10m', 'oidc.config': yaml.safe_dump({
                'name': 'Keycloak', 'issuer': identity_issuer, 'clientID': 'argocd',
                'enablePKCEAuthentication': True, 'refreshTokenThreshold': '2m',
                'requestedScopes': ['openid', 'profile', 'email']}, sort_keys=True)},
            'rbac': {'policy.default': 'role:no-access', 'scopes': '[groups]',
                     'policy.csv': '\n'.join([
                         'g, platform-admin, role:admin',
                         'g, developer, role:developer',
                         'g, viewer, role:viewer',
                         'p, role:developer, applications, get, cloudlab-public/*, allow',
                         'p, role:developer, applications, sync, cloudlab-public/*, allow',
                         'p, role:developer, logs, get, cloudlab-public/*, allow',
                         'p, role:viewer, applications, get, cloudlab-public/*, allow',
                         'p, role:viewer, logs, get, cloudlab-public/*, allow'])}}}},
        'limits': 'Browser native PKCE only; no HTTP loopback callback or offline_access. Integrated session deadline requires measurement.',
    }


def access(identity_issuer, team, secret):
    issuer(identity_issuer)
    if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', team):
        raise ValueError('Access team must be one DNS label')
    if not isinstance(secret, str) or len(secret) < 32:
        raise ValueError('Access requires its dedicated vault secret')
    protocol = identity_issuer + '/protocol/openid-connect'
    return {
        'client': {'id': 'cloudflare-access', 'public': False, 'audience': 'cloudflare-access',
                   'callbacks': ['https://' + team + '.cloudflareaccess.com/cdn-cgi/access/callback'],
                   'scopes': ['profile', 'email']},
        'provider': {'name': 'CloudLab Keycloak', 'type': 'oidc', 'config': {
            'client_id': 'cloudflare-access', 'client_secret': secret,
            'auth_url': protocol + '/auth', 'token_url': protocol + '/token', 'certs_url': protocol + '/certs',
            'pkce_enabled': True, 'email_claim_name': 'email', 'claims': ['groups'],
            'scopes': ['openid', 'profile', 'email']}},
        'limits': 'Create a separate provider; retain prior provider until browser/back-channel and measured offboarding checks pass.',
    }
