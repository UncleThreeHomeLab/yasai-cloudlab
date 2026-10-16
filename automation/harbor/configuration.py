"""Harbor consumes the retained platform realm; no second identity writer."""
from urllib.parse import urlsplit

from automation.identity.configuration import exact_url
from automation.identity.integrations import issuer


def client(identity_issuer, origin):
    issuer(identity_issuer)
    callback = exact_url(origin + '/c/oidc/callback')
    parsed = urlsplit(callback)
    if (not parsed.hostname.startswith('harbor.internal.') or parsed.path != '/c/oidc/callback' or
            parsed.hostname[16:] != urlsplit(identity_issuer).hostname.removeprefix('login.')):
        raise ValueError('Harbor requires the platform issuer and exact private callback')
    return {'id': 'harbor', 'audience': 'harbor', 'public': False,
            'callbacks': [callback, origin + '/oauth2/callback'], 'scopes': ['profile', 'email']}
