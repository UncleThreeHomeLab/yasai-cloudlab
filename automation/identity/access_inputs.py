"""Identity's public protocol and private administration DNS contract."""
import copy
import json


def runtime(environment, settings):
    """Use the same hostname classification for apply and identity handoff."""
    enabled = settings.get('identity', {}).get('enabled')
    environment['LAB_IDENTITY_ENABLED'] = '1' if enabled else '0'
    if enabled:
        public, private = names(json.loads(environment.get('CLOUDFLARE_ACCESS_HOSTS') or '[]'),
                                json.loads(environment.get('PRIVATE_ACCESS_HOSTS') or '[]'))
        environment['CLOUDFLARE_ACCESS_HOSTS'] = json.dumps(public)
        environment['PRIVATE_ACCESS_HOSTS'] = json.dumps(private)
    environment['CLOUDFLARE_HUMAN_EMAIL'] = (environment.get('CLOUDFLARE_HUMAN_EMAIL') or
                                           environment.get('TAILSCALE_ADMIN_LOGIN') or '')


def names(public, private):
    public, private = copy.deepcopy(public), list(private)
    existing = [rule for rule in public if rule.get('name') == 'login']
    if existing and (len(existing) != 1 or existing[0] != {'name': 'login', 'access': 'public'}):
        raise ValueError('Identity login must be a dedicated public protocol hostname without Access authentication')
    if not existing:
        public.append({'name': 'login', 'access': 'public'})
    for name in ('identity-admin', 'cd'):
        if name not in private:
            private.append(name)
    if any(rule.get('name') == 'identity-admin' for rule in public):
        raise ValueError('Identity administration must remain outside public tunnel routing')
    return public, private
