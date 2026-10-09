"""Identity's public protocol and private administration DNS contract."""
import copy


def names(public, private):
    public, private = copy.deepcopy(public), list(private)
    existing = [rule for rule in public if rule.get('name') == 'login']
    if existing and (len(existing) != 1 or existing[0] != {'name': 'login', 'access': 'public'}):
        raise ValueError('Identity login must be a dedicated public protocol hostname without Access authentication')
    if not existing:
        public.append({'name': 'login', 'access': 'public'})
    if 'identity-admin' not in private:
        private.append('identity-admin')
    if any(rule.get('name') == 'identity-admin' for rule in public):
        raise ValueError('Identity administration must remain outside public tunnel routing')
    return public, private
