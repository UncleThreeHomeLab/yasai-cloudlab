"""Durable identity fixtures; selected native Cloudflare fields remain fenced."""
import copy
import hashlib
import json

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def matches(actual, desired):
    """Ignore provider metadata, but never ignore extra policy rules or list entries."""
    if isinstance(desired, dict):
        return isinstance(actual, dict) and all(k in actual and matches(actual[k], v) for k, v in desired.items())
    if isinstance(desired, list):
        return isinstance(actual, list) and len(actual) == len(desired) and all(matches(a, b) for a, b in zip(actual, desired))
    return type(actual) is type(desired) and actual == desired


class Reconciler:
    def __init__(self, state, save):
        self.state, self.save = state, save
        self.changed = False

    def checkpoint(self):
        self.save(copy.deepcopy(self.state))

    def ensure(self, client, key, path, desired, selector):
        """Persist create intent before POST; recover an interrupted create only exactly."""
        if 'infra_owner' in self.state:
            owner = self.state['infra_owner']
            if (not isinstance(owner, dict) or not isinstance(owner.get('objects'), dict) or
                    not owner['objects'] or owner.get('binding') != self.state.get('binding') or
                    key in owner['objects']):
                raise RuntimeError('Selected Cloudflare objects belong to infrastructure maintenance; old writer suspended')
        objects = client.collection(path)
        selected = [obj for obj in objects if selector(obj)]
        entry = self.state.setdefault('objects', {}).get(key)
        if entry is None:
            if selected:
                raise RuntimeError('Unowned external object conflicts with declared access resource')
            entry = {'intent': digest(desired)}
            self.state['objects'][key] = entry
            self.checkpoint()
        if len(selected) > 1:
            raise RuntimeError('Ambiguous external access resource; refusing mutation')
        if 'id' in entry:
            if len(selected) != 1 or selected[0].get('id') != entry['id']:
                raise RuntimeError('External resource identity changed or disappeared; explicit recovery required')
            actual = client.request('GET', path + '/' + entry['id'])
        elif selected:
            actual = client.request('GET', path + '/' + selected[0]['id'])
            if entry['intent'] != digest(desired) or not matches(actual, desired):
                raise RuntimeError('Interrupted create differs from its saved intent; inspect before adoption')
            entry['id'] = actual['id']
            self.checkpoint()
        else:
            if entry['intent'] != digest(desired):
                raise RuntimeError('Pending external create intent changed')
            actual = client.request('POST', path, desired)
            if not actual.get('id'):
                raise RuntimeError('External create returned no identity; retain pending intent')
            entry['id'] = actual['id']
            self.checkpoint()
            self.changed = True
        if not matches(actual, desired):
            # Keep nested Access policy IDs during app updates, avoiding recreation.
            update = copy.deepcopy(desired)
            if 'policies' in update:
                policies = actual.get('policies', [])
                for value in update['policies']:
                    old = [p for p in policies if p.get('name') == value['name']]
                    if len(old) == 1 and old[0].get('id'):
                        value['id'] = old[0]['id']
            client.request('PUT', path + '/' + entry['id'], update)
            self.changed = True
        actual = client.request('GET', path + '/' + entry['id'])
        if not matches(actual, desired):
            raise RuntimeError('External access resource did not converge')
        return actual
