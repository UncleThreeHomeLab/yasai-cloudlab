"""Durable, identity-preserving Cloudflare reconciliation; no credential generation.

The caller holds the state lock and validates provider, cluster and vault inputs.
DNS publication is last. Host removal and exposure changes require a separate
reviewed migration; a missing input must never silently unprotect a hostname.
"""
import copy
import hashlib
import json

from automation.connectivity.cloudflare import access_application, dns_record, tunnel_config
from automation.connectivity.contract import host_rules


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
    def __init__(self, admin, dns, state, save):
        self.admin, self.dns, self.state, self.save = admin, dns, state, save
        self.changed = False

    def checkpoint(self):
        self.save(copy.deepcopy(self.state))

    def ensure(self, client, key, path, desired, selector):
        """Persist create intent before POST; recover an interrupted create only exactly."""
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

    def run(self, *, account, zone_id, zone, tunnel, rules, team, human_email, identity_provider, service_token_id, add_identity_protocol=False):
        # Validate all declarations before the first mutation.
        rules = host_rules(rules, zone)
        binding = digest({'account': account, 'zone': zone_id, 'tunnel': tunnel, 'rules': rules})
        extension = False
        if self.state and self.state.get('binding') != binding:
            protocol = {'hostname': 'login.' + zone, 'access': 'public'}
            previous = [rule for rule in rules if rule != protocol]
            previous_binding = digest({'account': account, 'zone': zone_id, 'tunnel': tunnel, 'rules': previous})
            if not add_identity_protocol or protocol not in rules or previous_binding != self.state.get('binding'):
                raise RuntimeError('Access identity or hostname classification changed; explicit migration required')
            # The only permitted extension is the new identity protocol hostname.
            # Existing identities, classification and managed objects stay unchanged.
            extension = True
        applications = {rule['hostname']: access_application(rule, human_email=human_email,
                            identity_provider=identity_provider, service_token_id=service_token_id)
                        for rule in rules if rule['access'] != 'public'}
        if applications and not team:
            raise ValueError('Access organization is required before publication')
        if extension:
            self.state.update(binding=binding, phase='preparing')
            self.checkpoint()
        config_path = 'accounts/' + account + '/cfd_tunnel/' + tunnel + '/configurations'
        current = self.admin.request('GET', config_path)
        if not self.state:
            ingress = (current.get('config') or {}).get('ingress', [])
            if ingress not in ([], [{'service': 'http_status:404'}]):
                raise RuntimeError('Tunnel contains unowned routes; explicit adoption required')
            self.state.update(binding=binding, phase='preparing', objects={}, original_config=current.get('config', {}))
            self.checkpoint()
        audiences = {}
        app_path = 'accounts/' + account + '/access/apps'
        for hostname, desired in applications.items():
            actual = self.ensure(self.admin, 'app:' + hostname, app_path, desired,
                                 lambda obj, h=hostname: obj.get('domain') == h)
            if not actual.get('aud'):
                raise RuntimeError('Access application has no JWT audience; DNS remains unpublished')
            audiences[hostname] = actual['aud']
        wanted = tunnel_config(rules, audiences, team)
        if current.get('config') != wanted['config']:
            self.admin.request('PUT', config_path, wanted)
            self.changed = True
        actual_config = self.admin.request('GET', config_path).get('config')
        if actual_config != wanted['config']:
            raise RuntimeError('Tunnel configuration did not converge; DNS remains unpublished')
        for rule in rules:
            hostname = rule['hostname']
            self.ensure(self.dns, 'dns:' + hostname, 'zones/' + zone_id + '/dns_records',
                        dns_record(hostname, tunnel), lambda obj, h=hostname: obj.get('name') == h)
        self.state['phase'] = 'configured'
        self.checkpoint()
        return {'changed': self.changed, 'configured': True, 'acceptance_passed': False,
                'managed_objects': len(self.state['objects'])}
