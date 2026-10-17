"""Capture existing Cloudflare ownership privately, using read-only provider calls."""
import json
import os
from pathlib import Path
import uuid

from dotenv import dotenv_values

from automation.connectivity.cloudflare import API
from playbooks.secrets.files.vault import fields


def capture(admin, dns, state, management, tunnel):
    objects = state.get('objects', {})
    if not objects or any(not entry.get('id') for entry in objects.values()):
        raise ValueError('Complete existing owner identities required before inventory')
    account = 'accounts/' + management['ACCOUNT_ID']
    result = {'owner': state, 'applications': {}, 'dns': {}, 'account_policy_reads': {}}
    for key, entry in objects.items():
        kind, hostname = key.split(':', 1)
        if kind == 'app':
            app = admin.request('GET', account + '/access/apps/' + entry['id'])
            if app.get('id') != entry['id'] or app.get('domain') != hostname or not app.get('aud'):
                raise ValueError('Existing Access identity differs from owner receipt')
            result['applications'][hostname] = app
            for policy in app.get('policies', []):
                identity = policy.get('id')
                if not identity:
                    raise ValueError('Existing Access policy lacks an identity')
                try:
                    observed = admin.request('GET', account + '/access/policies/' + identity)
                    result['account_policy_reads'][identity] = {'supported': observed.get('id') == identity,
                                                                'policy': observed}
                except RuntimeError as error:
                    result['account_policy_reads'][identity] = {'supported': False, 'error': str(error)}
        elif kind == 'dns':
            record = dns.request('GET', 'zones/' + management['ZONE_ID'] + '/dns_records/' + entry['id'])
            if record.get('id') != entry['id'] or record.get('name') != hostname:
                raise ValueError('Existing DNS identity differs from owner receipt')
            result['dns'][hostname] = record
        else:
            raise ValueError('Unknown old-owner object; scope review required')
    result['tunnel'] = admin.request('GET', account + '/cfd_tunnel/' + tunnel['TUNNEL_ID'])
    result['configuration'] = admin.request('GET', account + '/cfd_tunnel/' + tunnel['TUNNEL_ID'] + '/configurations')
    result['organization'] = admin.request('GET', account + '/access/organizations')
    return result


def credentials():
    """Retrieve qualification credentials from their vault owners, in memory only."""
    inputs = dotenv_values('/workspace/.env', interpolate=False)
    os.environ.update({key: value for key, value in inputs.items() if value is not None})
    management = fields('cloudflare-management', ('API_TOKEN', 'ACCOUNT_ID', 'ZONE_ID'))
    dns = fields('cloudlab-dns01', ('API_TOKEN', 'ZONE_ID'))
    if management['ZONE_ID'] != dns['ZONE_ID'] or management['API_TOKEN'] == dns['API_TOKEN']:
        raise ValueError('Separate management and DNS scope required')
    tunnel = fields('cloudflare-tunnel', ('TUNNEL_ID',))
    backend = fields('gitlab-state-cloudflare', ('PROJECT_ID', 'USERNAME', 'TOKEN'))
    encryption = fields('opentofu-state-cloudflare', ('PASSPHRASE',))
    return dict(management=management, dns=dns, tunnel=tunnel, backend=backend, encryption=encryption)


def main():
    os.umask(0o077)
    bundle = credentials()
    # The existing owner supplies IDs under its host receipt lock; no writer is suspended here.
    from automation.connectivity.checkpoint import transaction
    with transaction() as receipts:
        owner = receipts.load('external')
    management, dns, tunnel = bundle['management'], bundle['dns'], bundle['tunnel']
    snapshot = capture(API(management['API_TOKEN']), API(dns['API_TOKEN']), owner, management, tunnel)
    directory = Path('/recovery/infra/cloudflare') / ('baseline-' + uuid.uuid4().hex)
    directory.mkdir(parents=True, mode=0o700)
    (directory / 'snapshot.json').write_text(json.dumps(snapshot, sort_keys=True))
    print(json.dumps({'private_directory': str(directory), 'production_mutations': 0,
                      'applications': len(snapshot['applications']), 'dns_records': len(snapshot['dns']),
                      'existing_policy_account_endpoint_supported': all(
                          value['supported'] for value in snapshot['account_policy_reads'].values())}))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError, KeyError, AttributeError, OSError):
        raise SystemExit('Cloudflare inventory incomplete; no production ownership change') from None
