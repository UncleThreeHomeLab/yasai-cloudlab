"""Certify pinned imports and updates on recorded disposable Cloudflare resources."""
import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import uuid

from automation.connectivity.cloudflare import API
from automation.infra.backend import environment
from automation.infra.command import guarded_changes
from automation.infra.gitlab_qualification import address, delete_state, request
from automation.infra.snapshot import credentials


def native(directory, env, *arguments, input_data=None):
    prefix = 2 if arguments[0] == 'state' else 1
    result = subprocess.run(['tofu', *arguments[:prefix], '-no-color', *arguments[prefix:]],
                            cwd=directory, env=env, input=input_data, capture_output=True, timeout=180)
    with (directory / 'diagnostics.txt').open('ab') as stream:
        stream.write(result.stderr if arguments[0] == 'show' or arguments[:2] == ('state', 'pull')
                     else result.stdout + result.stderr)
    return result


def require(result, allowed=(0,)):
    if result.returncode not in allowed:
        raise RuntimeError('Native Cloudflare fixture check failed; protected diagnostics retained')
    return result


def policy_update_unsupported(result):
    if result.returncode == 0:
        return False
    diagnostics = result.stdout + result.stderr
    if b'12135' in diagnostics and b'/access/policies/' in diagnostics:
        return True
    require(result)


def updated(after, desired, identities):
    app = desired['applications']['human']
    route = desired['routes']['human']
    policies = {policy['id']: policy for policy in after['app']['policies']}
    ingress = [entry for entry in after['config']['config']['ingress'] if entry.get('hostname') == route['hostname']]
    if (after['app']['session_duration'] != app['session_duration'] or
            after['dns']['comment'] != route['dns_comment'] or len(ingress) != 1 or
            ingress[0]['service'] != route['service'] or any(
                policies[identities[key]]['name'] != policy['name'] for key, policy in app['policies'].items())):
        raise ValueError('Provider update was not observed in remote fields')


def document_plan(directory, env, filename):
    result = require(native(directory, env, 'plan', '-input=false', '-detailed-exitcode',
                            '-lock-timeout=0s', '-var-file=desired.tfvars.json', '-out=' + filename), (0, 2))
    document = json.loads(require(native(directory, env, 'show', '-json', filename)).stdout)
    return result.returncode, document


def review_import(document, identities):
    resources = {resource['address']: resource for resource in document.get('resource_changes', [])}
    if set(resources) != set(identities):
        raise ValueError('Fixture import scope differs from recorded identities')
    for name, resource in resources.items():
        change = resource['change']
        if change['actions'] != ['no-op'] or change.get('after', {}).get('id') != identities[name]:
            raise ValueError('Fixture import proposed an unintended remote change')


def remote(admin, dns, bundle, identities):
    account = 'accounts/' + bundle['management']['ACCOUNT_ID']
    app = admin.request('GET', account + '/access/apps/' + identities['app'])
    config = admin.request('GET', account + '/cfd_tunnel/' + identities['tunnel'] + '/configurations')
    record = dns.request('GET', 'zones/' + bundle['dns']['ZONE_ID'] + '/dns_records/' + identities['dns'])
    return {'app': app, 'config': config, 'dns': record}


def preserved(before, after):
    if before['app']['id'] != after['app']['id'] or before['app']['aud'] != after['app']['aud']:
        raise ValueError('Disposable Access identity or audience changed')
    if any(before['app'].get(key) != after['app'].get(key) for key in (
            'name', 'domain', 'allowed_idps', 'app_launcher_visible', 'auto_redirect_to_identity',
            'enable_binding_cookie', 'options_preflight_bypass')):
        raise ValueError('Existing Access authentication settings changed')
    policies = lambda value: {policy['id']: policy for policy in value['app']['policies']}
    old, new = policies(before), policies(after)
    if set(old) != set(new) or any(policy.get('reusable') is not False for policy in new.values()):
        raise ValueError('Legacy policy identity or reusability changed')
    for key in old:
        if any(old[key].get(field) != new[key].get(field) for field in ('include', 'exclude', 'require', 'decision', 'precedence')):
            raise ValueError('Existing Access selectors changed')
    if after['config']['config'].get('warp-routing') != before['config']['config'].get('warp-routing'):
        raise ValueError('Unrepresented tunnel routing changed')
    if before['dns']['id'] != after['dns']['id']:
        raise ValueError('Disposable DNS identity changed')
    if any(before['dns'].get(key) != after['dns'].get(key) for key in ('name', 'type', 'content', 'proxied', 'ttl')):
        raise ValueError('Disposable DNS publication scope changed')


def state_identities(document):
    result = {}
    for resource in document.get('resources', []):
        for instance in resource.get('instances', []):
            name = resource['type'] + '.' + resource['name']
            if 'index_key' in instance:
                name += '[' + json.dumps(instance['index_key']) + ']'
            result[name] = instance['attributes']['id']
    return result


def upload_recovery(directory, env, bundle, identities, desired, imports):
    url = address(bundle['backend'], directory.name)
    class UploadFailure(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            status, data = request(bundle['backend'], url)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.send_response(503)
            self.end_headers()

    server = HTTPServer(('127.0.0.1', 0), UploadFailure)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    faulty = dict(env, TF_HTTP_ADDRESS='http://127.0.0.1:' + str(server.server_port) + '/state')
    desired['routes']['human']['dns_comment'] = 'qualification-recovered'
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired))
    try:
        require(native(directory, faulty, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
        _, document = document_plan(directory, faulty, 'failed-upload.tfplan')
        guarded_changes(document)
        failed = native(directory, faulty, 'apply', '-input=false', '-lock-timeout=0s', 'failed-upload.tfplan')
        recovery = directory / 'errored.tfstate'
        if failed.returncode == 0 or not recovery.exists() or 'encrypted_data' not in json.loads(recovery.read_bytes()):
            raise RuntimeError('Failed upload did not retain protected recovery state')
        dns = API(bundle['dns']['API_TOKEN'])
        record = dns.request('GET', 'zones/' + bundle['dns']['ZONE_ID'] + '/dns_records/' + identities['dns'])
        if record['id'] != identities['dns'] or record['comment'] != 'qualification-recovered':
            raise RuntimeError('Provider success not observed before failed upload')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    decrypt = directory / 'decrypt-recovery'
    decrypt.mkdir(mode=0o700, exist_ok=True)
    protected = decrypt / 'recovery.encrypted'
    shutil.copyfile(recovery, protected)
    (decrypt / 'main.tf.json').write_text(json.dumps({'terraform': {
        'required_version': '= 1.13.1', 'backend': {'local': {'path': str(protected)}}}}))
    local_env = {key: value for key, value in env.items() if not key.startswith('TF_HTTP_')}
    require(native(decrypt, local_env, 'init', '-input=false'))
    decrypted = require(native(decrypt, local_env, 'state', 'pull')).stdout
    if state_identities(json.loads(decrypted)) != imports:
        raise ValueError('Recovery identities differ; state push refused')
    require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
    require(native(directory, env, 'state', 'push', '-', input_data=decrypted))
    if document_plan(directory, env, 'recovered-repeat.tfplan')[0] != 0:
        raise RuntimeError('Recovered provider repeat plan is not empty')


def retention_probe(directory, env, bundle):
    url = address(bundle['backend'], directory.name)
    current = json.loads(require(native(directory, env, 'state', 'pull')).stdout)
    status, raw = request(bundle['backend'], url)
    if status != 200 or len(raw) > 8 * 1024**2:
        raise RuntimeError('Fixture state unavailable or above the proposed size bound')
    for serial in range(1, current['serial']):
        status, older = request(bundle['backend'], url + '/versions/' + str(serial))
        if status == 404:
            continue
        if status != 200 or 'encrypted_data' not in json.loads(older):
            raise RuntimeError('Older encrypted version unavailable for retention qualification')
        (directory / 'retention-recovery.encrypted').write_bytes(older)
        if not delete_state(bundle['backend'], url + '/versions/' + str(serial)):
            raise RuntimeError('Scoped state-version deletion unavailable; retention handoff blocked')
        status, after = request(bundle['backend'], url)
        if status != 200 or after != raw:
            raise RuntimeError('Version pruning changed current state; retain recovery data')
        return {'version_delete_preserves_current': True, 'measured_encrypted_state_bytes': len(raw),
                'proposed_max_versions': 32, 'proposed_max_state_bytes': 8 * 1024**2}
    raise RuntimeError('No historical version available for retention qualification')


def fixture_scope(name, identities, observed, tunnel):
    unique = name.removeprefix('qualification-')
    if not name.startswith('qualification-') or len(unique) != 32 or any(char not in '0123456789abcdef' for char in unique):
        raise ValueError('Only recorded disposable scopes can be removed')
    if (observed['app']['name'] != name or not observed['app']['domain'].startswith(name + '.') or
            observed['app']['id'] != identities['app'] or observed['dns']['id'] != identities['dns'] or
            observed['dns']['name'] != observed['app']['domain'] or
            observed['dns']['content'] != identities['tunnel'] + '.cfargotunnel.com' or
            tunnel.get('id') != identities['tunnel'] or tunnel.get('name') != name or tunnel.get('connections')):
        raise ValueError('Recorded fixture scope differs from provider; cleanup refused')


def cleanup(directory, bundle):
    result = json.loads((directory / 'result.json').read_text())
    if not result.get('provider_success_failed_upload_recovery') or not result.get('repeat_plan_empty'):
        raise ValueError('Recover and verify failed upload before retiring fixture resources')
    identities = json.loads((directory / 'identities.json').read_text())
    admin, dns = API(bundle['management']['API_TOKEN']), API(bundle['dns']['API_TOKEN'])
    account, zone = bundle['management']['ACCOUNT_ID'], bundle['dns']['ZONE_ID']
    def read(client, path):
        try:
            return client.request('GET', path)
        except RuntimeError as error:
            if str(error).endswith('HTTP 404'):
                return None
            raise
    app_path = 'accounts/' + account + '/access/apps/' + identities['app']
    dns_path = 'zones/' + zone + '/dns_records/' + identities['dns']
    tunnel_path = 'accounts/' + account + '/cfd_tunnel/' + identities['tunnel']
    app, record, tunnel = read(admin, app_path), read(dns, dns_path), read(admin, tunnel_path)
    # The original provider readbacks bind missing objects during partial cleanup to this exact scope.
    before = json.loads((directory / 'before.json').read_text())
    observed = {'app': app or before['app'], 'dns': record or before['dns']}
    fixture_scope(directory.name, identities, observed,
                  tunnel or {'id': identities['tunnel'], 'name': directory.name, 'connections': []})
    # These IDs were created by this fixture owner. Protected state and failure evidence remain local.
    if record:
        dns.request('DELETE', dns_path)
    if app:
        admin.request('DELETE', app_path)
    if tunnel and not tunnel.get('deleted_at'):
        admin.request('DELETE', tunnel_path)
    for client, path in ((dns, dns_path), (admin, app_path)):
        if read(client, path) is not None:
            raise RuntimeError('Disposable resource removal not observed; recovery evidence retained')
    tunnel = read(admin, tunnel_path)
    if tunnel and not tunnel.get('deleted_at'):
        raise RuntimeError('Disposable tunnel removal not observed')
    if not delete_state(bundle['backend'], address(bundle['backend'], directory.name)):
        raise RuntimeError('Disposable backend removal not observed')
    result['disposable_resources_removed'] = True
    result['disposable_state_removed'] = True
    (directory / 'result.json').write_text(json.dumps(result))
    return directory


def qualify(baseline, bundle):
    snapshot = json.loads((baseline / 'snapshot.json').read_text())
    admin, dns = API(bundle['management']['API_TOKEN']), API(bundle['dns']['API_TOKEN'])
    account, zone = bundle['management']['ACCOUNT_ID'], bundle['dns']['ZONE_ID']
    unique = uuid.uuid4().hex
    directory = Path('/recovery/infra/cloudflare') / ('qualification-' + unique)
    directory.mkdir(mode=0o700)
    identities = {}
    def checkpoint():
        (directory / 'identities.json').write_text(json.dumps(identities))
    checkpoint()
    zone_name = dns.request('GET', 'zones/' + zone)['name']
    hostname = 'qualification-' + unique + '.' + zone_name
    original = next(app for app in snapshot['applications'].values()
                    if any(policy['decision'] == 'allow' for policy in app['policies']))
    app = {key: copy.deepcopy(original[key]) for key in (
        'session_duration', 'allowed_idps', 'app_launcher_visible', 'auto_redirect_to_identity',
        'enable_binding_cookie', 'options_preflight_bypass')}
    primary = next(policy for policy in original['policies'] if policy['decision'] == 'allow')
    primary = {key: copy.deepcopy(primary[key]) for key in ('name', 'decision', 'include', 'exclude', 'require')}
    primary.update(name='qualification-primary', precedence=1)
    unrelated = {'name': 'qualification-unrelated', 'decision': 'deny', 'precedence': 2,
                 'include': [{'email': {'email': 'denied@example.invalid'}}], 'exclude': [], 'require': []}
    app.update(name='qualification-' + unique, domain=hostname, type='self_hosted', policies=[primary, unrelated])
    created = admin.request('POST', 'accounts/' + account + '/access/apps', app)
    identities['app'] = created['id']
    checkpoint()
    existing = admin.request('GET', 'accounts/' + account + '/access/apps/' + identities['app'])
    policies = {policy['name']: policy for policy in existing['policies']}
    for key, name in (('primary', primary['name']), ('unrelated', unrelated['name'])):
        identities[key] = policies[name]['id']
    checkpoint()
    # The fixture has no connectors and serves no existing hostname.
    tunnel = admin.request('POST', 'accounts/' + account + '/cfd_tunnel',
                           {'name': 'qualification-' + unique, 'config_src': 'cloudflare'})
    identities['tunnel'] = tunnel['id']
    checkpoint()
    config = {'ingress': [{'hostname': hostname, 'service': 'https://localhost:9443', 'originRequest': {
        'originServerName': hostname, 'httpHostHeader': hostname, 'noTLSVerify': False,
        'connectTimeout': 10, 'tlsTimeout': 10, 'access': {'required': True,
        'teamName': snapshot['organization']['auth_domain'].removesuffix('.cloudflareaccess.com'),
        'audTag': [existing['aud']]}}}, {'service': 'http_status:404'}], 'warp-routing': {'enabled': False}}
    admin.request('PUT', 'accounts/' + account + '/cfd_tunnel/' + identities['tunnel'] + '/configurations', {'config': config})
    record = dns.request('POST', 'zones/' + zone + '/dns_records', {'name': hostname, 'type': 'CNAME',
        'content': identities['tunnel'] + '.cfargotunnel.com', 'ttl': 1, 'proxied': True, 'comment': 'qualification-bootstrap'})
    identities['dns'] = record['id']
    checkpoint()
    before = remote(admin, dns, bundle, identities)
    (directory / 'before.json').write_text(json.dumps(before))
    desired = {'account_id': account, 'zone_id': zone, 'tunnel_id': identities['tunnel'],
               'team_name': snapshot['organization']['auth_domain'].removesuffix('.cloudflareaccess.com'),
               'applications': {'human': {key: app[key] for key in (
                   'name', 'domain', 'session_duration', 'allowed_idps', 'app_launcher_visible', 'auto_redirect_to_identity',
                   'enable_binding_cookie', 'options_preflight_bypass')}},
               'routes': {'human': {'hostname': hostname, 'service': 'https://localhost:9443',
                                    'application': 'human', 'dns_comment': 'qualification-bootstrap'}}}
    desired['applications']['human']['policies'] = {'primary': primary, 'unrelated': unrelated}
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired))
    return exercise(directory, bundle)


def exercise(directory, bundle):
    unique = directory.name.removeprefix('qualification-')
    if not directory.name.startswith('qualification-') or len(unique) != 32 or any(char not in '0123456789abcdef' for char in unique):
        raise ValueError('Only recorded disposable scopes can resume')
    identities = json.loads((directory / 'identities.json').read_text())
    before = json.loads((directory / 'before.json').read_text())
    desired = json.loads((directory / 'desired.tfvars.json').read_text())
    if set(identities) != {'app', 'primary', 'unrelated', 'tunnel', 'dns'} or before['app']['name'] != directory.name:
        raise ValueError('Complete matching fixture identities required before resume')
    if not before['app']['domain'].startswith(directory.name + '.') or before['app']['id'] != identities['app']:
        raise ValueError('Fixture identity escaped its recorded scope')
    admin, dns = API(bundle['management']['API_TOKEN']), API(bundle['dns']['API_TOKEN'])
    account, zone = bundle['management']['ACCOUNT_ID'], bundle['dns']['ZONE_ID']
    for source in Path('/workspace/infra/cloudflare').glob('*'):
        if source.is_file() and (source.suffix == '.tf' or source.name == '.terraform.lock.hcl'):
            shutil.copyfile(source, directory / source.name)
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired))
    imports = {'cloudflare_zero_trust_access_application.application["human"]': identities['app'],
               'cloudflare_zero_trust_tunnel_cloudflared_config.routing': identities['tunnel'],
               'cloudflare_dns_record.publication["human"]': identities['dns']}
    imports.update({'cloudflare_zero_trust_access_policy.policy["human:' + key + '"]': identities[key]
                    for key in ('primary', 'unrelated')})
    (directory / 'imports.tf.json').write_text(json.dumps({'import': [
        {'to': name, 'id': (zone if name.startswith('cloudflare_dns_record') else
                           'accounts/' + account if name.startswith('cloudflare_zero_trust_access_application') else account) + '/' + identity}
        for name, identity in imports.items()]}))
    url = address(bundle['backend'], directory.name)
    env = environment(bundle['backend'], url, bundle['encryption']['PASSPHRASE'])
    env.update(CLOUDFLARE_API_TOKEN=bundle['management']['API_TOKEN'], TF_VAR_dns_api_token=bundle['dns']['API_TOKEN'])
    require(native(directory, env, 'init', '-input=false', '-lockfile=readonly'))
    status, _ = request(bundle['backend'], url)
    if status == 404:
        _, document = document_plan(directory, env, 'imports.tfplan')
        review_import(document, imports)
        require(native(directory, env, 'apply', '-input=false', '-lock-timeout=0s', 'imports.tfplan'))
    elif status == 200:
        current = json.loads(require(native(directory, env, 'state', 'pull')).stdout)
        if state_identities(current) != imports:
            raise ValueError('Interrupted fixture identities differ; resume refused')
    else:
        raise RuntimeError('Fixture backend unavailable; resume refused')
    preserved(before, remote(admin, dns, bundle, identities))
    (directory / 'imports.tf.json').unlink()
    if status == 404 and document_plan(directory, env, 'imported-repeat.tfplan')[0] != 0:
        raise RuntimeError('Imported fixture repeat plan is not empty')
    desired['applications']['human']['session_duration'] = '2h'
    desired['applications']['human']['policies']['primary']['name'] = 'qualification-primary-updated'
    desired['routes']['human'].update(service='https://localhost:9444', dns_comment='qualification-updated')
    (directory / 'desired.tfvars.json').write_text(json.dumps(desired))
    _, document = document_plan(directory, env, 'update.tfplan')
    guarded_changes(document)
    result = native(directory, env, 'apply', '-input=false', '-lock-timeout=0s', 'update.tfplan')
    policy_unsupported = policy_update_unsupported(result)
    if policy_unsupported:
        # Keep the failed capability explicit while certifying the other disposable resources.
        preserved(before, remote(admin, dns, bundle, identities))
        desired['applications']['human']['policies']['primary']['name'] = 'qualification-primary'
        (directory / 'desired.tfvars.json').write_text(json.dumps(desired))
        _, document = document_plan(directory, env, 'supported-update.tfplan')
        guarded_changes(document)
        require(native(directory, env, 'apply', '-input=false', '-lock-timeout=0s', 'supported-update.tfplan'))
    after = remote(admin, dns, bundle, identities)
    preserved(before, after)
    updated(after, desired, identities)
    (directory / 'after.json').write_text(json.dumps(after))
    if document_plan(directory, env, 'updated-repeat.tfplan')[0] != 0:
        raise RuntimeError('Updated fixture repeat plan is not empty')
    dns.request('PATCH', 'zones/' + zone + '/dns_records/' + identities['dns'], {'comment': 'qualification-drift'})
    code, document = document_plan(directory, env, 'drift.tfplan')
    if code != 2:
        raise RuntimeError('Disposable DNS drift was not detected')
    guarded_changes(document)
    require(native(directory, env, 'apply', '-input=false', '-lock-timeout=0s', 'drift.tfplan'))
    upload_recovery(directory, env, bundle, identities, desired, imports)
    preserved(before, remote(admin, dns, bundle, identities))
    retention = retention_probe(directory, env, bundle)
    (directory / 'result.json').write_text(json.dumps({'native_import': True,
        'dns_tunnel_application_update': True, 'legacy_policy_update_supported': not policy_unsupported,
        'repeat_plan_empty': True, 'identity_audience_selectors_preserved': True,
        'disposable_drift_detected_repaired': True, 'provider_success_failed_upload_recovery': True, **retention}))
    return directory


def main():
    os.umask(0o077)
    baselines = sorted(Path('/recovery/infra/cloudflare').glob('baseline-*'), key=lambda path: path.stat().st_mtime)
    if not baselines:
        raise ValueError('Private existing-owner snapshot required')
    if sys.argv[1:] in (['--resume'], ['--cleanup']):
        fixtures = sorted(Path('/recovery/infra/cloudflare').glob('qualification-*'), key=lambda path: path.stat().st_mtime)
        if not fixtures:
            raise ValueError('Recorded disposable fixture required for resume')
        directory = cleanup(fixtures[-1], credentials()) if sys.argv[1:] == ['--cleanup'] else exercise(fixtures[-1], credentials())
    elif not sys.argv[1:]:
        directory = qualify(baselines[-1], credentials())
    else:
        raise ValueError('Unknown fixture qualification operation')
    result = json.loads((directory / 'result.json').read_text())
    print(json.dumps({'private_directory': str(directory), **result, 'production_mutations': 0}))
    if not result['legacy_policy_update_supported'] and sys.argv[1:] != ['--cleanup']:
        raise RuntimeError('Legacy policy update unsupported; mandatory Cloudflare handoff blocked')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Cloudflare qualification incomplete; protected recovery data retained', file=sys.stderr)
        raise SystemExit(1) from None
