"""Disposable GitLab HTTP backend checks; never import production resources."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

from dotenv import dotenv_values
from playbooks.secrets.files.vault import fields
from automation.infra.backend import environment


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def address(values, name):
    if not re.fullmatch(r'[1-9][0-9]*', values['PROJECT_ID']):
        raise ValueError('GitLab PROJECT_ID must be numeric')
    if not re.fullmatch(r'qualification-[a-f0-9]{32}', name):
        raise ValueError('Only disposable qualification state names are permitted')
    return 'https://gitlab.com/api/v4/projects/' + values['PROJECT_ID'] + '/terraform/state/' + name


def request(values, url, method='GET', document=None, anonymous=False):
    if not re.fullmatch(r'https://gitlab[.]com/api/v4/projects/[1-9][0-9]*/terraform/state/qualification-[a-f0-9]{32}(?:/lock|/versions/[0-9]+)?', url):
        raise ValueError('GitLab request escaped disposable state scope')
    headers = {'Content-Type': 'application/json'}
    if not anonymous:
        basic = base64.b64encode((values['USERNAME'] + ':' + values['TOKEN']).encode()).decode()
        headers['Authorization'] = 'Basic ' + basic
    req = urllib.request.Request(url, method=method, headers=headers,
                                 data=json.dumps(document).encode() if document is not None else None)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=30) as response:
            return response.status, response.read(16 * 1024**2)
    except urllib.error.HTTPError as error:
        return error.code, error.read(16 * 1024)


def delete_state(values, url):
    """GitLab deletion is asynchronous; require observed absence, not acceptance alone."""
    if request(values, url, 'DELETE')[0] not in (200, 202, 204, 404):
        return False
    for _ in range(30):
        status, _ = request(values, url)
        if status == 404:
            return True
        if status != 200:
            return False
        time.sleep(2)
    return False


def write_root(root, generation):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / 'main.tf.json').write_text(json.dumps({
        'terraform': {'required_version': '= 1.13.1', 'backend': {'http': {}}},
        'resource': {'terraform_data': {'fixture': {'input': generation}}},
    }))


def tofu(root, env, *arguments, input_data=None):
    command = ['tofu', *arguments]
    if arguments[:2] == ('state', 'push'):
        command.insert(3, '-no-color')
    else:
        command.append('-no-color')
    result = subprocess.run(command, cwd=root, env=env,
                            input=input_data, capture_output=True, timeout=120)
    # Raw diagnostics can include private locations and stay in protected local storage.
    diagnostics = result.stderr if arguments[:2] == ('state', 'pull') else result.stdout + result.stderr
    (root / 'last-diagnostics.txt').write_bytes(diagnostics)
    return result


def fixture_input(attributes, expected):
    return attributes.get('input') in (expected, {'value': expected, 'type': 'string'})


def failed_upload(root, env, values, url, identity):
    """Inject upload failure after a native terraform_data update, then recover state."""
    class UploadFailure(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            status, data = request(values, url)
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
    write_root(root, 'synthetic-generation-3')
    try:
        initialized = tofu(root, faulty, 'init', '-input=false', '-reconfigure')
        if initialized.returncode:
            return {'failed_upload_injected': False}
        failed = tofu(root, faulty, 'apply', '-input=false', '-auto-approve', '-lock-timeout=0s')
        recovery = root / 'errored.tfstate'
        protected = recovery.exists() and b'synthetic-generation-3' not in recovery.read_bytes()
        results = {'failed_upload_injected': failed.returncode != 0 and protected}
        if not results['failed_upload_injected']:
            return results
        # Keep protected recovery state. Never automatically force-unlock or force-push.
        (root.parent / 'upload-failure-diagnostics.txt').write_bytes(failed.stdout + failed.stderr)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    # state push accepts plaintext source only. Decrypt with a local backend and
    # pass through stdin; no plaintext state file or encryption downgrade.
    decrypt_root = root.parent / 'decrypt-recovery'
    write_root(decrypt_root, 'synthetic-generation-3')
    configuration = json.loads((decrypt_root / 'main.tf.json').read_text())
    configuration['terraform']['backend'] = {'local': {'path': str(recovery)}}
    (decrypt_root / 'main.tf.json').write_text(json.dumps(configuration))
    local_env = {key: value for key, value in env.items() if not key.startswith('TF_HTTP_')}
    initialized_local = tofu(decrypt_root, local_env, 'init', '-input=false')
    decrypted = tofu(decrypt_root, local_env, 'state', 'pull') if initialized_local.returncode == 0 else initialized_local
    if decrypted.returncode:
        return dict(results, recovery_decryption=False)
    state = json.loads(decrypted.stdout)
    attrs = state.get('resources', [{}])[0].get('instances', [{}])[0].get('attributes', {})
    if not fixture_input(attrs, 'synthetic-generation-3') or attrs.get('id') != identity:
        return dict(results, recovery_identity_matches=False)
    initialized = tofu(root, env, 'init', '-input=false', '-reconfigure')
    pushed = tofu(root, env, 'state', 'push', '-', input_data=decrypted.stdout) if initialized.returncode == 0 else initialized
    results['recovery_state_pushed_without_force'] = pushed.returncode == 0
    if pushed.returncode:
        (root.parent / 'recovery-push-diagnostics.txt').write_bytes(pushed.stdout + pushed.stderr)
        return results
    pulled = tofu(root, env, 'state', 'pull')
    document = json.loads(pulled.stdout) if pulled.returncode == 0 else {}
    attributes = document.get('resources', [{}])[0].get('instances', [{}])[0].get('attributes', {})
    results['recovered_identity_preserved'] = fixture_input(attributes, 'synthetic-generation-3') and attributes.get('id') == identity
    repeated = tofu(root, env, 'plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s')
    results['recovered_repeat_plan_empty'] = repeated.returncode == 0
    return results


def qualify(label, values, other):
    name = 'qualification-' + secrets.token_hex(16)
    url = address(values, name)
    root = Path('/recovery/infra/gitlab') / label / name
    root.mkdir(mode=0o700, parents=True)
    passphrase = secrets.token_urlsafe(48)
    (root / 'recovery-passphrase').write_text(passphrase)
    (root / 'private-backend.json').write_text(json.dumps({'url': url}))
    env = environment(values, url, passphrase)
    results = {'credential_read': True, 'production_mutations': 0}
    status, _ = request(values, url)
    results['initial_read_http_status'] = status
    if status != 404:
        return dict(results, blocker='Disposable state read must return 404 before creation')
    primary, independent = root / 'client-one', root / 'client-two'
    write_root(primary, 'synthetic-generation-1')
    initialized = tofu(primary, env, 'init', '-input=false')
    results['native_init'] = initialized.returncode == 0
    if initialized.returncode:
        return dict(results, blocker='Native HTTP init failed; protected diagnostics retained')
    applied = tofu(primary, env, 'apply', '-input=false', '-auto-approve', '-lock-timeout=0s')
    results['native_apply'] = applied.returncode == 0
    if applied.returncode:
        return dict(results, blocker='Native HTTP apply failed; protected recovery directory retained')
    status, raw = request(values, url)
    if status != 200:
        return dict(results, blocker='Native state could not be retrieved')
    (root / 'generation-one.encrypted').write_bytes(raw)
    results['encrypted_retrieval'] = b'synthetic-generation-1' not in raw and b'encrypted_data' in raw
    results['cross_project_denied'] = request(other, url)[0] in (401, 403, 404)
    results['cross_project_write_denied'] = request(other, url, 'POST', json.loads(raw))[0] in (401, 403, 404)
    results['anonymous_denied'] = request(values, url, anonymous=True)[0] in (401, 403, 404)
    first = tofu(primary, env, 'state', 'pull')
    if first.returncode:
        return dict(results, blocker='Independent decryption failed')
    decoded = json.loads(first.stdout)
    identity = decoded['resources'][0]['instances'][0]['attributes']['id']
    serial = decoded['serial']
    lock = {'ID': str(uuid.uuid4()), 'Operation': 'OperationTypeApply', 'Info': 'Disposable qualification', 'Who': 'independent-client',
            'Version': '1.13.1', 'Created': '2026-10-11T00:00:00Z', 'Path': 'qualification'}
    (root / 'owned-lock.json').write_text(json.dumps(lock))
    lock_status, _ = request(values, url + '/lock', 'POST', lock)
    results['lock_http_status'] = lock_status
    results['lock_acquired'] = lock_status in (200, 201)
    if not results['lock_acquired']:
        return dict(results, blocker='Explicit disposable lock acquisition failed')
    try:
        write_root(independent, 'synthetic-generation-1')
        init_two = tofu(independent, env, 'init', '-input=false')
        second = tofu(independent, env, 'apply', '-input=false', '-auto-approve', '-lock-timeout=0s') if init_two.returncode == 0 else init_two
        results['concurrent_apply_rejected'] = (second.returncode != 0 and
                                                b'Error acquiring the state lock' in second.stdout + second.stderr)
    finally:
        unlock_status, _ = request(values, url + '/lock', 'DELETE', lock)
        results['owned_lock_released'] = unlock_status in (200, 204)
    write_root(primary, 'synthetic-generation-2')
    updated = tofu(primary, env, 'apply', '-input=false', '-auto-approve', '-lock-timeout=0s')
    results['native_update'] = updated.returncode == 0
    if updated.returncode:
        return dict(results, blocker='Native update failed; recovery directory retained')
    status, previous = request(values, url + '/versions/' + str(serial))
    results['version_retrieval'] = status == 200 and hashlib.sha256(previous).digest() == hashlib.sha256(raw).digest()
    pulled = tofu(independent, env, 'state', 'pull')
    current = json.loads(pulled.stdout) if pulled.returncode == 0 else {}
    attributes = current.get('resources', [{}])[0].get('instances', [{}])[0].get('attributes', {})
    results['independent_decryption'] = fixture_input(attributes, 'synthetic-generation-2')
    results['identity_preserved'] = attributes.get('id') == identity
    restored = root / 'isolated-restore'
    write_root(restored, 'synthetic-generation-1')
    restored_config = json.loads((restored / 'main.tf.json').read_text())
    restored_config['terraform']['backend'] = {'local': {'path': str(root / 'generation-one.encrypted')}}
    (restored / 'main.tf.json').write_text(json.dumps(restored_config))
    restore_env = {key: value for key, value in env.items() if not key.startswith('TF_HTTP_')}
    initialized_restore = tofu(restored, restore_env, 'init', '-input=false')
    restored_pull = tofu(restored, restore_env, 'state', 'pull') if initialized_restore.returncode == 0 else initialized_restore
    restored_state = json.loads(restored_pull.stdout) if restored_pull.returncode == 0 else {}
    restored_attributes = restored_state.get('resources', [{}])[0].get('instances', [{}])[0].get('attributes', {})
    results['isolated_version_restore'] = (fixture_input(restored_attributes, 'synthetic-generation-1') and
                                          restored_attributes.get('id') == identity)
    wrong_key = environment(values, url, secrets.token_urlsafe(48))
    wrong_key = {key: value for key, value in wrong_key.items() if not key.startswith('TF_HTTP_')}
    wrong_pull = tofu(restored, wrong_key, 'state', 'pull')
    results['wrong_key_rejected'] = wrong_pull.returncode != 0
    repeated = tofu(independent, env, 'plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s')
    # The independent root intentionally still declares generation one, proving drift is visible.
    results['drift_detected'] = repeated.returncode == 2
    write_root(independent, 'synthetic-generation-2')
    repeated = tofu(independent, env, 'plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s')
    results['repeat_plan_empty'] = repeated.returncode == 0
    results.update(failed_upload(primary, env, values, url, identity))
    if not all(value for value in results.values() if type(value) is bool):
        (root / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
        return dict(results, blocker='Disposable qualification incomplete; recovery state retained')
    destroyed = tofu(primary, env, 'destroy', '-input=false', '-auto-approve', '-lock-timeout=0s')
    results['disposable_destroy'] = destroyed.returncode == 0
    if destroyed.returncode == 0:
        results['disposable_state_deleted'] = delete_state(values, url)
    (root / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    return results


def cleanup_incomplete(label, values):
    """Explicit cleanup of recorded native fixtures; no unlock or remote force."""
    removed = 0
    for root in (Path('/recovery/infra/gitlab') / label).glob('qualification-*'):
        url = json.loads((root / 'private-backend.json').read_text())['url']
        if url != address(values, root.name):
            raise ValueError('Recorded fixture belongs to a different backend')
        status, _ = request(values, url)
        if status == 404:
            continue
        if status != 200:
            raise RuntimeError('Recorded qualification state unavailable; cleanup refused')
        primary = root / 'client-one'
        configuration = json.loads((primary / 'main.tf.json').read_text())
        generation = configuration.get('resource', {}).get('terraform_data', {}).get('fixture', {}).get('input')
        expected = {'terraform': {'required_version': '= 1.13.1', 'backend': {'http': {}}},
                    'resource': {'terraform_data': {'fixture': {'input': generation}}}}
        if configuration != expected or generation not in ('synthetic-generation-1', 'synthetic-generation-2', 'synthetic-generation-3'):
            raise ValueError('Cleanup refuses resources outside the exact native fixture')
        env = environment(values, url, (root / 'recovery-passphrase').read_text())
        initialized = tofu(primary, env, 'init', '-input=false', '-reconfigure')
        destroyed = tofu(primary, env, 'destroy', '-input=false', '-auto-approve', '-lock-timeout=0s') if initialized.returncode == 0 else initialized
        if destroyed.returncode or not delete_state(values, url):
            raise RuntimeError('Recorded fixture cleanup failed; preserve recovery material')
        removed += 1
    return {'root': label, 'recorded_disposable_states_removed': removed, 'production_mutations': 0}


def main():
    os.umask(0o077)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = dotenv_values('/workspace/.env', interpolate=False).get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = {label: fields('gitlab-state-' + label, ('PROJECT_ID', 'USERNAME', 'TOKEN'))
                   for label in ('cloudflare', 'github')}
    if credentials['cloudflare']['PROJECT_ID'] == credentials['github']['PROJECT_ID']:
        raise ValueError('Qualification requires separate projects')
    if sys.argv[1:] == ['--cleanup']:
        for label, values in credentials.items():
            print(json.dumps(cleanup_incomplete(label, values)), flush=True)
        return 0
    if sys.argv[1:]:
        raise ValueError('Unknown qualification operation')
    successful = True
    for label, other in (('cloudflare', 'github'), ('github', 'cloudflare')):
        result = qualify(label, credentials[label], credentials[other])
        print(json.dumps({'root': label, **result}), flush=True)
        if result.get('blocker'):
            return 1
        successful = successful and all(value for value in result.values() if type(value) is bool)
    return 0 if successful else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError, OSError, subprocess.TimeoutExpired):
        raise SystemExit('GitLab qualification incomplete; protected diagnostics retained. No production handoff.') from None
