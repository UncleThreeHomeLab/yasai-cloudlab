"""Qualify pinned API-only resources on disposable Grafana OSS, never the lab."""
import base64
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import traceback
import urllib.error
import urllib.request

from automation.observability.native_proof import wait

WORK = Path('/candidate')
AUTH = None


def request(path, method='GET', value=None, token=None, expected=200):
    authorization = 'Bearer ' + token if token else 'Basic ' + base64.b64encode(AUTH.encode()).decode()
    req = urllib.request.Request('http://grafana:3000' + path, method=method,
        data=None if value is None else json.dumps(value).encode(),
        headers={'Authorization': authorization, 'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            status, raw = response.status, response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(1024 * 1024 + 1)
        error.close()
    if status != expected or len(raw) > 1024 * 1024:
        raise RuntimeError('Pinned Grafana fixture HTTP assertion failed: expected ' + str(expected) + ', received ' + str(status))
    return json.loads(raw) if raw else None


def tofu(*arguments, expected=0):
    result = subprocess.run(['tofu', *arguments, '-no-color'], cwd=WORK,
                            capture_output=True, text=True, timeout=120)
    if result.returncode != expected:
        (WORK / 'private-diagnostics').write_text(result.stderr)
        raise RuntimeError('Pinned Grafana provider fixture failed: ' + arguments[0])
    return result.stdout


def plan():
    tofu('plan', '-input=false', '-out=fixture.plan')
    return json.loads(tofu('show', '-json', 'fixture.plan'))


def changes(document):
    return {row['address']: row['change']['actions'] for row in document.get('resource_changes', [])
            if row['change']['actions'] != ['no-op']}


def main():
    global AUTH
    os.umask(0o077)
    AUTH = 'fixture-admin:' + Path('/fixture/grafana_password').read_text()
    wait(lambda: request('/api/health').get('database') == 'ok')
    plugins = {row['id'] for row in request('/api/plugins')}
    if not {'prometheus', 'loki', 'tempo'} <= plugins:
        raise RuntimeError('Pinned offline Grafana lacks a required data-source plugin')
    account = request('/api/serviceaccounts', 'POST', {'name': 'cloudlab-fixture-machine', 'role': 'Viewer'}, expected=201)
    identifier = account['id']
    configuration = {'provider': {'grafana': {'url': 'http://grafana:3000', 'auth': AUTH}},
        'resource': {'grafana_service_account': {'machine': {'name': 'cloudlab-fixture-machine', 'role': 'Viewer'}},
                     'grafana_service_account_token': {'machine': {'name': 'bounded-fixture',
                         'service_account_id': '${grafana_service_account.machine.id}', 'seconds_to_live': 30}}}}
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    tofu('import', '-input=false', 'grafana_service_account.machine', str(identifier))
    if changes(plan()) != {'grafana_service_account_token.machine': ['create']}:
        raise RuntimeError('Pinned OSS service-account import is not convergent')
    tofu('apply', '-input=false', '-auto-approve', 'fixture.plan')
    if changes(plan()): raise RuntimeError('Pinned Grafana repeat plan differs')
    state = json.loads(tofu('show', '-json'))
    rows = {row['address']: row['values'] for row in state['values']['root_module']['resources']}
    token = rows['grafana_service_account_token.machine']['key']
    request('/api/search', token=token)
    request('/api/serviceaccounts', 'POST', {'name': 'unauthorized-machine', 'role': 'Admin'}, token=token, expected=403)
    inventory = request('/api/serviceaccounts/' + str(identifier) + '/tokens')
    if any(token == value for row in inventory for value in row.values()):
        raise RuntimeError('Grafana token inventory unexpectedly returns credentials')
    # The once-issued token remains recoverable in ordinary provider state.
    if token not in (WORK / 'terraform.tfstate').read_text():
        raise RuntimeError('Expected sensitive state exposure was not observed')
    # Import must target a declared resource, so qualify the token importer itself.
    configuration['resource']['grafana_service_account_token']['unknown'] = dict(
        configuration['resource']['grafana_service_account_token']['machine'], name='unknown-fixture')
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    imported = subprocess.run(['tofu', 'import', '-input=false', '-no-color',
        'grafana_service_account_token.unknown', str(identifier) + ':' + str(inventory[0]['id'])],
        cwd=WORK, capture_output=True, timeout=120)
    if imported.returncode == 0 or not any(message in imported.stderr.lower() for message in
            (b'does not support import', b"doesn't support import", b'resource import not implemented')):
        (WORK / 'private-import-diagnostics').write_bytes(imported.stderr)
        raise RuntimeError('Token import capability changed; review ownership disposition')
    del configuration['resource']['grafana_service_account_token']['unknown']
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    request('/api/serviceaccounts/' + str(identifier), 'PATCH', {'name': 'cloudlab-fixture-machine', 'role': 'Editor'})
    if changes(plan()) != {'grafana_service_account.machine': ['update']}:
        raise RuntimeError('Pinned service-account drift repair changed token ownership')
    tofu('apply', '-input=false', '-auto-approve', 'fixture.plan')
    if changes(plan()): raise RuntimeError('Pinned service-account repair repeat is not empty')
    request('/api/serviceaccounts', 'POST', {'name': 'unrelated-fixture', 'role': 'Viewer'}, expected=201)
    replacement = secrets.token_urlsafe(48)
    request('/api/admin/users/1/password', 'PUT', {'password': replacement})
    request('/api/serviceaccounts/search', expected=401)
    AUTH = 'fixture-admin:' + replacement
    request('/api/serviceaccounts/search')
    request('/api/search', token=token)
    time.sleep(31)
    request('/api/search', token=token, expected=401)
    configuration['provider']['grafana']['auth'] = AUTH
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    tofu('destroy', '-auto-approve', '-input=false')
    inventory = request('/api/serviceaccounts/search')
    if any(row['name'] == 'cloudlab-fixture-machine' for row in inventory['serviceAccounts']) or not any(
            row['name'] == 'unrelated-fixture' for row in inventory['serviceAccounts']):
        raise RuntimeError('Pinned scoped destroy changed unrelated Grafana accounts')
    print(json.dumps({'oss_version': '13.2.4', 'provider_version': '4.49.0', 'service_account_import': True,
        'repeat_plan_empty': True, 'drift_repair': True, 'viewer_write_denied': True, 'offline_core_plugins': True,
        'token_import_supported': False, 'token_inventory_retrieval': False, 'token_in_state': True,
        'token_expiry_denied': True, 'emergency_password_rotation': True, 'unrelated_account_preserved': True}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        message = str(error) if isinstance(error, RuntimeError) else 'Private fixture diagnostics withheld'
        raise SystemExit('Pinned Grafana qualification failed at ' + frame.name + ':' + str(frame.lineno) + ': ' + message) from None
