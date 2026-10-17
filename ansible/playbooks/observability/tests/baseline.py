"""Bounded authenticated release proof with a privately declared disposable viewer."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

from playbooks.secrets.files.vault import fields
from playbooks.keycloak.files.owner_enrollment import inputs
from playbooks.keycloak.files.session_fixture import scope
from playbooks.keycloak.tests.session_setup import environment, wait_private_source

CHECKPOINT = Path('/recovery/notes-baseline-fixture.json')
RESULT = Path('/recovery/notes-baseline-result.json')
ROOT = Path(__file__).resolve().parents[4]


def prepare():
    from playbooks.keycloak.tests.session_setup import prepare as prepare_viewer
    prepare_viewer(CHECKPOINT, 'applications')
    return {'disposable_applications_viewer': True, 'primary_users_changed': False, 'baseline_measured': False}


def result(document, policy):
    required = {'scenario', 'passed', 'samples', 'p95_ms', 'maximum_ms', 'failure_rate', 'evaluation_seconds'}
    if set(document) != required or document['scenario'] != 'notes-release-read' or document['passed'] is not True:
        raise ValueError('Bounded release thresholds failed')
    for key in required - {'scenario', 'passed'}:
        value = document[key]
        if type(value) not in (int, float) or not 0 <= value < float('inf'):
            raise ValueError('Release evidence must contain bounded numeric measurements')
    if (document['samples'] < policy['minimum_samples'] or document['samples'] > policy['rate_per_second'] * policy['duration_seconds'] + 1 or
            document['evaluation_seconds'] != policy['duration_seconds'] or
            document['p95_ms'] >= policy['p95_seconds'] * 1000 or document['maximum_ms'] >= policy['maximum_seconds'] * 1000 or
            document['failure_rate'] >= policy['failure_rate']):
        raise ValueError('Release evidence exceeds its versioned thresholds')
    return document


def run():
    values, api, _source, _revoked = inputs()
    environment(values)
    request = json.loads(CHECKPOINT.read_text())
    scope(request)
    if request.get('realm') != 'applications': raise ValueError('Baseline requires the applications viewer')
    credentials = fields('keycloak-proof-' + request['nonce'], ('username', 'password', 'email', 'ownership_id'))
    if credentials['username'] != 'proof-' + request['nonce'] or credentials['ownership_id'] != request['nonce']:
        raise ValueError('Baseline viewer ownership changed')
    from automation.services.inputs import catalog
    entries = [entry for entry in catalog(required=True)['catalog'] if entry['publication'] == 'published' and
               entry['definition']['name'] == 'notes' and entry['approval'].get('chartPath') == 'apps/notes']
    if len(entries) != 1: raise ValueError('One approved Notes service required')
    origin = 'https://' + entries[0]['definition']['exposure']['hostname']
    issuer = 'https://' + metadata()['loginHost'] + '/realms/applications'
    saved = json.loads(RESULT.read_text()) if RESULT.exists() else {}
    policy = json.loads((ROOT / 'apps/notes/slo.json').read_text())['release']
    if saved.get('nonce') == request['nonce']:
        evidence = result(saved['evidence'], policy)
    else:
        evidence = measure(request, credentials, origin, issuer, policy)
        from playbooks.data.files.control import atomic
        atomic(RESULT, {'nonce': request['nonce'], 'evidence': evidence})
    retire(api, values, request)
    return dict(evidence, viewer_mfa=True, disposable_viewer_offboarded=True, primary_users_changed=False)


def cleanup():
    """Retire a failed disposable login before registering a fresh virtual passkey."""
    values, api, _source, _revoked = inputs()
    environment(values)
    request = json.loads(CHECKPOINT.read_text())
    scope(request)
    if request.get('realm') != 'applications': raise ValueError('Baseline cleanup requires the applications viewer')
    credentials = fields('keycloak-proof-' + request['nonce'], ('username', 'ownership_id'))
    if credentials != {'username': 'proof-' + request['nonce'], 'ownership_id': request['nonce']}:
        raise ValueError('Baseline viewer ownership changed')
    retire(api, values, request)
    return {'disposable_viewer_offboarded': True, 'primary_users_changed': False}


def retire(api, values, request):
    from playbooks.keycloak.tests.session_setup import retire as retire_viewer
    retire_viewer(api, values, request, CHECKPOINT)


def measure(request, credentials, origin, issuer, policy):
    deadline = time.monotonic() + 60
    connection = None
    while time.monotonic() < deadline:
        try:
            connection = socket.create_connection(('baseline-browser', 5055), timeout=5)
            break
        except OSError: time.sleep(1)
    if connection is None: raise RuntimeError('Pinned browser controller unavailable')
    try:
        connection.settimeout(150)
        connection.sendall((json.dumps({'nonce': request['nonce'], 'username': credentials['username'],
            'password': credentials['password'], 'origin': origin, 'issuer': issuer}) + '\n').encode())
        with connection.makefile('rb') as messages:
            raw = messages.readline(65537)
            if len(raw) > 65536: raise RuntimeError('Browser evidence exceeds its bound')
            issued = json.loads(raw)
        if issued.get('viewer_mfa') is not True or set(issued) != {'access_token', 'viewer_mfa'}:
            raise RuntimeError('Disposable viewer MFA incomplete; no release traffic sent')
        token = issued['access_token']
        if not isinstance(token, str) or not 32 <= len(token) <= 16384:
            raise ValueError('Transient viewer token invalid')
        version = subprocess.check_output(['k6', 'version'], text=True, timeout=10)
        if not version.startswith('k6 v2.3.0 '): raise RuntimeError('Release proof requires the pinned k6 binary')
        completed = subprocess.run(['k6', 'run', '--quiet', '--log-output=none', '--no-usage-report', 'release.k6.js'],
            cwd=ROOT / 'apps/notes', capture_output=True, text=True, timeout=policy['duration_seconds'] + 30,
            env={'PATH': os.environ['PATH'], 'RELEASE_ORIGIN': origin, 'RELEASE_TOKEN': token})
        if completed.returncode: raise RuntimeError('Release thresholds failed; raw diagnostics withheld')
        evidence = result(json.loads(completed.stdout), policy)
    finally:
        try: connection.sendall(b'{"finish":true}\n')
        finally: connection.close()
    return evidence


if __name__ == '__main__':
    try: print(json.dumps({'prepare': prepare, 'run': run, 'cleanup': cleanup}[sys.argv[1]](), sort_keys=True))
    except Exception:
        raise SystemExit('Notes baseline incomplete; preserve its private checkpoint. Credentials and diagnostics withheld') from None
