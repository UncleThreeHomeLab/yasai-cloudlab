"""Prepare a disposable platform viewer only after native Harbor acceptance."""
import fcntl
import json
import os
from pathlib import Path
import socket
import sys
import time

from playbooks.infrastructure.files import harbor as api
from playbooks.keycloak.tests.session_setup import prepare as prepare_viewer

CHECKPOINT = api.WORK / 'browser/fixture.json'
RESULT = api.WORK / 'browser/result.json'
PENDING = api.WORK / 'browser/pending.json'


def prepare():
    os.umask(0o077)
    api.WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = api.Client()
        with client.connected(browser=True):
            # Includes OIDC prerequisites, exact group roles, imported IDs and preservation fields.
            accepted = client.plan(verify=True)
            if accepted.get('changes') != 0 or accepted.get('apply_blocked') is not None:
                raise RuntimeError('Accept the unchanged native Harbor API root before human enrollment')
        CHECKPOINT.parent.mkdir(mode=0o700, exist_ok=True)
        return dict(prepare_viewer(CHECKPOINT, 'platform'), harbor_browser_acceptance_proven=False)


def observation(document):
    timings = ('browser_cookie_denied_seconds', 'oidc_cli_denied_seconds', 'last_registry_token_denied_seconds')
    if (not isinstance(document, dict) or set(document) != {*timings, 'offboarded_new_login_denied', 'sessions_persisted'} or
            document['offboarded_new_login_denied'] is not True or document['sessions_persisted'] is not False):
        raise ValueError('Harbor browser evidence must contain only bounded session observations')
    for key in timings:
        maximum = 245 if key == 'browser_cookie_denied_seconds' else 1500
        if type(document[key]) not in (int, float) or not 0 <= document[key] <= maximum:
            raise ValueError('Harbor browser session termination bound exceeded')
    return document


def receive(stream):
    raw = stream.readline(16385)
    if not raw or len(raw) > 16384:
        raise RuntimeError('Browser evidence exceeds its bounded protocol')
    return json.loads(raw)


def diagnostic(document):
    value = document if isinstance(document, dict) else {}
    stages = ('input', 'account enrollment', 'account password', 'WebAuthn registration', 'account session',
              'native Harbor OIDC', 'Harbor viewer roles', 'native OIDC CLI token', 'Harbor cookie bound',
              'Harbor offboarding observation', 'offboarded new Harbor login')
    codes = ('ERR_NAME_NOT_RESOLVED', 'ERR_ADDRESS_UNREACHABLE', 'ERR_CONNECTION_TIMED_OUT',
             'ERR_CONNECTION_REFUSED', 'ERR_CERT_AUTHORITY_INVALID', 'ERR_CERT_COMMON_NAME_INVALID',
             'ERR_BLOCKED_BY_LOCAL_NETWORK_ACCESS_CHECKS', 'ERR_NETWORK_CHANGED', 'ERR_INTERNET_DISCONNECTED',
             'ERR_TIMED_OUT', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNREFUSED', 'EHOSTUNREACH')
    return {'browser_failed_stage': value.get('stage') if value.get('stage') in stages else 'baseline',
            'error_type': value.get('error_type') if value.get('error_type') in ('Error', 'TimeoutError', 'TypeError') else None,
            'network_code': value.get('network_code') if value.get('network_code') in codes else None}


def cleanup():
    from playbooks.secrets.files.vault import fields
    from playbooks.keycloak.files.owner_enrollment import inputs
    from playbooks.keycloak.files.session_fixture import scope
    from playbooks.keycloak.tests.session_setup import environment, retire
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        values, github, _source, _revoked = inputs()
        environment(values)
        request = json.loads(CHECKPOINT.read_text())
        nonce = scope(request)
        if request.get('realm') != 'platform' or fields('keycloak-proof-' + nonce, ('username', 'ownership_id')) != {
                'username': 'proof-' + nonce, 'ownership_id': nonce}:
            raise ValueError('Harbor cleanup requires its exact disposable platform ownership')
        retire(github, values, request, CHECKPOINT)
    return {'disposable_viewer_offboarded': True, 'original_vault_inputs_preserved': True}


def complete(client, request, pending):
    """Finish read-only acceptance without creating another browser session."""
    from playbooks.harbor.files.recovery import atomic
    from playbooks.keycloak.tests.session_acceptance import remote_state
    from playbooks.keycloak.files.session_fixture import scope
    nonce = scope(request)
    if (request.get('realm') != 'platform' or set(pending) != {
            'nonce', 'user_id', 'preservation', 'binding', 'observation'} or pending['nonce'] != nonce):
        raise ValueError('Pending Harbor browser evidence belongs to another fixture')
    measured = observation(pending['observation'])
    current = remote_state(request)
    if (current['realm'] != 'platform' or current['username'] != 'proof-' + nonce or
            current['user_id'] != pending['user_id'] or current['enabled'] is not False or
            current['preservation'] != pending['preservation']):
        raise RuntimeError('Pending Harbor browser identity or preservation changed')
    with client.connected():
        client.unchanged(pending['binding'])
        checked = client.plan(verify=True)
        if checked.get('changes') != 0 or checked.get('apply_blocked') is not None:
            raise RuntimeError('Pending Harbor browser API preservation is incomplete')
    result = dict(measured, native_harbor_oidc=True, viewer_project_roles=True,
                  unrelated_identities_preserved=True, private_revocation_persisted=True,
                  native_resource_ids_preserved=True)
    atomic(RESULT, {'nonce': nonce, 'result': result, 'verified_at': time.time()})
    PENDING.unlink()
    return result


def verify():
    from playbooks.keycloak.files.owner_enrollment import inputs
    from playbooks.keycloak.tests.session_setup import environment
    from playbooks.keycloak.files.session_fixture import scope
    os.umask(0o077)
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        values, _github, _source, revoked = inputs()
        environment(values)
        request = json.loads(CHECKPOINT.read_text())
        nonce = scope(request)
        if 'proof-' + nonce not in revoked['realms'].get('platform', {}).get('users', []):
            raise ValueError('Pending Harbor browser evidence requires the retained private tombstone')
        return complete(api.Client(), request, json.loads(PENDING.read_text()))


def run():
    from playbooks.access.files.verify import remote
    from playbooks.secrets.files.vault import fields
    from playbooks.harbor.files.artifacts import receipt
    from playbooks.harbor.files.recovery import atomic
    from playbooks.keycloak.files.lifecycle import local_offboard
    from playbooks.keycloak.files.owner_enrollment import inputs
    from playbooks.keycloak.tests.session_acceptance import remote_state, offboard_inputs
    from playbooks.keycloak.files.session_fixture import scope
    from playbooks.keycloak.tests.session_setup import environment
    os.umask(0o077)
    values, github, _source, _revoked = inputs()
    environment(values)
    request = json.loads(CHECKPOINT.read_text())
    nonce = scope(request)
    if request.get('realm') != 'platform':
        raise ValueError('Harbor requires its exact platform fixture')
    proof = fields('keycloak-proof-' + nonce, ('username', 'password', 'email', 'ownership_id'))
    before = remote_state(request)
    if (proof['ownership_id'] != nonce or before['enabled'] is not True or before['groups'] != ['/viewer'] or
            before['username'] != proof['username'] or before['email'] != proof['email']):
        raise ValueError('Harbor browser requires its active exact disposable viewer')
    runtime = remote('runtime')
    with (api.WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        client = api.Client()
        with client.connected(browser=True):
            client.plan(verify=True)
            origin = 'https://' + client.private['host']
            source_binding = client.snapshot()
        artifacts = receipt(api.WORK / 'artifacts/receipt.json')
        if not artifacts.get('verified_at'):
            raise ValueError('Complete independent bootstrap and node pulls before human browser acceptance')
        browser_input = {'nonce': nonce, 'username': proof['username'], 'password': proof['password'],
                  'subject': before['user_id'], 'digest': artifacts['projects']['cloudlab-public']['digest'],
                  'origin': origin, 'issuer': 'https://login.' + runtime['zone'] + '/realms/platform',
                  'gateway_address': runtime['private']['tailnet_gateway']}
        deadline = time.monotonic() + 90
        while True:
            try:
                connection = socket.create_connection(('harbor-browser', 5055), timeout=5)
                break
            except OSError:
                if time.monotonic() >= deadline: raise RuntimeError('Pinned Harbor browser unavailable') from None
                time.sleep(1)
        with connection:
            connection.settimeout(1680)
            stream = connection.makefile('rwb')
            stream.write((json.dumps(browser_input) + '\n').encode()); stream.flush()
            ready = receive(stream)
            expected = {'ready', 'native_harbor_oidc', 'viewer_public_project_allowed',
                        'viewer_private_project_denied', 'viewer_admin_denied', 'native_oidc_cli_pull'}
            if not isinstance(ready, dict) or set(ready) != expected or any(ready[key] is not True for key in expected):
                print(json.dumps(diagnostic(ready)), flush=True)
                raise RuntimeError('Harbor browser baseline incomplete; private fixture retained')
            stream.write(b'{"action":"observe-offboarding"}\n'); stream.flush()
            started = time.monotonic()
            offboard_inputs(github, values, request)
            while remote_state(request)['enabled'] is not False:
                if time.monotonic() - started > 900:
                    raise RuntimeError('Private viewer offboarding convergence deadline exceeded')
                time.sleep(5)
            local_offboard({key: before[key] for key in ('realm', 'username', 'user_id', 'email')})
            observed = receive(stream)
            if isinstance(observed, dict) and observed.get('failed') is True:
                print(json.dumps(diagnostic(observed)), flush=True)
            measured = observation(observed)
        pending = {'nonce': nonce, 'user_id': before['user_id'], 'preservation': before['preservation'],
                   'binding': source_binding, 'observation': measured}
        # Keep bounded evidence before any final network/state check can fail.
        # No passwords, cookies, CLI secrets or registry tokens enter this record.
        atomic(PENDING, pending)
        return complete(client, request, pending)


if __name__ == '__main__':
    try:
        os.umask(0o077)
        operations = {'prepare': prepare, 'run': run, 'verify': verify, 'cleanup': cleanup}
        if len(sys.argv) != 2 or sys.argv[1] not in operations:
            raise ValueError('Unknown Harbor browser operation')
        print(json.dumps(operations[sys.argv[1]](), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor browser preparation incomplete; retain private ownership and vault inputs') from None
