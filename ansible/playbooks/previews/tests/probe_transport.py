"""Controller authorization for one same-session SSH access frame."""
import base64
import os
import re
import resource
import secrets
import subprocess
import time

from playbooks.previews.files import contract
from playbooks.previews.tests.probe_inspection import decode, validate_result

REMOTE = 'python3 /opt/cloudlab/playbooks/previews/tests/probe_inspection.py'


def client_assurance(timeout=10):
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    host = os.environ['VM_HOST']; user = os.environ['VM_USER']; port = os.environ.get('VM_PORT') or '22'
    result = subprocess.run(['ssh', '-G', '-T', '-p', port, '-o', 'StrictHostKeyChecking=yes',
        '-o', 'UserKnownHostsFile=/state/known_hosts', user + '@' + host], capture_output=True, text=True, timeout=timeout)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError('Private probe SSH prerequisite unavailable')
    values = dict(line.split(' ', 1) for line in result.stdout.splitlines() if ' ' in line)
    if (values.get('requesttty') != 'false' or values.get('permitlocalcommand') != 'no' or
            values.get('proxycommand', 'none') != 'none' or values.get('proxyjump', 'none') != 'none' or
            values.get('controlmaster') not in ('false', 'no') or values.get('controlpath', 'none') != 'none' or
            values.get('remotecommand', 'none') != 'none' or values.get('localcommand', 'none') != 'none' or
            values.get('loglevel') not in ('QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE') or
            values.get('hostname') != host or values.get('user') != user or user != 'root'):
        raise ValueError('Private probe SSH prerequisite unavailable')
    return contract.digest(contract.canonical(values))


def readiness(value, request, prior):
    if (not isinstance(value, dict) or set(value) != {'action', 'challenge', 'serverNonce', 'revision', 'digests', 'assurance',
            'bindings', 'namespaceUID', 'podUID'} or value['action'] != 'ready' or value['challenge'] != request['challenge'] or
            value['revision'] != request['revision'] or value['digests'] != request['digests'] or
            any(not isinstance(value.get(key), str) or not re.fullmatch('[a-f0-9]{64}', value[key]) for key in ('serverNonce', 'assurance', 'bindings')) or
            any(not isinstance(value.get(key), str) or not re.fullmatch('[A-Za-z0-9-]{1,100}', value[key]) for key in ('namespaceUID', 'podUID'))):
        raise ValueError('Private probe readiness refused')
    if prior and any(value[key] != prior[other] for key, other in (
            ('assurance', 'remoteAssurance'), ('bindings', 'bindings'), ('namespaceUID', 'namespaceUID'), ('podUID', 'podUID'),
            ('revision', 'revision'), ('digests', 'digests'))):
        raise ValueError('Private probe readiness changed')


def lifetime(tokens, deadline):
    if len(tokens) != 2: raise ValueError('Private probe requires two access tokens')
    for token in tokens:
        if not isinstance(token, str) or len(token) > 8192 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token):
            raise ValueError('Private probe credential shape differs')
        payload = token.split('.')[1]
        expires = decode(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))['exp']
        if type(expires) is not int or expires < deadline + 5 or expires < time.time() + 35:
            raise ValueError('Private probe access token lifetime is insufficient')


def handoff(state, rows, tokens, prior=None, *, browser_deadline=None):
    from playbooks.access.files.preflight import ssh_channel
    deadline = min(time.monotonic() + 50, browser_deadline if browser_deadline is not None else float('inf'))
    if deadline <= time.monotonic(): raise ValueError('Private probe browser budget expired')
    assurance = client_assurance(timeout=min(10, deadline - time.monotonic()))
    if prior and prior['clientAssurance'] != assurance: raise ValueError('Private probe SSH state changed')
    if tokens and prior is None: raise ValueError('Private probe requires prior public preflight')
    wall_deadline = int(time.time() + deadline - time.monotonic())
    request = {'challenge': secrets.token_hex(32), 'nonce': state['nonce'],
               'revision': state['executionPlatform'], 'digests': [contract.digest(contract.canonical(row)) for row in rows], 'deadline': wall_deadline}
    if tokens: lifetime(tokens, wall_deadline)
    with ssh_channel('VM', os.environ['VM_HOST'], REMOTE, deadline=deadline, output_limit=8192) as channel:
        channel.write_frame(contract.canonical(request))
        ready = decode(channel.read_frame())
        readiness(ready, request, prior)
        channel.no_pending()
        ready_digest = contract.digest(contract.canonical(ready))
        if tokens:
            if channel.remaining() < 35: raise ValueError('Private probe browser budget insufficient')
            lifetime(tokens, wall_deadline)
            # Serialization happens only after fresh same-session readiness and lifetime checks.
            channel.write_frame(contract.canonical({'action': 'access', 'challenge': request['challenge'], 'serverNonce': ready['serverNonce'],
                                'readinessDigest': ready_digest, 'tokens': tokens}))
        channel.close_input()
        response = decode(channel.read_frame())
        if (not isinstance(response, dict) or set(response) != {'action', 'challenge', 'serverNonce', 'readinessDigest', 'result'} or
                response['action'] != 'result' or response['challenge'] != request['challenge'] or response['serverNonce'] != ready['serverNonce'] or
                response['readinessDigest'] != ready_digest): raise ValueError('Private probe result refused')
        validate_result(response['result'], 'probe' if tokens else 'preflight')
        channel.finish()
    return {'clientAssurance': assurance, 'remoteAssurance': ready['assurance'], 'bindings': ready['bindings'],
            'namespaceUID': ready['namespaceUID'], 'podUID': ready['podUID'], 'revision': ready['revision'], 'digests': ready['digests'],
            'result': response['result']}
