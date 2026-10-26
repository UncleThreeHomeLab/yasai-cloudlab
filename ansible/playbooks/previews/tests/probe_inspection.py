"""Fixed read-only SSH protocol; authorize one access frame only after fresh readiness."""
import json
from pathlib import Path
import re
import resource
import secrets
import signal
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, '/opt/cloudlab')
from playbooks.previews.files import contract
from playbooks.previews.tests import probe_state
from playbooks.tailscale.files.ssh_channel import Frames, PipeChannel


def decode(raw):
    def unique(pairs):
        value = dict(pairs)
        if len(value) != len(pairs): probe_state.refused()
        return value
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise ValueError('Private probe frame refused') from None


def validate(request):
    if (not isinstance(request, dict) or set(request) != {'challenge', 'nonce', 'revision', 'digests', 'deadline'} or
            not re.fullmatch('[a-f0-9]{64}', request.get('challenge', '')) or
            not re.fullmatch('[a-f0-9]{32}', request.get('nonce', '')) or
            not re.fullmatch('[a-f0-9]{40}', request.get('revision', '')) or
            not isinstance(request['digests'], list) or len(request['digests']) != 2 or len(set(request['digests'])) != 2 or
            any(not isinstance(value, str) or not re.fullmatch('[a-f0-9]{64}', value) for value in request['digests']) or
            type(request['deadline']) is not int or not time.time() < request['deadline'] <= time.time() + 60):
        probe_state.refused()


def execute(frame, namespace, deadline):
    process = subprocess.Popen(['/usr/local/bin/k3s', 'kubectl', '--kubeconfig=/etc/rancher/k3s/k3s.yaml', '--request-timeout=45s',
        'exec', '-i', '-n', namespace, 'probe', '--', 'python', '-B', '/fixture/probe_program.py'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0, start_new_session=True,
        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
    with PipeChannel(process, deadline, output_limit=4096) as channel:
        channel.write_frame(contract.canonical(frame))
        channel.close_input()
        response = decode(channel.read_frame())
        channel.finish()
    validate_result(response, frame['phase'])
    return response


def validate_result(response, phase):
    if phase == 'preflight':
        if response != {'preflight': True}: probe_state.refused()
        return
    if not isinstance(response, dict) or set(response) != {'targets'} or not isinstance(response['targets'], list) or len(response['targets']) != 2:
        probe_state.refused()
    for value in response['targets']:
        if (not isinstance(value, dict) or set(value) != {'control', 'gateway', 'podProtected', 'serviceProtected', 'serviceMode'} or
                any(value.get(key) is not True for key in ('control', 'gateway', 'podProtected', 'serviceProtected')) or
                value.get('serviceMode') not in ('waypoint', 'blocked')): probe_state.refused()


def context(request):
    state = probe_state.receipt(request['nonce'])
    rows = state.get('probeRows')
    if state.get('revision') != request['revision'] or not isinstance(rows, list) or len(rows) != 2:
        probe_state.refused()
    for row in rows: contract.approval(row)
    if [contract.digest(contract.canonical(row)) for row in rows] != request['digests']:
        probe_state.refused()
    probe = probe_state.bound_probe(state)
    declarations, snapshot = probe_state.targets(rows, request['revision'])
    code = probe['ConfigMap'].get('data', {})
    if set(code) != {'probe_program.py', 'traffic.py'} or probe['ConfigMap'].get('binaryData'): probe_state.refused()
    if code['probe_program.py'] != Path(__file__).with_name('probe_program.py').read_text(): probe_state.refused()
    if code['traffic.py'] != Path(__file__).parents[2].joinpath('access/files/traffic.py').read_text(): probe_state.refused()
    binding = {'targets': snapshot, 'code': contract.digest(contract.canonical(code)),
               'probeUIDs': {kind: value['metadata']['uid'] for kind, value in probe.items()}}
    return probe, declarations, contract.digest(contract.canonical(binding))


def frame(request, probe, declarations, phase, tokens):
    return {'phase': phase, 'control': {'host': 'control', 'address': probe['Service']['spec']['clusterIP'], 'path': '/', 'tls': False,
            'expected': {'synthetic': 'probe-control'}}, 'targets': declarations, 'tokens': tokens, 'deadline': request['deadline']}


def run(channel):
    request = decode(channel.read_frame())
    validate(request)
    channel.deadline = min(channel.deadline, time.monotonic() + request['deadline'] - time.time())
    signal.setitimer(signal.ITIMER_REAL, channel.remaining())
    assurance = probe_state.assurance()
    probe, declarations, binding = context(request)
    execute(frame(request, probe, declarations, 'preflight', []), probe['Namespace']['metadata']['name'], channel.deadline)
    _, _, after = context(request)
    if binding != after or probe_state.assurance() != assurance: probe_state.refused()
    channel.no_pending()
    ready = {'action': 'ready', 'challenge': request['challenge'], 'serverNonce': secrets.token_hex(32),
             'revision': request['revision'], 'digests': request['digests'], 'assurance': assurance, 'bindings': binding,
             'namespaceUID': probe['Namespace']['metadata']['uid'], 'podUID': probe['Pod']['metadata']['uid']}
    channel.write_frame(contract.canonical(ready))
    ready_digest = contract.digest(contract.canonical(ready))
    raw = channel.read_frame(allow_eof=True)
    if raw is None:
        channel.require_eof()
        output = {'preflight': True}
    else:
        access = decode(raw)
        if (not isinstance(access, dict) or set(access) != {'action', 'challenge', 'serverNonce', 'readinessDigest', 'tokens'} or
                access['action'] != 'access' or access['challenge'] != request['challenge'] or access['serverNonce'] != ready['serverNonce'] or
                access['readinessDigest'] != ready_digest or not isinstance(access['tokens'], list) or len(access['tokens']) != 2 or
                any(not isinstance(token, str) or len(token) > 8192 or not re.fullmatch(
                    r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', token) for token in access['tokens'])):
            probe_state.refused()
        channel.require_eof()
        current_probe, current_declarations, current_binding = context(request)
        if binding != current_binding or probe_state.assurance() != assurance: probe_state.refused()
        output = execute(frame(request, current_probe, current_declarations, 'probe', access['tokens']),
                         current_probe['Namespace']['metadata']['name'], channel.deadline)
        _, _, after = context(request)
        if binding != after or probe_state.assurance() != assurance: probe_state.refused()
    channel.remaining()
    channel.write_frame(contract.canonical({'action': 'result', 'challenge': request['challenge'], 'serverNonce': ready['serverNonce'],
                         'readinessDigest': ready_digest, 'result': output}))


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    def expired(*args): probe_state.refused()
    signal.signal(signal.SIGALRM, expired)
    deadline = time.monotonic() + 60
    signal.setitimer(signal.ITIMER_REAL, 60)
    channel = Frames(sys.stdin.buffer, sys.stdout.buffer, deadline)
    try:
        run(channel)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        channel.close()


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit(1) from None
