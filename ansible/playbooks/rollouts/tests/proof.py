"""Existing-VM measured canaries through the accepted GitOps and ambient owners."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import time

from dotenv import dotenv_values

from playbooks.rollouts.files.check import check, ROOT, CHART
from playbooks.rollouts.tests.fixtures import objects

CHECKPOINT = Path('/recovery/rollouts-proof.json')
RECEIPT = Path('/recovery/rollouts-result.json')


def environment():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    for prefix in ('VM', 'VM2'):
        for suffix in ('HOST', 'USER', 'PASSWORD'):
            key = prefix + '_' + suffix
            if not values.get(key):
                raise ValueError('Missing VM input: ' + key)
            os.environ[key] = values[key]
        os.environ[prefix + '_PORT'] = values.get(prefix + '_PORT') or '22'
        os.environ[prefix + '_BECOME_PASSWORD'] = values.get(prefix + '_BECOME_PASSWORD') or values[prefix + '_PASSWORD']
        os.environ[prefix + '_PUBLIC_IP'] = socket.gethostbyname(values[prefix + '_HOST'])


def remote(nonce, action, **request):
    from playbooks.access.files.preflight import ssh
    source = (ROOT / 'ansible/playbooks/rollouts/files/remote.py').read_text()
    code = "import sys;sys.path.insert(0,'/opt/cloudlab');\n" + source
    try:
        return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(code),
                             input=json.dumps(dict(request, nonce=nonce, action=action)), timeout=240,
                             diagnostics='/recovery/rollouts-remote-error.log'))
    except RuntimeError:
        raise RuntimeError('Progressive delivery operation failed: ' + action + '; private diagnostics retained in recovery volume') from None


def wait_for(nonce, predicate, label, timeout=420):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = remote(nonce, 'snapshot')
        if predicate(state):
            return state
        time.sleep(5)
    raise RuntimeError('Progressive delivery timed out: ' + label)


@contextlib.contextmanager
def tunnel(gateway):
    # Use the established SSH host key and password path; TLS still verifies the canonical gateway host.
    command = ['sshpass', '-e', 'ssh', '-N', '-p', os.environ['VM_PORT'],
               '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/state/known_hosts',
               '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=10',
               '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
               '-L', '127.0.0.1:8443:' + gateway + ':443', os.environ['VM_USER'] + '@' + os.environ['VM_HOST']]
    process = subprocess.Popen(command, env=dict(os.environ, SSHPASS=os.environ['VM_PASSWORD']),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            if process.poll() is not None:
                raise RuntimeError('Fixture SSH transport failed')
            try:
                with socket.create_connection(('127.0.0.1', 8443), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            raise RuntimeError('Fixture SSH transport timed out')
        yield
    finally:
        process.terminate()
        process.wait(timeout=15)


def traffic(host, stable, canary):
    version = subprocess.check_output(['k6', 'version'], text=True, timeout=10)
    if not version.startswith('k6 v2.3.0 '):
        raise RuntimeError('Measured releases require the pinned k6 runner')
    return subprocess.Popen(['k6', 'run', '--quiet', '--log-output=none', '--no-usage-report',
                             str(Path(__file__).with_name('traffic.k6.js'))],
                            env={'PATH': os.environ['PATH'], 'NO_PROXY': '*',
                                 'RELEASE_ORIGIN': 'https://' + host + ':8443',
                                 'STABLE_REVISION': stable, 'CANARY_REVISION': canary},
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def traffic_result(process):
    stdout, _stderr = process.communicate(timeout=220)
    try:
        document = json.loads(stdout.strip())
    except ValueError:
        error = RuntimeError('Bounded traffic summary unavailable')
        error.evidence = {'exit_code': process.returncode}
        raise error from None
    total = document['stable_samples'] + document['canary_samples']
    if (process.returncode or document['unknown_revision'] or document['dropped_iterations'] or total < 680 or
            not 0.35 <= document['canary_samples'] / total <= 0.65):
        error = RuntimeError('Bounded traffic thresholds or observed 50/50 split failed')
        error.evidence = dict(document, exit_code=process.returncode)
        raise error
    return document


def restore(nonce):
    sequence = json.loads(CHECKPOINT.read_text()).get('known_sequence', 'baseline')
    remote(nonce, 'release', environment={'RELEASE_MODE': 'healthy', 'RELEASE_SEQUENCE': sequence})
    return wait_for(nonce, lambda s: s['phase'] == 'Healthy' and s['stable'] == s['current'] and
                    s['weights'] == [100, 0] and s['mode'] == 'healthy' and s['sequence'] == sequence and s['observed'],
                    'known-good release restored')


def prove(*, converge=True):
    check()
    environment()
    from playbooks.argocd.files.render import committed_payload
    source = committed_payload()
    pin = json.loads((CHART / 'artifact.lock.json').read_text())
    nonce = json.loads(CHECKPOINT.read_text())['nonce'] if CHECKPOINT.exists() else secrets.token_hex(16)
    CHECKPOINT.write_text(json.dumps({'nonce': nonce}))
    CHECKPOINT.chmod(0o600)
    image = next(name + '@' + digest for name, digest in pin['images'].items())
    # Apply only the accepted Argo bootstrap entry point; no host, recovery or application CI scenarios.
    applies = []
    for _ in range(2 if converge else 0):
        stats = {}
        for component in ('argocd/010-bootstrap', 'services/010-bootstrap', 'observability/020-converge'):
            subprocess.run(['ansible-playbook', '-i', 'inventory.yml', 'playbooks/' + component + '.yml'],
                           cwd=ROOT / 'ansible', check=True, timeout=600)
            stats[component] = json.loads(Path('/tmp/lab-stats.json').read_text())
        applies.append(stats)
    if applies and any(row['changed'] or row.get('failures') or row.get('unreachable')
           for component in applies[1].values() for row in component.values()):
        raise RuntimeError('Scoped repeat apply did not converge without changes')
    deadline = time.monotonic() + 600
    while True:
        prerequisites = remote(nonce, 'prerequisites', revision=source['revision'], controller_image=image,
                               plugin_sha256=pin['plugin']['sha256'])
        if prerequisites.get('ready') is not False:
            break
        if time.monotonic() >= deadline:
            raise RuntimeError('Pinned Git-owned Rollouts application is not ready')
        time.sleep(10)
    result = {'revision': source['revision'], 'setup_repeated': converge, 'scoped_applies': applies,
              'runs': [], 'restored': False, 'fixture_removed': False}
    prepared = False
    try:
        if remote(nonce, 'snapshot')['current']:
            restore(nonce)
            remote(nonce, 'cleanup')
        CHECKPOINT.write_text(json.dumps({'nonce': nonce, 'known_sequence': 'baseline'}))
        prepared = True
        remote(nonce, 'prepare', objects=objects(source['repository'], source['revision'], prerequisites['host'], prerequisites['artifact']))
        wait_for(nonce, lambda s: s['phase'] == 'Healthy' and s['stable'] == s['current'] and s['sync'] == 'Synced', 'fixture baseline')
        with tunnel(prerequisites['gateway']):
            for mode in ('healthy', 'faulty', 'missing', 'low-samples', 'query-failure'):
                started = time.monotonic()
                previous = remote(nonce, 'snapshot')['stable']
                remote(nonce, 'release', environment={'RELEASE_MODE': 'healthy' if mode == 'query-failure' else mode,
                                                     'RELEASE_SEQUENCE': mode})
                state = wait_for(nonce, lambda s: s['current'] != previous and s['weights'] == [50, 50], 'weighted ' + mode)
                process = traffic(prerequisites['host'], previous, state['current'])
                injected = False
                observations = []
                decision_seconds = None
                try:
                    traffic_started = time.monotonic()
                    while process.poll() is None:
                        state = remote(nonce, 'snapshot')
                        elapsed = time.monotonic() - traffic_started
                        if decision_seconds is None and (state['abort'] or (state['phase'] == 'Healthy' and state['current'] == state['stable'])):
                            decision_seconds = round(time.monotonic() - started, 3)
                        if mode == 'query-failure' and not injected and state['analysis']:
                            injected = remote(nonce, 'query-failure')['injected']
                        if elapsed <= 120:
                            if state['weights'] != [50, 50] or state['abort']:
                                raise RuntimeError('Argo or analysis changed the split before the accepted evaluation duration')
                            observations.append({'seconds': round(elapsed, 1), 'weights': state['weights'], 'sync': state['sync']})
                        if 55 <= elapsed <= 75:
                            remote(nonce, 'refresh')
                        if elapsed > 215:
                            raise RuntimeError('Bounded traffic process exceeded deadline')
                        time.sleep(5)
                    try:
                        measured = traffic_result(process)
                    except RuntimeError as error:
                        result['pending_case'] = {'case': mode, 'traffic': getattr(error, 'evidence', {}),
                                                  'state': state, 'weight_observations': observations}
                        RECEIPT.write_text(json.dumps(result, indent=2))
                        raise
                finally:
                    if process.poll() is None:
                        process.terminate()
                        process.communicate(timeout=15)
                state = wait_for(nonce, lambda s: s['abort'] or (s['phase'] == 'Healthy' and
                                 s['current'] == s['stable'] and s['weights'] == [100, 0]),
                                 'analysis decision and traffic convergence', timeout=120)
                result['pending_case'] = {'case': mode, 'traffic': measured, 'state': state,
                                          'decision_seconds': decision_seconds, 'weight_observations': observations}
                RECEIPT.write_text(json.dumps(result, indent=2))
                if mode == 'healthy':
                    if state['phase'] != 'Healthy' or state['current'] != state['stable'] or state['weights'] != [100, 0]:
                        raise RuntimeError('Healthy revision did not promote')
                    CHECKPOINT.write_text(json.dumps({'nonce': nonce, 'known_sequence': 'healthy'}))
                else:
                    if (not state['abort'] or state['stable'] != previous or state['weights'] != [100, 0] or
                            state['analysis_phase'] not in ('Failed', 'Error')):
                        raise RuntimeError('Unsafe release did not abort and restore stable traffic')
                    if mode == 'query-failure' and (not injected or not any(m['phase'] == 'Error' for m in state['metrics'])):
                        raise RuntimeError('Query failure did not fail closed')
                    remote(nonce, 'rollback-requests', host=prerequisites['host'], stable=previous)
                if not any(o['seconds'] >= 65 and o['sync'] == 'Synced' for o in observations):
                    raise RuntimeError('Argo reconciliation was not observed during delegated traffic weights')
                receipt = {'case': mode, 'elapsed_seconds': round(time.monotonic() - started, 3),
                           'decision_seconds': decision_seconds,
                           'traffic': measured, 'analysis': state['metrics'], 'analysis_phase': state['analysis_phase'],
                           'weight_observations': observations, 'new_stable_requests': 0 if mode == 'healthy' else 30}
                result['runs'].append(receipt)
                result.pop('pending_case', None)
                RECEIPT.write_text(json.dumps(result, indent=2))
                print(json.dumps({'case': mode, 'elapsed_seconds': receipt['elapsed_seconds'],
                                  'traffic': measured, 'analysis': state['metrics']}), flush=True)
                if mode != 'healthy':
                    restore(nonce)
        final = remote(nonce, 'prerequisites', revision=source['revision'], controller_image=image,
                       plugin_sha256=pin['plugin']['sha256'])
        if final['retained'] != prerequisites['retained']:
            raise RuntimeError('Accepted Notes resources or images changed during release proof')
    finally:
        try:
            if prepared:
                if remote(nonce, 'snapshot')['current']:
                    restore(nonce)
                    result['restored'] = True
                result['fixture_removed'] = remote(nonce, 'cleanup')['fixture_removed']
        finally:
            RECEIPT.write_text(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'prove', 'verify', 'cleanup'))
    action = parser.parse_args().action
    if action != 'check':
        import fcntl
        lock = Path('/recovery/rollouts-proof.lock').open('a')
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another measured release operation holds the fixture lock') from None
    if action == 'check':
        result = check()
    elif action == 'cleanup':
        environment()
        nonce = json.loads(CHECKPOINT.read_text())['nonce']
        if remote(nonce, 'snapshot')['current']:
            restore(nonce)
        result = remote(nonce, 'cleanup')
    else:
        result = prove(converge=action == 'prove')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Progressive delivery proof incomplete; private diagnostics withheld', flush=True)
        raise SystemExit(1) from None
