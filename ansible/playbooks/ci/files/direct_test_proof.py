"""Qualify direct offline execution using disposable tracked source and no job secrets."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time


PROGRAM = '''set -eu
test "$(id -u)" -eq 0
test "${GITHUB_TOKEN+x}" != x
for path in /app/.git /app/.env /run/cloudlab-test/registry/config.json \\
  /var/run/cloudlab-health/token /run/cloudlab-publisher/github/private_key; do
 test ! -e "$path"
done
test "$(head -n 1 /app/proof.sh)" = 'set -eu'
if (printf 'unexpected write' >> /app/proof.sh) 2>/dev/null; then exit 1; fi
command -v nc >/dev/null
network_status=0
nc -z -w 1 1.1.1.1 443 || network_status=$?
test "$network_status" -eq 1
directory=$(mktemp -d)
chmod 0755 "$directory"
printf initial > "$directory/ownership"
chown 1000:1000 "$directory/ownership"
su -s /bin/sh user -c 'set -eu; test "$(id -u)" -eq 1000; test "$(id -g)" -eq 1000; test "$(id -G)" = 1000; printf "mapped user" > "$1"' proof "$directory/ownership"
test "$(cat "$directory/ownership")" = 'mapped user'
test "$(stat -c %u:%g "$directory/ownership")" = 1000:1000
rm "$directory/ownership"
rmdir "$directory"
case "$1" in
 fail) printf 'EXPECTED_TEST_FAILURE\\n'; exit 17 ;;
 cancel)
  sleep 120 &
  child=$!
  printf 'DIRECT_TEST_CHILD_STARTED\\n'
  wait "$child"
  ;;
esac
test ! -e /tmp/previous-test-run
printf 'fresh execution' > /tmp/previous-test-run
printf 'CLOUDLAB_DIRECT_TEST_OK\\n'
'''


def require_released_sandbox():
    # Pinned BuildKit UsageInfo serializes its boolean field as "inUse".
    for _ in range(10):
        records = json.loads(subprocess.check_output(
            ['buildctl', '--addr', 'tcp://127.0.0.1:1234', 'du', '--format', '{{json .}}'],
            text=True, timeout=10))
        # The native API returns null for an empty slice, otherwise an array of records.
        if records is None:
            records = []
        if not isinstance(records, list) or any(
                not isinstance(record, dict) or type(record.get('inUse')) is not bool for record in records):
            raise RuntimeError('Direct test cleanup returned invalid sandbox state')
        if not any(record['inUse'] for record in records):
            return
        time.sleep(1)
    raise RuntimeError('Direct test execution retained active sandbox state')


def captured_result(result):
    def bounded(value):
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')
        return (value or '')[-16384:]
    return {'rc': getattr(result, 'returncode', None),
            'timeout': isinstance(result, subprocess.TimeoutExpired),
            'stdout': bounded(result.stdout), 'stderr': bounded(result.stderr)}


def failed_execution(result):
    # Only the qualification owner invokes this proof; Ansible retains stderr with no_log and mode 0600.
    details = {'execution': captured_result(result)}
    command = ['buildctl', '--addr', 'tcp://127.0.0.1:1234', 'debug']
    try:
        history = subprocess.run(command + ['histories', '--format', '{{json .}}'],
                                 capture_output=True, text=True, timeout=10)
        details['history'] = captured_result(history)
        refs = []
        for line in history.stdout.splitlines()[-32:]:
            event = json.loads(line)
            record = event.get('record', {}) if isinstance(event, dict) else {}
            ref = record.get('Ref') if isinstance(record, dict) else None
            if isinstance(ref, str) and re.fullmatch('[a-z0-9]{25}', ref) and ref not in refs:
                refs.append(ref)
        details['progress'] = []
        for ref in refs[:2]:
            try:
                progress = subprocess.run(command + ['logs', '--progress', 'plain', ref],
                                          capture_output=True, text=True, timeout=10)
                details['progress'].append(captured_result(progress))
            except (OSError, subprocess.TimeoutExpired) as error:
                details['progress'].append({'unavailable': type(error).__name__})
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        details['history_unavailable'] = type(error).__name__
    return RuntimeError('Direct offline test did not execute successfully: ' + json.dumps(details))


def main():
    expected = json.loads(Path('/proof/test-meta.json').read_text())
    version = subprocess.check_output(['cloudlab-test', '--version'], text=True, timeout=10).strip()
    if version != expected['source_sha256']:
        raise RuntimeError('Published executor source differs from qualification')
    lock = json.loads(Path('/usr/share/doc/cloudlab-ci/runner.lock.json').read_text())
    if any(lock['overlays'].get(name) != value for name, value in expected['gate_overlays'].items()):
        raise RuntimeError('Published workflow gate differs from qualification')
    with tempfile.TemporaryDirectory(prefix='ci-direct-proof-') as directory:
        source = Path(directory)
        (source / 'proof.sh').write_text(PROGRAM)
        (source / '.env').write_text('SYNTHETIC_UNTRACKED_SECRET=never_forward\n')
        for arguments in (['init', '-q'], ['add', 'proof.sh']):
            subprocess.run(['git', *arguments], cwd=source, check=True, capture_output=True)
        command = ['cloudlab-test', '--source', str(source),
                   '--timeout', '4m', '--', 'sh', '/app/proof.sh']
        environment = dict(os.environ, GITHUB_TOKEN='SYNTHETIC_MUST_NOT_ENTER_TEST')
        for _ in range(2):
            try:
                result = subprocess.run(command + ['pass'], env=environment, capture_output=True, text=True, timeout=260)
            except subprocess.TimeoutExpired as error:
                raise failed_execution(error) from None
            if result.returncode != 0 or result.stdout.strip() != 'CLOUDLAB_DIRECT_TEST_OK':
                raise failed_execution(result)
        result = subprocess.run(command + ['fail'], env=environment, capture_output=True, text=True, timeout=40)
        if result.returncode == 0 or 'EXPECTED_TEST_FAILURE' not in result.stdout:
            raise RuntimeError('Failed test did not fail the executor')
        deadline_command = list(command)
        deadline_command[deadline_command.index('4m')] = '5s'
        result = subprocess.run(deadline_command + ['cancel'], env=environment,
                                capture_output=True, text=True, timeout=20)
        if result.returncode == 0 or 'DIRECT_TEST_CHILD_STARTED' not in result.stdout:
            raise RuntimeError('Test deadline did not stop the running child')
        process = subprocess.Popen(command + ['cancel'], env=environment, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                if not selector.select(timeout=40) or process.stdout.readline().strip() != 'DIRECT_TEST_CHILD_STARTED':
                    raise RuntimeError('Cancellation fixture did not start its child')
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            if process.wait(timeout=15) == 0 or time.monotonic() - started > 15:
                raise RuntimeError('Cancellation did not stop test execution within its bound')
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            process.stdout.close()
        # Active refs retain the sandbox filesystem while any execution is still alive.
        require_released_sandbox()
    print('CLOUDLAB_DIRECT_TEST_QUALIFIED')


if __name__ == '__main__':
    main()
