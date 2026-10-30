"""Qualify direct offline execution using disposable tracked source and no job secrets."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tempfile
import time


PROGRAM = '''import errno, os, socket, subprocess, sys, tempfile, time
from pathlib import Path
assert os.getuid() == 0
assert 'GITHUB_TOKEN' not in os.environ
for path in ['/app/.git', '/app/.env', '/run/cloudlab-test/registry/config.json',
             '/var/run/cloudlab-health/token', '/run/cloudlab-publisher/github/private_key']:
 assert not Path(path).exists(), 'runner state entered sandbox'
assert Path('/app/proof.py').read_text().startswith('import errno')
try:
 with open('/app/proof.py', 'a') as output: output.write('unexpected write')
except OSError as error:
 assert error.errno in (errno.EROFS, errno.EACCES, errno.EPERM)
else: raise AssertionError('source is writable')
connection = socket.socket()
connection.settimeout(0.5)
try: connection.connect(('1.1.1.1', 443))
except OSError: pass
else: raise AssertionError('offline container reached the network')
finally: connection.close()
with tempfile.TemporaryDirectory() as directory:
 os.chmod(directory, 0o755)
 path = Path(directory) / 'ownership'
 path.write_text('initial')
 os.chown(path, 1001, 1001)
 child = os.fork()
 if child == 0:
  os.setgroups([]); os.setgid(1001); os.setuid(1001)
  path.write_text('mapped user')
  os._exit(0)
 _, status = os.waitpid(child, 0)
 assert status == 0 and path.read_text() == 'mapped user'
 assert path.stat().st_uid == 1001
if sys.argv[1] == 'fail':
 print('EXPECTED_TEST_FAILURE', flush=True)
 raise SystemExit(17)
if sys.argv[1] == 'cancel':
 subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])
 print('DIRECT_TEST_CHILD_STARTED', flush=True)
 time.sleep(120)
assert not Path('/tmp/previous-test-run').exists()
Path('/tmp/previous-test-run').write_text('fresh execution')
print('CLOUDLAB_DIRECT_TEST_OK', flush=True)
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
        (source / 'proof.py').write_text(PROGRAM)
        (source / '.env').write_text('SYNTHETIC_UNTRACKED_SECRET=never_forward\n')
        for arguments in (['init', '-q'], ['add', 'proof.py']):
            subprocess.run(['git', *arguments], cwd=source, check=True, capture_output=True)
        command = ['cloudlab-test', '--source', str(source),
                   '--timeout', '4m', '--', 'python3', '/app/proof.py']
        environment = dict(os.environ, GITHUB_TOKEN='SYNTHETIC_MUST_NOT_ENTER_TEST')
        for _ in range(2):
            result = subprocess.run(command + ['pass'], env=environment, capture_output=True, text=True, timeout=260)
            if result.returncode != 0 or result.stdout.strip() != 'CLOUDLAB_DIRECT_TEST_OK':
                raise RuntimeError('Direct offline test did not execute successfully')
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
