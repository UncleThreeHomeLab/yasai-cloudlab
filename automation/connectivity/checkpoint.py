"""Host-backed access receipts, locked for the entire provider transaction.

The existing server is authoritative. Compose state is only an initial migration
source, so another clean checkout can resume without inventing provider owners.
No credential or browser session belongs in these receipts.
"""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import select
import shlex
import subprocess

SERVER = r'''
import fcntl,json,os,sys
from pathlib import Path
os.umask(0o077)
base=Path('/var/lib/cloudlab/connectivity/receipts')
base.mkdir(mode=0o700,parents=True,exist_ok=True)
with (base/'lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 print('{"ready":true}',flush=True)
 for line in sys.stdin:
  request=json.loads(line)
  name=request['name']
  if name not in ('external','human-proof','acceptance'): raise ValueError('Invalid receipt')
  path=base/(name+'.json')
  if request['action']=='save':
   temporary=path.with_suffix('.tmp')
   with temporary.open('w') as stream:
    json.dump(request['value'],stream,sort_keys=True)
    stream.flush(); os.fsync(stream.fileno())
   temporary.replace(path)
   descriptor=os.open(base,os.O_DIRECTORY)
   try: os.fsync(descriptor)
   finally: os.close(descriptor)
  elif request['action']!='load': raise ValueError('Invalid operation')
  print(json.dumps({'value':json.loads(path.read_text()) if path.exists() else None}),flush=True)
'''


class Receipts:
    def __init__(self, process):
        self.process = process

    def response(self):
        if not select.select([self.process.stdout], [], [], 45)[0]:
            raise RuntimeError('Host receipt transaction timed out; stop provider mutations')
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError('Host receipt transaction unavailable or already locked')
        return json.loads(line)

    def request(self, name, action, **values):
        self.process.stdin.write(json.dumps(dict(name=name, action=action, **values)) + '\n')
        self.process.stdin.flush()
        return self.response()['value']

    def save(self, name, value):
        if self.request(name, 'save', value=value) != value:
            raise RuntimeError('Host receipt failed durable readback')

    def load(self, name):
        value = self.request(name, 'load')
        if value is None:
            # One-time migration of already verified local ownership/evidence.
            local = Path('/state/connectivity') / (name + '.json')
            if local.exists():
                value = json.loads(local.read_text())
                self.save(name, value)
        return value


@contextmanager
def transaction():
    command = ['sshpass', '-e', 'ssh', '-p', os.environ.get('VM_PORT', '22'),
        '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
        '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=/state/known_hosts',
        os.environ['VM_USER'] + '@' + os.environ['VM_HOST'], 'python3 -u -c ' + shlex.quote(SERVER)]
    process = subprocess.Popen(command, env=dict(os.environ, SSHPASS=os.environ['VM_PASSWORD']),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    try:
        receipts = Receipts(process)
        if receipts.response() != {'ready': True}:
            raise RuntimeError('Host receipt lock was not acquired')
        yield receipts
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stdout.close()
