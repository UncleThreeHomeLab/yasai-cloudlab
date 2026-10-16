"""Daemon-free OCI client with temporary, project-scoped registry credentials."""
from contextlib import contextmanager
from pathlib import Path
import re
import subprocess
import tempfile

from automation.harbor.transport import hostname
from automation.harbor.api_policy import POLICY


class Registry:
    def __init__(self, host, environment, diagnostics):
        self.host = hostname(host)
        self.environment = {key: environment[key] for key in ('PATH', 'HOME', 'HTTPS_PROXY', 'NO_PROXY') if key in environment}
        self.diagnostics = diagnostics

    def command(self, *arguments, input_data=None, denied=False, missing=False):
        result = subprocess.run(['crane', '--platform=linux/amd64', *arguments], env=self.environment,
                                input=input_data, capture_output=True, timeout=600)
        if missing and result.returncode and re.search(rb'MANIFEST_UNKNOWN|NAME_UNKNOWN', result.stderr):
            return None
        if denied:
            if not result.returncode or not re.search(rb'UNAUTHORIZED|DENIED|status code (?:401|403)', result.stderr):
                raise RuntimeError('Registry access denial was not proven')
        elif result.returncode:
            with self.diagnostics.open('ab') as stream:
                stream.write(result.stdout + result.stderr)
            raise RuntimeError('OCI operation failed; protected diagnostics retained')
        return result.stdout

    @contextmanager
    def identity(self, credential=None):
        with tempfile.TemporaryDirectory(prefix='harbor-oci-auth-') as temporary:
            self.environment['DOCKER_CONFIG'] = temporary
            try:
                if credential is not None:
                    self.command('auth', 'login', self.host, '--username', credential['username'],
                                 '--password-stdin', input_data=credential['password'].encode())
                    config = Path(temporary) / 'config.json'
                    config.chmod(0o600)
                yield self
            finally:
                self.environment.pop('DOCKER_CONFIG', None)

    def reference(self, project, digest=None):
        if project not in POLICY['projects']:
            raise ValueError('OCI proof escaped its designated projects')
        if digest is not None and not re.fullmatch(r'sha256:[a-f0-9]{64}', digest):
            raise ValueError('OCI proof requires an exact SHA-256 image digest')
        return self.host + '/' + project + '/bootstrap' + ('@' + digest if digest else ':deploy-bootstrap')

    def digest(self, reference, missing=False):
        output = self.command('digest', reference, missing=missing)
        if output is None:
            return None
        value = output.decode().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
            raise RuntimeError('Registry returned an invalid artifact digest')
        return value
