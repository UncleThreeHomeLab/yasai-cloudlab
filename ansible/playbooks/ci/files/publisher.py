"""Publish a scanned application digest and propose its bounded GitOps release."""
import base64
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import time

_spec = importlib.util.spec_from_file_location('cloudlab_release', Path(__file__).with_name('release.py'))
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)
SECRETS = Path('/run/cloudlab-publisher')
SHA = r'[a-f0-9]{40}'
DIGEST = r'sha256:[a-f0-9]{64}'
REPOSITORY = r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+'


class NativeFailure(RuntimeError):
    """Only fixed native command names may reach public workflow logs."""


class PublicationFailure(ValueError):
    """Fixed boundary failures contain no service addresses or credential values."""


def publication_configuration(document):
    fields = {'application', 'source_repository', 'source_repository_id', 'visibility', 'registry',
              'project', 'release_repository', 'release_repository_id', 'workflow_identity'}
    if (set(document) != fields or document['visibility'] not in ('public', 'private') or
            not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', document['application']) or
            not re.fullmatch(REPOSITORY, document['source_repository']) or
            not re.fullmatch(REPOSITORY, document['release_repository']) or
            document['release_repository'].split('/')[0].lower() != document['source_repository'].split('/')[0].lower() or
            not re.fullmatch(r'[1-9][0-9]{0,19}', document['source_repository_id']) or
            type(document['release_repository_id']) is not int or document['release_repository_id'] <= 0 or
            not re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,252}', document['registry']) or
            document['project'] != 'cloudlab-' + document['visibility'] or
            not re.fullmatch(r'https://github[.]com/' + REPOSITORY +
                r'/\.github/workflows/application-publish\.yaml@' + SHA, document['workflow_identity'])):
        raise PublicationFailure('Publication requires matching application, project, workflow and GitOps boundaries')
    return document


def configuration(document, environment):
    publication_configuration(document)
    if (environment.get('RUNNER_ENVIRONMENT') != 'self-hosted' or
            environment.get('GITHUB_REPOSITORY') != document['source_repository'] or
            environment.get('GITHUB_REPOSITORY_ID') != document['source_repository_id'] or
            environment.get('GITHUB_REF') != 'refs/heads/main' or
            environment.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch') or
            not re.fullmatch(SHA, environment.get('GITHUB_SHA', '')) or
            any(not re.fullmatch(r'[1-9][0-9]{0,19}', environment.get(key, ''))
                for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))):
        raise PublicationFailure('Publication requires its approved local main workflow and repository boundaries')
    return document


def execute(arguments, environment, *, data=b'', missing=False, timeout=900):
    # Keep native tool output out of public logs and bound responses used as metadata.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(arguments, env=environment, input=data, stdout=output, stderr=errors,
                                timeout=timeout, check=False)
        output.seek(0)
        errors.seek(0)
        response, diagnostic = output.read(1048577), errors.read(1048577)
    if result.returncode:
        denied = re.search(rb'UNAUTHORIZED|DENIED|status code (?:401|403)', diagnostic)
        if missing and not denied and (re.search(rb'\b(MANIFEST_UNKNOWN|NAME_UNKNOWN)\b', diagnostic) or
                isinstance(missing, bytes) and re.search(missing, diagnostic)):
            return None
        operation = ' '.join(arguments[:2])
        raise NativeFailure('Native ' + operation + ' failed; private output withheld')
    if len(response) > 1048576:
        raise PublicationFailure('Native publication response exceeds its bound')
    return response


def credential(name):
    return (SECRETS / name).read_text().strip()


def registry_environment(directory, registry, project, role, environment):
    path = directory / role
    path.mkdir(mode=0o700)
    username = credential(role + '/username')
    if username != 'robot$' + project + '+' + role or credential(role + '/secret_version') != '1':
        raise PublicationFailure('Registry credential differs from its approved project and retained version')
    auth = base64.b64encode((username + ':' + credential(role + '/password')).encode()).decode()
    (path / 'config.json').write_text(json.dumps({'auths': {registry: {'auth': auth}}}))
    (path / 'config.json').chmod(0o600)
    return dict(environment, DOCKER_CONFIG=str(path))


def build_and_scan(source, directory, environment):
    archive = directory / 'image.tar'
    execute(['buildctl', '--addr', 'tcp://127.0.0.1:1234', 'build', '--frontend', 'dockerfile.v0',
             '--local', 'context=' + str(source), '--local', 'dockerfile=' + str(source),
             '--opt', 'target=runtime', '--opt', 'platform=linux/amd64',
             '--output', 'type=docker,name=application,dest=' + str(archive)], environment, timeout=1200)
    if not archive.is_file() or archive.stat().st_size > 4 * 1024 ** 3:
        raise PublicationFailure('Publication requires an application archive within the 4 GiB build budget')
    print('Application archive built', flush=True)
    digest = execute(['crane', 'digest', '--tarball', str(archive)], environment).decode().strip()
    if not re.fullmatch(DIGEST, digest):
        raise PublicationFailure('Application archive has no immutable image digest')
    scan = json.loads(Path(__file__).resolve().parents[4].joinpath('platform/delivery/ci/scan.lock.json').read_text())
    report = directory / 'scan.json'
    scan_environment = {key: environment[key] for key in ('PATH', 'HOME') if key in environment}
    execute(['trivy', 'image', '--quiet', '--no-progress', '--config', '/dev/null', '--ignorefile', '/dev/null',
             '--ignore-unfixed=false', '--input', str(archive), '--timeout', '15m', '--parallel', '2',
             '--cache-dir', str(directory / 'trivy'), '--db-repository', scan['database'], '--offline-scan',
             '--skip-java-db-update', '--scanners', 'vuln,secret', '--severity', ','.join(scan['severities']),
             '--exit-code', '1', '--format', 'json', '--output', str(report)], scan_environment, timeout=1000)
    document = json.loads(report.read_text())
    if (document.get('SchemaVersion') != 2 or document.get('ArtifactType') != 'container_image' or
            not document.get('Results') or any(row.get('Vulnerabilities') or row.get('Secrets')
                                               for row in document['Results']) or
            execute(['crane', 'digest', '--tarball', str(archive)], environment).decode().strip() != digest):
        raise PublicationFailure('Application requires an unchanged archive and complete clean scan')
    return archive, digest


def sign(reference, document, directory, environment, source, identity):
    if document['visibility'] == 'public':
        signing = dict(environment, **{key: identity[key] for key in
            ('ACTIONS_ID_TOKEN_REQUEST_TOKEN', 'ACTIONS_ID_TOKEN_REQUEST_URL')})
        # The pinned Kyverno bundle verifier omits source certificate extensions.
        # Keep the supported compatibility format until that verifier checks them.
        execute(['cosign', 'sign', '--yes', '--new-bundle-format=false', '--use-signing-config=false',
                 '--sign-container-identity=https://github.com/' + document['source_repository'],
                 reference], signing, timeout=300)
        execute(['cosign', 'verify', '--certificate-identity', document['workflow_identity'],
                 '--certificate-oidc-issuer', 'https://token.actions.githubusercontent.com',
                 '--certificate-github-workflow-repository', document['source_repository'],
                 '--certificate-github-workflow-ref', 'refs/heads/main',
                 '--certificate-github-workflow-sha', source, reference], environment, timeout=300)
    else:
        private, public = SECRETS / 'signer/private_key', SECRETS / 'signer/public_key'
        if execute(['openssl', 'pkey', '-in', str(private), '-pubout'], environment) != public.read_bytes():
            raise PublicationFailure('Private signer differs from its retained public verifier')
        prefix = directory / 'signing'
        signing = dict(environment, COSIGN_PASSWORD=secrets.token_urlsafe(48))
        execute(['cosign', 'import-key-pair', '--key', str(private), '--output-key-prefix', str(prefix)], signing)
        execute(['cosign', 'sign', '--yes', '--new-bundle-format=false',
                 '--use-signing-config=false', '--tlog-upload=false',
                 '--key', str(prefix.with_suffix('.key')), reference], signing, timeout=300)
        execute(['cosign', 'verify', '--insecure-ignore-tlog=true', '--key', str(public), reference],
                environment, timeout=300)


@contextmanager
def release_token(document, environment):
    app_id, installation_id = credential('github/app_id'), credential('github/installation_id')
    if not all(re.fullmatch(r'[1-9][0-9]{0,19}', value) for value in (app_id, installation_id)):
        raise PublicationFailure('Release App identifiers must be numeric')
    def encoded(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
    now = int(time.time())
    message = encoded({'alg': 'RS256', 'typ': 'JWT'}) + b'.' + encoded(
        {'iat': now - 60, 'exp': now + 540, 'iss': app_id})
    signature = execute(['openssl', 'dgst', '-sha256', '-sign', str(SECRETS / 'github/private_key')],
                        environment, data=message)
    jwt = (message + b'.' + base64.urlsafe_b64encode(signature).rstrip(b'=')).decode()
    token = release.api('POST', 'app/installations/' + installation_id + '/access_tokens',
        {'repository_ids': [document['release_repository_id']],
         'permissions': {'contents': 'write', 'pull_requests': 'write'}}, token=jwt)['token']
    try:
        target = release.api('GET', 'repos/' + document['release_repository'], token=token)
        if (target['id'] != document['release_repository_id'] or target['fork'] or target['archived'] or
                target['private'] is not (document['visibility'] == 'private') or
                target['full_name'] != document['release_repository'] or target['default_branch'] != 'main'):
            raise PublicationFailure('Release token is not bound to the approved GitOps repository')
        yield token
    finally:
        release.api('DELETE', 'installation/token', token=token)


def publish(document, source, environment):
    document = configuration(document, environment)
    native_environment = {key: environment[key] for key in ('PATH', 'HOME') if key in environment}
    with tempfile.TemporaryDirectory(prefix='cloudlab-publish-') as temporary:
        directory = Path(temporary)
        pull = registry_environment(directory, document['registry'], document['project'], 'pull', native_environment)
        archive, digest = build_and_scan(source, directory, pull)
        print('Application scan passed', flush=True)
        # App Dockerfiles receive only pull authentication through BuildKit's session.
        push = registry_environment(directory, document['registry'], document['project'], 'push', native_environment)
        repository = document['registry'] + '/' + document['project'] + '/' + document['application']
        tag = repository + ':release-' + '-'.join(environment[key] for key in
            ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
        absent = (rb'(?:GET|HEAD) https://' + re.escape((document['registry'] + '/v2/' +
            document['project'] + '/' + document['application'] + '/manifests/' + tag.rsplit(':', 1)[-1]).encode()) +
            rb':\s*NOT_FOUND\b')
        existing = execute(['crane', 'digest', tag], push, missing=absent)
        if existing is not None and existing.decode().strip() != digest:
            raise PublicationFailure('Existing release tag differs; original artifact preserved')
        if existing is None:
            execute(['crane', 'push', str(archive), tag], push)
        reference = repository + '@' + digest
        if execute(['crane', 'digest', reference], pull).decode().strip() != digest:
            raise PublicationFailure('Published digest is not obtainable through the project pull robot')
        print('Application digest published', flush=True)
        sign(reference, document, directory, push, environment['GITHUB_SHA'], environment)
        print('Application signature verified', flush=True)
        with release_token(document, native_environment) as token:
            original = dict(os.environ)
            os.environ.clear()
            os.environ.update(native_environment, GH_TOKEN=token, GIT_TERMINAL_PROMPT='0',
                              GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_GLOBAL='/dev/null')
            try:
                result = release.propose(document['release_repository'],
                    'apps/releases/' + document['application'] + '.json',
                    {'digest': digest, 'source_revision': environment['GITHUB_SHA'],
                     'workflow_run_id': environment['GITHUB_RUN_ID']})
            finally:
                os.environ.clear()
                os.environ.update(original)
        return dict(result, digest=digest, scanned=True, signed=True)


def main():
    os.umask(0o077)
    document = json.loads((SECRETS / 'config/config.json').read_text())
    print(json.dumps(publish(document, Path('application').resolve(), os.environ), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (NativeFailure, PublicationFailure, release.ReleaseFailure) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        raise SystemExit('Application publication incomplete (' + type(error).__name__ +
                         '); existing artifacts and releases preserved') from None
