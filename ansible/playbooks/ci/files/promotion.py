"""Human-only promotion of authenticated signed candidates into private GitOps PRs."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

from dotenv import dotenv_values
import yaml

from playbooks.argocd.files.github_setup import configuration as designated_repositories
from playbooks.ci.files import publisher
from playbooks.secrets.files.vault import fields

ROOT = Path(__file__).resolve().parents[4]


def request(token, path):
    return publisher.release.api('GET', path, token=token)


def human(token):
    if (os.environ.get('GITHUB_ACTIONS') or os.environ.get('RUNNER_ENVIRONMENT') or
            not re.fullmatch(r'(?:gho_|ghp_|github_pat_)[A-Za-z0-9_]{8,8000}', token)):
        raise publisher.PublicationFailure('Promotion requires a local human GitHub token supplied through stdin')
    user = request(token, 'user')
    if (user.get('type') != 'User' or not isinstance(user.get('login'), str) or
            user['login'].endswith('[bot]') or type(user.get('id')) is not int or user['id'] <= 0):
        raise publisher.PublicationFailure('Promotion requires an authenticated human GitHub identity')


def provenance(token, pool, source, run, attempt):
    document = pool['values']['publishing']
    prefix = 'repos/' + document['source_repository']
    repository = request(token, prefix)
    if (str(repository.get('id')) != document['source_repository_id'] or repository.get('full_name') != document['source_repository'] or
            repository.get('private') is not (document['visibility'] == 'private') or repository.get('fork') or
            repository.get('archived') or repository.get('disabled') or repository.get('default_branch') != 'main'):
        raise publisher.PublicationFailure('Promotion source differs from its approved repository identity')
    if request(token, prefix + '/branches/main').get('protected') is not True:
        raise publisher.PublicationFailure('Promotion requires protected source main')
    comparison = request(token, prefix + '/compare/' + source + '...main')
    if comparison.get('status') not in ('ahead', 'identical') or comparison.get('base_commit', {}).get('sha') != source:
        raise publisher.PublicationFailure('Promotion source must remain in protected main history')
    current = request(token, prefix + '/actions/runs/' + run + '/attempts/' + attempt)
    if (str(current.get('id')) != run or str(current.get('run_attempt')) != attempt or
            current.get('status') != 'completed' or current.get('conclusion') != 'success' or
            current.get('head_sha') != source or current.get('head_branch') != 'main' or
            current.get('event') not in ('push', 'workflow_dispatch') or current.get('path') != '.github/workflows/ci.yaml' or
            str(current.get('repository', {}).get('id')) != document['source_repository_id'] or
            str(current.get('head_repository', {}).get('id')) != document['source_repository_id']):
        raise publisher.PublicationFailure('Promotion requires the explicit completed successful main run and attempt')
    content = request(token, prefix + '/contents/.github/workflows/ci.yaml?ref=' + source)
    if (content.get('type') != 'file' or content.get('path') != '.github/workflows/ci.yaml' or
            content.get('encoding') != 'base64' or type(content.get('size')) is not int or not 0 < content['size'] <= 65536):
        raise publisher.PublicationFailure('Promotion requires bounded approved workflow content')
    raw = base64.b64decode(''.join(content['content'].split()), validate=True)
    if len(raw) != content['size']:
        raise publisher.PublicationFailure('Promotion workflow content differs from its declared size')
    templates = pool['values'].get('workflowTemplates', [])
    if templates:
        selected = [row for row in templates if row.get('job') == 'publish']
        if (len(selected) != 1 or selected[0].get('repository_id') != document['source_repository_id'] or
                selected[0].get('repository') != document['source_repository'] or
                selected[0].get('visibility') != document['visibility'] or
                selected[0].get('workflow_path') != '.github/workflows/ci.yaml' or
                selected[0].get('workflow_sha256') != hashlib.sha256(raw).hexdigest() or
                'https://github.com/' + selected[0].get('job_workflow_ref', '') != document['workflow_identity']):
            raise publisher.PublicationFailure('Promotion workflow differs from its reviewed publisher policy')
    elif not any(row.get('sha') == source and row.get('workflow_sha') == source and
                 row.get('repository_id') == document['source_repository_id'] and row.get('repository') == document['source_repository'] and
                 row.get('workflow_ref') == document['source_repository'] + '/.github/workflows/ci.yaml@refs/heads/main' and
                 row.get('event_name') == current['event'] and row.get('ref') == 'refs/heads/main' and
                 row.get('job') in ('publish', '__default') for row in pool['values'].get('eligibility', [])):
        raise publisher.PublicationFailure('Promotion requires its exact approved source workflow')
    workflow = yaml.safe_load(raw)
    jobs = workflow.get('jobs', {})
    if 'test' not in jobs or 'publish' not in jobs:
        raise publisher.PublicationFailure('Promotion requires approved test and publish jobs')
    completed = request(token, prefix + '/actions/runs/' + run + '/attempts/' + attempt + '/jobs?per_page=100')
    if completed.get('total_count') != len(completed.get('jobs', [])) or len(completed['jobs']) > 100:
        raise publisher.PublicationFailure('Promotion job evidence must fit one complete bounded response')
    for role in ('test', 'publish'):
        declared = jobs[role]
        name = declared.get('name', role)
        if 'uses' in declared:
            name += ' / ' + role
        matches = [job for job in completed['jobs'] if job.get('name') == name]
        expected = 'cloudlab-' + document['application'] + ('-publish' if role == 'publish' else '')
        if (len(matches) != 1 or matches[0].get('status') != 'completed' or matches[0].get('conclusion') != 'success' or
                str(matches[0].get('run_id')) != run or matches[0].get('head_sha') != source or
                not matches[0].get('runner_name') or expected not in matches[0].get('labels', [])):
            raise publisher.PublicationFailure('Promotion requires successful jobs on the approved local runner roles')


def promote(pool, values, token, digest, source, run, attempt):
    document = publisher.publication_configuration(pool['values']['publishing'])
    if (document.get('release_mode') != 'manual' or document.get('release_visibility') != 'private' or
            not re.fullmatch(publisher.DIGEST, digest) or not re.fullmatch(publisher.SHA, source) or
            any(not re.fullmatch(r'[1-9][0-9]{0,19}', value) for value in (run, attempt))):
        raise publisher.PublicationFailure('Promotion requires manual private inputs and an explicit immutable run tuple')
    targets = [(name, private) for role, name, private in designated_repositories(values) if role == 'private-config']
    if targets != [(document['release_repository'], True)]:
        raise publisher.PublicationFailure('Promotion target must be the designated private GitOps repository')
    human(token)
    target = request(token, 'repos/' + document['release_repository'])
    if (target.get('id') != document['release_repository_id'] or target.get('full_name') != document['release_repository'] or
            target.get('private') is not True or target.get('fork') or target.get('archived') or target.get('disabled') or
            target.get('default_branch') != 'main' or target.get('permissions', {}).get('push') is not True):
        raise publisher.PublicationFailure('Promotion requires human write access to the approved private repository ID')
    provenance(token, pool, source, run, attempt)
    native = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    with tempfile.TemporaryDirectory(prefix='cloudlab-promote-') as temporary:
        directory = Path(temporary)
        original = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN')
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        try:
            credentials = fields('harbor-' + document['project'] + '-pull', ('username', 'password', 'secret_version'))
            public = None
            if document['visibility'] == 'private':
                public = directory / 'cosign.pub'
                public.write_text(fields('ci-private-verifier', ('public_key',))['public_key'])
        finally:
            if original is None: os.environ.pop('OP_SERVICE_ACCOUNT_TOKEN', None)
            else: os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = original
        pull = publisher.registry_environment(directory, document['registry'], document['project'], 'pull', native, credentials)
        repository = document['registry'] + '/' + document['project'] + '/' + document['application']
        reference = repository + '@' + digest
        tag = publisher.candidate_tag(repository, source, run, attempt)
        if publisher.execute(['crane', 'digest', tag], pull).decode().strip() != digest:
            raise publisher.PublicationFailure('Promotion candidate tag differs from the explicit digest')
        publisher.verify_signature(reference, document, pull, source, public)
        desired = publisher.fetch_candidate(reference, document, source, run, attempt, pull)
        for component_digest in desired.get('components', {'': desired['digest']}).values():
            component_reference = repository + '@' + component_digest
            if publisher.execute(['crane', 'digest', component_reference], pull).decode().strip() != component_digest:
                raise publisher.PublicationFailure('Promotion component is unavailable through its authenticated pull robot')
            publisher.verify_signature(component_reference, document, pull, source, public)
        original_environment = dict(os.environ)
        os.environ.clear()
        os.environ.update(native, GH_TOKEN=token, GIT_TERMINAL_PROMPT='0',
                          GIT_CONFIG_SYSTEM='/dev/null', GIT_CONFIG_GLOBAL='/dev/null')
        try:
            return publisher.release.propose(document['release_repository'], 'apps/releases/' + document['application'] + '.json', desired)
        finally:
            os.environ.clear()
            os.environ.update(original_environment)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--publisher-file', type=Path, required=True)
    parser.add_argument('--candidate-digest', required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--workflow-run-id', required=True)
    parser.add_argument('--workflow-run-attempt', required=True)
    arguments = parser.parse_args()
    os.umask(0o077)
    path = arguments.publisher_file
    if any(parent.is_symlink() for parent in (path, *path.parents)) or not path.is_file() or path.stat().st_size > 262144:
        raise publisher.PublicationFailure('Promotion requires a bounded regular private publisher configuration')
    token = sys.stdin.read(8193).strip()
    values = dotenv_values(ROOT / '.env', interpolate=False)
    result = promote(json.loads(path.read_text()), values, token, arguments.candidate_digest,
                     arguments.source_revision, arguments.workflow_run_id, arguments.workflow_run_attempt)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Private release promotion incomplete; existing candidates and GitOps preserved') from None
