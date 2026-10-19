"""Non-secret GitOps inputs derived from the qualified tools and designated repository."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re

import yaml

from playbooks.argocd.files.github_setup import MARKER, inputs, inspect, repository
from playbooks.ci.files.qualification import images, profile_fingerprint
from playbooks.ci.files.chart import POOL
from playbooks.harbor.files.recovery import atomic
from playbooks.infrastructure.files import harbor as harbor_api


def qualified_images(qualified):
    references = images({'revision': qualified['image_revision'], 'images': qualified['images']})
    if (qualified.get('nodes_verified') != 2 or qualified.get('max_build_pods') != 1 or
            qualified.get('workload_api_writes_denied') is not True or
            qualified.get('github_or_signing_credentials_provisioned') is not False or
            qualified.get('health_access_loss_shutdown_bound_seconds') != 90 or
            not re.fullmatch(r'[a-f0-9]{40}', qualified.get('revision', '')) or
            qualified.get('profile_sha256') != profile_fingerprint()):
        raise ValueError('CI registration requires the complete native two-node qualification')
    return references


def application_workflows(api, current, revision, pull_request=None):
    if not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('Application eligibility requires the exact reviewed commit')
    name = current['full_name']
    ref = 'refs/heads/main'
    jobs, events = ('test', 'publish'), ('push', 'workflow_dispatch')
    if pull_request is not None:
        if type(pull_request) is not int or not 0 < pull_request < 2**31:
            raise ValueError('Application eligibility requires a positive pull request number')
        request = api.request('GET', 'repos/' + name + '/pulls/' + str(pull_request))
        if (request.get('state') != 'open' or request.get('mergeable') is not True or
                request.get('merge_commit_sha') != revision or request.get('base', {}).get('ref') != 'main'):
            raise ValueError('Approve the current merge revision of an open mergeable pull request')
        for side in ('head', 'base'):
            origin = request.get(side, {}).get('repo') or {}
            if (origin.get('id') != current['id'] or origin.get('full_name') != name or origin.get('fork') is not False):
                raise ValueError('Fork and foreign pull requests cannot execute on lab runners')
        ref, jobs, events = 'refs/pull/' + str(pull_request) + '/merge', ('test',), ('pull_request',)
    elif api.request('GET', 'repos/' + name + '/git/ref/heads/main')['object']['sha'] != revision:
        raise ValueError('Approve the actual protected main revision')
    workflow = api.request('GET', 'repos/' + name + '/contents/.github/workflows/ci.yaml?ref=' + revision, missing=True)
    if not workflow or workflow.get('type') != 'file':
        raise ValueError('The exact reviewed application CI workflow must exist')
    return [{'repository_id': str(current['id']), 'repository': name,
             'workflow_ref': name + '/.github/workflows/ci.yaml@' + ref,
             'workflow_sha': revision, 'sha': revision, 'ref': ref, 'event_name': event, 'job': job}
            for event in events for job in jobs]


def workflow_bytes(document, path):
    if (document.get('type') != 'file' or document.get('path') != path or
            document.get('encoding') != 'base64' or type(document.get('size')) is not int or
            not 0 < document['size'] <= 65536):
        raise ValueError('Workflow template must be a bounded file at the reviewed revision')
    content = base64.b64decode(''.join(document['content'].split()), validate=True)
    if len(content) != document['size']:
        raise ValueError('Workflow template content differs from its declared size')
    return content


def application_templates(api, current, revision, pull_request=None, *, platform_repository=None):
    """Bind approved caller bytes and each immutable, single-job local reusable workflow."""
    application_workflows(api, current, revision, pull_request)
    prefix = 'repos/' + current['full_name']
    if api.request('GET', prefix + '/branches/main').get('protected') is not True:
        raise ValueError('Workflow templates require protected main')
    content = workflow_bytes(api.request('GET', prefix + '/contents/.github/workflows/ci.yaml?ref=' + revision),
                             '.github/workflows/ci.yaml')
    workflow = yaml.safe_load(content)
    jobs = workflow.get('jobs') if isinstance(workflow, dict) else None
    if not isinstance(jobs, dict) or not jobs or set(jobs) - {'test', 'publish'}:
        raise ValueError('Application CI requires the shared test/publish job interface')
    platform = repository(platform_repository or
                          yaml.safe_load((harbor_api.ROOT / 'gitops/roots/public/values.yaml').read_text())['repository'])
    rows = []
    for role, job in jobs.items():
        path = '.github/workflows/application-' + role + '.yaml'
        reference = job.get('uses') if isinstance(job, dict) else None
        if (not isinstance(reference, str) or not reference.startswith(platform + '/' + path + '@') or
                not re.fullmatch('[a-f0-9]{40}', reference.rsplit('@', 1)[-1])):
            raise ValueError('Application jobs must pin their platform-owned reusable workflow')
        called = yaml.safe_load(workflow_bytes(api.request('GET', 'repos/' + platform + '/contents/' + path +
                               '?ref=' + reference.rsplit('@', 1)[-1]), path))
        called_jobs = called.get('jobs') if isinstance(called, dict) else None
        if not isinstance(called_jobs, dict) or set(called_jobs) != {role}:
            raise ValueError('Each shared workflow must have exactly its one approved role')
        target = called_jobs[role]
        runner = "${{ format('cloudlab-{0}" + ('-publish' if role == 'publish' else '') + "', inputs.application) }}"
        if (not isinstance(target, dict) or target.get('runs-on') != runner or not target.get('steps') or
                any(key in target for key in ('container', 'services', 'snapshot', 'uses'))):
            raise ValueError('Shared workflows require local runners and the qualified process profile')
        rows.append({'repository_id': str(current['id']), 'repository': current['full_name'],
                     'visibility': 'private' if current['private'] else 'public',
                     'workflow_path': '.github/workflows/ci.yaml',
                     'workflow_sha256': hashlib.sha256(content).hexdigest(), 'job': role,
                     'job_workflow_ref': reference})
    return rows


def application_configuration(qualified, application, current, workflows=(), templates=()):
    references = qualified_images(qualified)
    if (set(application) != {'name', 'repository', 'visibility'} or
            not re.fullmatch(r'[a-z][a-z0-9-]{0,34}', application.get('name', '')) or
            application.get('visibility') not in ('public', 'private')):
        raise ValueError('Application registration requires a name, repository and visibility')
    name = application['name']
    full_name = repository(application['repository'])
    scope = application['visibility']
    if (current.get('full_name') != full_name or current.get('html_url') != 'https://github.com/' + full_name or
            current.get('visibility') != scope or current.get('private') is not (scope == 'private') or
            current.get('fork') or current.get('archived') or current.get('disabled') or
            current.get('default_branch') != 'main' or type(current.get('id')) is not int or current['id'] <= 0):
        raise ValueError('Application repository identity or trust boundary differs')
    namespace = 'cloudlab-ci-' + scope + '-' + name
    controller = 'cloudlab-' + name + '-controller'
    image_repository, image_digest = references['controller'].split('@')
    documents = {'controller.json': {'name': name, 'namespace': namespace, 'values': {
        'manageSystemNamespace': False, 'arc': {
            'fullnameOverride': controller, 'serviceAccount': {'name': controller},
            'flags': {'watchSingleNamespace': namespace},
            'image': {'repository': image_repository, 'tag': '0.15.0@' + image_digest}}}}}
    if workflows and templates:
        raise ValueError('Choose exact revisions or reviewed workflow templates')
    if workflows or templates:
        values = json.loads((POOL / 'values.json').read_text())
        values['arc'].update(githubConfigUrl=current['html_url'],
                             githubConfigSecret='github-arc-public' if scope == 'public' else 'github-arc',
                             runnerScaleSetName='cloudlab-' + name,
                             controllerServiceAccount={'namespace': 'cloudlab-ci-system', 'name': controller})
        pod = values['arc']['template']['spec']
        pod['containers'][0]['image'] = references['runner']
        pod['initContainers'][0]['image'] = references['builder']
        values['eligibility'] = list(workflows)
        if templates:
            values['workflowTemplates'] = list(templates)
        if any(row.get('repository') != full_name or row.get('repository_id') != str(current['id']) for row in (*workflows, *templates)):
            raise ValueError('Application eligibility must retain its immutable repository identity')
        documents['runner.json'] = {'name': name, 'namespace': namespace, 'values': values}
    return documents


def configuration(qualified, fixture, workflow_revision=None):
    references = qualified_images(qualified)
    url = fixture['html_url'].rstrip('/') + '.git'
    name = repository(url)
    if (fixture.get('private') is not True or fixture.get('fork') or fixture.get('archived') or
            type(fixture.get('id')) is not int or fixture['id'] <= 0 or
            fixture.get('full_name') != name or fixture.get('default_branch') != 'main' or
            fixture.get('description') != MARKER + 'private-fixture'):
        raise ValueError('Lab runners require the designated private main-branch repository')
    workflows = []
    if workflow_revision is not None:
        if not re.fullmatch(r'[a-f0-9]{40}', workflow_revision):
            raise ValueError('Runner registration requires the exact reviewed workflow revision')
        workflows = [{'repository_id': str(fixture['id']), 'repository': name,
                      'workflow_ref': name + '/.github/workflows/publish.yaml@refs/heads/main',
                      'workflow_sha': workflow_revision, 'sha': workflow_revision, 'ref': 'refs/heads/main',
                      'event_name': event, 'job': 'publish'} for event in ('push', 'workflow_dispatch')]
    return {'images': references, 'arc': {'githubConfigUrl': fixture['html_url']},
            'eligibility': workflows, 'qualification': {
                key: qualified[key] for key in ('revision', 'image_revision', 'profile_sha256', 'nodes_verified')}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workflow-revision')
    parser.add_argument('--application-file', type=Path)
    parser.add_argument('--pull-request', type=int)
    parser.add_argument('--approve-workflow-template', action='store_true')
    parser.add_argument('--output', type=Path, default=harbor_api.WORK / 'ci/configuration.json')
    arguments = parser.parse_args()
    if arguments.pull_request is not None and not (arguments.application_file and arguments.workflow_revision):
        parser.error('--pull-request requires --application-file and --workflow-revision')
    if arguments.approve_workflow_template and not (arguments.application_file and arguments.workflow_revision):
        parser.error('--approve-workflow-template requires --application-file and --workflow-revision')
    os.umask(0o077)
    revision = harbor_api.binding()
    values, api = inputs()
    application = json.loads(arguments.application_file.read_text()) if arguments.application_file else None
    name = repository(application['repository'] if application else values.get('PRIVATE_TEST_REPOSITORY'))
    owner = repository(yaml.safe_load((harbor_api.ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']).split('/')[0]
    if application and name.split('/')[0].lower() != owner.lower():
        raise ValueError('Application registration is restricted to the designated organization')
    fixture = api.request('GET', 'repos/' + name) if application else inspect(api, 'private-fixture', name, True)
    if fixture is None:
        raise ValueError('The designated private repository must exist before registration')
    if arguments.workflow_revision is not None and not application:
        current = api.request('GET', 'repos/' + name + '/git/ref/heads/main')['object']['sha']
        if current != arguments.workflow_revision or not api.request('GET', 'repos/' + name +
                '/contents/.github/workflows/publish.yaml?ref=' + current, missing=True):
            raise ValueError('Approve the actual main workflow revision before registering the pool')
    qualified = json.loads((harbor_api.WORK / 'ci/qualified.json').read_text())
    desired = configuration(qualified, fixture, arguments.workflow_revision) if not application else None
    source = yaml.safe_load((harbor_api.ROOT / 'gitops/roots/public/values.yaml').read_text())
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    if not all(harbor_api.reviewed_ancestor(source['repository'], qualified[key], revision, environment)
               for key in ('revision', 'image_revision')):
        raise ValueError('CI tools and qualification must originate from reviewed ancestors')
    if application:
        templates, workflows = [], []
        if arguments.approve_workflow_template:
            templates = application_templates(api, fixture, arguments.workflow_revision, arguments.pull_request,
                                                platform_repository=source['repository'])
            if any(not harbor_api.reviewed_ancestor(source['repository'], row['job_workflow_ref'].rsplit('@', 1)[-1],
                                                    revision, environment) for row in templates):
                raise ValueError('Shared workflows must originate from reviewed platform history')
        elif arguments.workflow_revision:
            workflows = application_workflows(api, fixture, arguments.workflow_revision, arguments.pull_request)
        documents = application_configuration(qualified, application, fixture, workflows, templates)
        if arguments.output.is_symlink():
            raise ValueError('Application output cannot redirect its protected directory')
        arguments.output.mkdir(mode=0o700, parents=True, exist_ok=True)
        for filename, document in documents.items():
            path = arguments.output / filename
            if path.is_symlink() or path.with_suffix('.tmp').is_symlink():
                raise ValueError('Application output cannot redirect existing files')
            if path.exists() and json.loads(path.read_text()) != document:
                raise ValueError('Preserve existing application inputs; review a new output directory')
            if not path.exists():
                atomic(path, document)
        print(json.dumps({'configuration_generated': True, 'application_documents': len(documents), 'credentials_created': 0}))
        return
    if arguments.output.exists() and json.loads(arguments.output.read_text()) != desired:
        raise ValueError('Preserve existing CI inputs; generate a new file and review its diff')
    if not arguments.output.exists():
        atomic(arguments.output, desired)
    print(json.dumps({'configuration_generated': True, 'approved_workflows': len(desired['eligibility']),
                      'credentials_created': 0}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CI configuration incomplete; existing inputs and credentials preserved') from None
