"""Non-secret GitOps inputs derived from the qualified tools and designated repository."""
import argparse
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


def application_configuration(qualified, application, current, workflows=()):
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
    if workflows:
        values = json.loads((POOL / 'values.json').read_text())
        values['arc'].update(githubConfigUrl=current['html_url'],
                             githubConfigSecret='github-arc-public' if scope == 'public' else 'github-arc',
                             runnerScaleSetName='cloudlab-' + name,
                             controllerServiceAccount={'namespace': 'cloudlab-ci-system', 'name': controller})
        pod = values['arc']['template']['spec']
        pod['containers'][0]['image'] = references['runner']
        pod['initContainers'][0]['image'] = references['builder']
        values['eligibility'] = list(workflows)
        if any(row.get('repository') != full_name or row.get('repository_id') != str(current['id']) for row in workflows):
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
    parser.add_argument('--output', type=Path, default=harbor_api.WORK / 'ci/configuration.json')
    arguments = parser.parse_args()
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
    if arguments.workflow_revision is not None:
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
        if arguments.workflow_revision:
            raise ValueError('Application runner eligibility needs a separately reviewed exact policy')
        documents = application_configuration(qualified, application, fixture)
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
