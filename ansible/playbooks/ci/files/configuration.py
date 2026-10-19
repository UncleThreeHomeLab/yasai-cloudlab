"""Non-secret GitOps inputs derived from the qualified tools and designated repository."""
import argparse
import json
import os
from pathlib import Path
import re

import yaml

from playbooks.argocd.files.github_setup import MARKER, inputs, inspect, repository
from playbooks.ci.files.qualification import images, profile_fingerprint
from playbooks.harbor.files.recovery import atomic
from playbooks.infrastructure.files import harbor as harbor_api


def configuration(qualified, fixture, workflow_revision=None):
    references = images({'revision': qualified['image_revision'], 'images': qualified['images']})
    if (qualified.get('nodes_verified') != 2 or qualified.get('max_build_pods') != 1 or
            qualified.get('workload_api_writes_denied') is not True or
            qualified.get('github_or_signing_credentials_provisioned') is not False or
            qualified.get('health_access_loss_shutdown_bound_seconds') != 90 or
            not re.fullmatch(r'[a-f0-9]{40}', qualified.get('revision', '')) or
            qualified.get('profile_sha256') != profile_fingerprint()):
        raise ValueError('CI registration requires the complete native two-node qualification')
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
    parser.add_argument('--output', type=Path, default=harbor_api.WORK / 'ci/configuration.json')
    arguments = parser.parse_args()
    os.umask(0o077)
    revision = harbor_api.binding()
    values, api = inputs()
    name = repository(values.get('PRIVATE_TEST_REPOSITORY'))
    fixture = inspect(api, 'private-fixture', name, True)
    if fixture is None:
        raise ValueError('The designated private repository must exist before registration')
    if arguments.workflow_revision is not None:
        current = api.request('GET', 'repos/' + name + '/git/ref/heads/main')['object']['sha']
        if current != arguments.workflow_revision or not api.request('GET', 'repos/' + name +
                '/contents/.github/workflows/publish.yaml?ref=' + current, missing=True):
            raise ValueError('Approve the actual main workflow revision before registering the pool')
    qualified = json.loads((harbor_api.WORK / 'ci/qualified.json').read_text())
    desired = configuration(qualified, fixture, arguments.workflow_revision)
    source = yaml.safe_load((harbor_api.ROOT / 'gitops/roots/public/values.yaml').read_text())
    environment = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    if not all(harbor_api.reviewed_ancestor(source['repository'], qualified[key], revision, environment)
               for key in ('revision', 'image_revision')):
        raise ValueError('CI tools and qualification must originate from reviewed ancestors')
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
