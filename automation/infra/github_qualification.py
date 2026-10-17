"""Disposable repository-scoped governance proofs; never rewrite a default branch."""
import base64
import copy
import fcntl
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import uuid

from playbooks.secrets.files.vault import fields
from playbooks.argocd.files.github_setup import GitHub
from playbooks.argocd.files.github_app import app_token, verify_installation, verify_repositories
from automation.infra.backend import environment
from automation.infra.command import WORK, source_binding, identity, guarded_changes, digest
from automation.infra.cloudflare_adoption import write_json, import_document
from automation.infra.cloudflare_qualification import concurrent_apply_probe
from automation.infra.github_adoption import capture, declarations, inventory, ruleset, plan, declaration_hash
from automation.infra.gitlab_qualification import address, request, delete_state
from automation.infra.native import native, require


def bundle():
    return {'token': os.environ['GITHUB_TOKEN'],
            'backend': fields('gitlab-state-github', ('PROJECT_ID', 'USERNAME', 'TOKEN')),
            'encryption': fields('opentofu-state-github', ('PASSPHRASE',))}


def client(directory, values):
    env = environment(values['backend'], address(values['backend'], directory.name), values['encryption']['PASSPHRASE'])
    env['GITHUB_TOKEN'] = values['token']
    return SimpleNamespace(path=directory, env=env, native=lambda *arguments: native(directory, env, *arguments))


def recorded(directory):
    if not re.fullmatch(r'qualification-[a-f0-9]{32}', directory.name) or directory.parent != WORK / 'github':
        raise ValueError('Only recorded disposable GitHub scopes may resume or clean up')
    fixture = json.loads((directory / 'fixture.json').read_text())
    if (fixture['name'] != directory.name or fixture['base'] != directory.name + '-base' or
            fixture['head'] != directory.name + '-head' or fixture['rule_name'] != directory.name):
        raise ValueError('Disposable namespace binding changed; cleanup refused')
    if fixture['phase'] not in ('prepared', 'imported', 'updated', 'recovered', 'drift_repaired',
                                'pr_enforced', 'clones_proven', 'restored', 'cleaned'):
        raise ValueError('Invalid disposable phase; no provider operation')
    return fixture


def target(fixture):
    return fixture['snapshot']['public_platform']['repository']['full_name']


def bound_values(fixture, values):
    if (fixture['backend_project_id'] != values['backend']['PROJECT_ID'] or
            fixture['encryption_hash'] != digest(values['encryption']['PASSPHRASE'].encode()) or
            fixture['credential_hash'] != digest(values['token'].encode())):
        raise ValueError('Recorded backend, recovery key or governance credential changed; no fixture mutation')


def fixture_rule(fixture):
    return {'name': fixture['rule_name'], 'target': 'branch', 'enforcement': 'active', 'bypass_actors': [],
            'conditions': {'ref_name': {'include': ['refs/heads/' + fixture['base']], 'exclude': []}},
            'rules': [{'type': 'pull_request', 'parameters': {
                'allowed_merge_methods': ['squash'], 'dismiss_stale_reviews_on_push': True,
                'require_code_owner_review': False, 'require_last_push_approval': False,
                'required_approving_review_count': 1, 'required_review_thread_resolution': True}},
                {'type': 'required_status_checks', 'parameters': {
                    'strict_required_status_checks_policy': False,
                    'required_status_checks': [{'context': fixture['name']}]}}]}


def create_fixture(directory, values):
    fixture = recorded(directory)
    api = GitHub(values['token'])
    path = 'repos/' + target(fixture)
    for branch in (fixture['base'], fixture['head']):
        current = api.request('GET', path + '/git/ref/heads/' + branch, missing=True)
        if current is None:
            api.request('POST', path + '/git/refs', {'ref': 'refs/heads/' + branch, 'sha': fixture['main_sha']})
        elif current['object']['sha'] not in (fixture['main_sha'], fixture.get('head_sha'), fixture.get('merged_sha')):
            if branch != fixture['head'] or fixture.get('head_sha'):
                raise ValueError('Disposable branch changed outside its owner; no overwrite or cleanup')
            comparison = api.request('GET', path + '/compare/' + fixture['main_sha'] + '...' + current['object']['sha'])
            content = api.request('GET', path + '/contents/' + fixture['name'] + '.txt?ref=' + fixture['head'])
            if (comparison.get('total_commits') != 1 or
                    [(file['filename'], file['status']) for file in comparison.get('files', [])] != [(fixture['name'] + '.txt', 'added')] or
                    base64.b64decode(content['content']) != (fixture['name'] + '\n').encode()):
                raise ValueError('Lost-response fixture differs from exact owned content; recovery refused')
            fixture['head_sha'] = current['object']['sha']
            write_json(directory / 'fixture.json', fixture)
    content_path = path + '/contents/' + fixture['name'] + '.txt'
    current = api.request('GET', content_path + '?ref=' + fixture['head'], missing=True)
    content = (fixture['name'] + '\n').encode()
    if current is None:
        result = api.request('PUT', content_path, {'message': 'Add disposable infrastructure enforcement fixture',
                             'branch': fixture['head'], 'content': base64.b64encode(content).decode()})
        fixture['head_sha'] = result['commit']['sha']
        write_json(directory / 'fixture.json', fixture)
    elif base64.b64decode(current['content']) == content:
        fixture['head_sha'] = api.request('GET', path + '/git/ref/heads/' + fixture['head'])['object']['sha']
        write_json(directory / 'fixture.json', fixture)
    else:
        raise ValueError('Disposable content has a foreign value; overwrite refused')
    matches = [rule for rule in api.request('GET', path + '/rulesets?includes_parents=false&per_page=100')
               if rule['name'] in (fixture['rule_name'], fixture['rule_name'] + '-native')]
    if len(matches) > 1:
        raise ValueError('Duplicate disposable ruleset; explicit recovery required')
    rule = (api.request('GET', path + '/rulesets/' + str(matches[0]['id'])) if matches else
            api.request('POST', path + '/rulesets', fixture_rule(fixture)))
    if (rule['conditions'] != fixture_rule(fixture)['conditions'] or rule.get('bypass_actors')):
        raise ValueError('Disposable ruleset scope changed; no adoption')
    fixture['rule_id'] = rule['id']
    write_json(directory / 'fixture.json', fixture)
    desired, _ = declarations(fixture['snapshot'])
    desired['repositories'] = {key: value for key, value in desired['repositories'].items()
                               if key in ('public_platform', 'public_fixture')}
    for repository in desired['repositories'].values():
        repository['default_branch'] = None
    desired['rulesets'] = {'disposable': ruleset(rule, 'public_platform')}
    imports = {address: value for address, value in declarations(fixture['snapshot'])[1].items()
               if address in ('github_repository.repository["public_platform"]', 'github_repository.repository["public_fixture"]')}
    imports['github_repository_ruleset.ruleset["disposable"]'] = {'id': str(rule['id']),
                                                               'import_id': target(fixture).split('/')[1] + ':' + str(rule['id'])}
    for source in Path('/workspace/infra/github').glob('*'):
        if source.is_file() and (source.suffix == '.tf' or source.name == '.terraform.lock.hcl'):
            shutil.copyfile(source, directory / source.name)
    write_json(directory / 'desired.tfvars.json', desired)
    write_json(directory / 'imports.json', imports)
    write_json(directory / 'imports.tf.json', import_document(imports))
    return fixture, desired, imports


def import_existing(current, imports):
    require(current.native('init', '-input=false', '-lockfile=readonly', '-reconfigure'))
    _, document = plan(current, 'imports.tfplan')
    resources = {resource['address']: resource for resource in document.get('resource_changes', [])}
    if set(resources) != set(imports) or any(
            resource['change']['actions'] != ['no-op'] or identity(resource, resource['change']['after']) !=
            inventory(imports)[address] for address, resource in resources.items()):
        raise ValueError('Disposable import would alter an existing resource; no apply')
    require(current.native('apply', '-input=false', '-lock-timeout=0s', 'imports.tfplan'))
    (current.path / 'imports.tf.json').unlink()
    if plan(current, 'imported-repeat.tfplan')[0] != 0:
        raise ValueError('Disposable native import repeat plan is not empty')


def apply_fixture(current, desired, filename, *, review_change=False):
    write_json(current.path / 'desired.tfvars.json', desired)
    _, document = plan(current, filename)
    if not review_change:
        guarded_changes(document)
    else:
        for resource in document.get('resource_changes', []):
            change = resource['change']
            if (change['actions'] not in (['no-op'], ['update']) or identity(resource, change['before']) != identity(resource, change['after']) or
                    (change['actions'] == ['update'] and resource['address'] != 'github_repository_ruleset.ruleset["disposable"]')):
                raise ValueError('Review enforcement test escaped its disposable ruleset')
    require(current.native('apply', '-input=false', '-lock-timeout=0s', filename))
    fixture = recorded(current.path)
    observed = GitHub(current.env['GITHUB_TOKEN']).request('GET',
        'repos/' + target(fixture) + '/rulesets/' + str(fixture['rule_id']))
    if ruleset(observed, 'public_platform') != desired['rulesets']['disposable']:
        raise ValueError('Native update changed unsupported defaults, review requirements or bypass scope')


def upload_recovery(current, values, desired, imports, fixture):
    recovery = current.path / 'errored.tfstate'
    if fixture.get('upload_started') and recovery.exists():
        recover_upload(current, desired, imports, fixture)
        return
    if recovery.exists():
        if 'encrypted_data' not in json.loads(recovery.read_bytes()):
            raise ValueError('Recovery data is unprotected; retain and inspect privately')
        recovery.replace(current.path / ('errored-' + uuid.uuid4().hex + '.encrypted'))
    url = address(values['backend'], current.path.name)
    class UploadFailure(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            status, data = request(values['backend'], url)
            self.send_response(status)
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.send_response(503)
            self.end_headers()
    server = HTTPServer(('127.0.0.1', 0), UploadFailure)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    faulty = dict(current.env, TF_HTTP_ADDRESS='http://127.0.0.1:' + str(server.server_port) + '/state')
    desired['repositories']['public_fixture']['description'] = fixture['name'] + '-recovered'
    write_json(current.path / 'desired.tfvars.json', desired)
    fixture['upload_started'] = True
    write_json(current.path / 'fixture.json', fixture)
    try:
        require(native(current.path, faulty, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
        failed_client = SimpleNamespace(path=current.path, env=faulty, native=lambda *args: native(current.path, faulty, *args))
        _, document = plan(failed_client, 'failed-upload.tfplan')
        guarded_changes(document)
        failed = native(current.path, faulty, 'apply', '-input=false', '-lock-timeout=0s', 'failed-upload.tfplan')
        observed = GitHub(values['token']).request('GET', 'repos/' + fixture['snapshot']['public_fixture']['repository']['full_name'])
        if (failed.returncode == 0 or not recovery.exists() or 'encrypted_data' not in json.loads(recovery.read_bytes()) or
                observed['id'] != fixture['snapshot']['public_fixture']['repository']['id'] or
                observed['description'] != desired['repositories']['public_fixture']['description']):
            raise ValueError('Provider success and protected failed-upload recovery were not observed')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    recover_upload(current, desired, imports, fixture)


def recover_upload(current, desired, imports, fixture):
    recovery = current.path / 'errored.tfstate'
    observed = GitHub(current.env['GITHUB_TOKEN']).request('GET',
        'repos/' + fixture['snapshot']['public_fixture']['repository']['full_name'])
    if (not recovery.exists() or 'encrypted_data' not in json.loads(recovery.read_bytes()) or
            observed['id'] != fixture['snapshot']['public_fixture']['repository']['id'] or
            observed['description'] != fixture['name'] + '-recovered' or
            desired['repositories']['public_fixture']['description'] != fixture['name'] + '-recovered'):
        raise ValueError('Failed-upload provider identity or recovery input changed; no native state push')
    decrypt = current.path / 'decrypt-recovery'
    decrypt.mkdir(mode=0o700, exist_ok=True)
    protected = decrypt / 'recovery.encrypted'
    shutil.copyfile(recovery, protected)
    versions = (current.path / 'versions.tf').read_text().replace('backend "http" {}',
        'backend "local" { path = ' + json.dumps(str(protected)) + ' }')
    versions = versions.replace('provider "github" { owner = var.owner }', '')
    if 'provider "github"' in versions:
        raise ValueError('Independent recovery cannot depend on a configured governance provider')
    (decrypt / 'versions.tf').write_text(versions)
    shutil.copyfile(current.path / '.terraform.lock.hcl', decrypt / '.terraform.lock.hcl')
    local_env = {key: value for key, value in current.env.items() if not key.startswith('TF_HTTP_') and key != 'GITHUB_TOKEN'}
    require(native(decrypt, local_env, 'init', '-input=false', '-lockfile=readonly'))
    decrypted = require(native(decrypt, local_env, 'state', 'pull')).stdout
    identities = {}
    for resource in json.loads(decrypted)['resources']:
        for instance in resource['instances']:
            address_name = resource['type'] + '.' + resource['name'] + '[' + json.dumps(instance['index_key']) + ']'
            identities[address_name] = identity(resource, instance['attributes'])
    if identities != inventory(imports):
        raise ValueError('Recovered identities differ; native state push refused')
    require(current.native('init', '-input=false', '-lockfile=readonly', '-reconfigure'))
    require(native(current.path, current.env, 'state', 'push', '-', input_data=decrypted))
    if plan(current, 'recovered-repeat.tfplan')[0] != 0:
        raise ValueError('Recovery repeat is not empty; no duplicate creation permitted')


def pr_enforcement(current, values, fixture, desired):
    api = GitHub(values['token'])
    path = 'repos/' + target(fixture)
    existing = api.request('GET', path + '/pulls?state=all&head=' + desired['owner'] + ':' + fixture['head'])
    if len(existing) > 1:
        raise ValueError('Duplicate disposable pull request; cleanup required')
    pull = existing[0] if existing else api.request('POST', path + '/pulls', {
        'head': fixture['head'], 'base': fixture['base'], 'title': 'Disposable infrastructure enforcement fixture',
        'body': 'This tests repository governance on disposable branches. It changes no default branch or workflow.'})
    fixture['pull'] = pull['number']
    write_json(current.path / 'fixture.json', fixture)
    if pull.get('merged_at'):
        pull = api.request('GET', path + '/pulls/' + str(fixture['pull']))
        fixture['merged_sha'] = pull['merge_commit_sha']
        write_json(current.path / 'fixture.json', fixture)
        return
    def status(state):
        api.request('POST', path + '/statuses/' + fixture['head_sha'], {'state': state, 'context': fixture['name'],
                    'description': 'Disposable infrastructure enforcement fixture'})
    def merge(denied):
        deadline = time.monotonic() + 60
        while True:
            state = api.request('GET', path + '/pulls/' + str(pull['number']))
            if state.get('mergeable') is True and state.get('mergeable_state') == ('blocked' if denied else 'clean'):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('Disposable pull request enforcement did not converge within 60 seconds')
            time.sleep(2)
        try:
            result = api.request('PUT', path + '/pulls/' + str(pull['number']) + '/merge',
                                 {'sha': fixture['head_sha'], 'merge_method': 'squash'})
        except RuntimeError as error:
            if denied and str(error).endswith('HTTP 405'):
                return
            raise
        if denied or result.get('merged') is not True:
            raise ValueError('Required review/status enforcement did not block or permit the fixture as expected')
        fixture['merged_sha'] = result['sha']
        write_json(current.path / 'fixture.json', fixture)
    if not fixture.get('review_denied'):
        status('success')
        merge(True)
        fixture['review_denied'] = True
        write_json(current.path / 'fixture.json', fixture)
    desired['rulesets']['disposable']['pull_request']['required_approving_review_count'] = 0
    apply_fixture(current, desired, 'fixture-review-update.tfplan', review_change=True)
    status('pending')
    merge(True)
    status('success')
    merge(False)


def clone_access(values, fixture):
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    api = GitHub(app_token(credentials))
    path = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', path), credentials['APP_ID'])
    token = api.request('POST', path + '/access_tokens', {'permissions': {'contents': 'read'}})['token']
    app = GitHub(token)
    try:
        private = {key: row['repository']['full_name'] for key, row in fixture['snapshot'].items()
                   if row['repository']['private']}
        verify_repositories(app.request('GET', 'installation/repositories?per_page=100'), private)
        with tempfile.TemporaryDirectory(prefix='cloudlab-infra-clone-') as temporary:
            directory = Path(temporary)
            askpass = directory / 'askpass'
            askpass.write_text('#!/bin/sh\ncase "$1" in *Username*) printf x-access-token;; *) printf "%s" "$CLOUDLAB_CLONE_TOKEN";; esac\n')
            askpass.chmod(0o700)
            for key, row in fixture['snapshot'].items():
                env = {name: os.environ[name] for name in ('PATH', 'HOME') if name in os.environ}
                env['GIT_TERMINAL_PROMPT'] = '0'
                if row['repository']['private']:
                    env.update(GIT_ASKPASS=str(askpass), CLOUDLAB_CLONE_TOKEN=token)
                result = subprocess.run(['git', 'clone', '--no-checkout', '--filter=blob:none',
                    'https://github.com/' + row['repository']['full_name'] + '.git', str(directory / key)],
                    env=env, capture_output=True, timeout=180)
                if result.returncode:
                    raise RuntimeError('Retained public/private clone access failed; private diagnostics withheld')
    finally:
        app.request('DELETE', 'installation/token')


def cleanup(directory, values):
    fixture = recorded(directory)
    bound_values(fixture, values)
    api = GitHub(values['token'])
    path = 'repos/' + target(fixture)
    original = fixture['snapshot']['public_fixture']['repository']
    observed_description = api.request('GET', 'repos/' + original['full_name'])['description']
    if observed_description != original['description']:
        if observed_description not in (fixture['name'], fixture['name'] + '-recovered', fixture['name'] + '-drift'):
            raise ValueError('Foreign repository description changed; cleanup cannot overwrite it')
        desired = json.loads((directory / 'desired.tfvars.json').read_text())
        desired['repositories']['public_fixture']['description'] = original['description']
        current = client(directory, values)
        require(current.native('init', '-input=false', '-lockfile=readonly', '-reconfigure'))
        apply_fixture(current, desired, 'cleanup-restore-description.tfplan')
    if fixture.get('rule_id'):
        rule = api.request('GET', path + '/rulesets/' + str(fixture['rule_id']), missing=True)
        if rule is not None:
            if (not rule['name'].startswith(fixture['name']) or rule['conditions'] != fixture_rule(fixture)['conditions'] or
                    rule.get('bypass_actors')):
                raise ValueError('Cleanup would remove a foreign ruleset; refused')
            api.request('DELETE', path + '/rulesets/' + str(fixture['rule_id']))
            if api.request('GET', path + '/rulesets/' + str(fixture['rule_id']), missing=True) is not None:
                raise ValueError('Disposable ruleset removal not observed')
    if fixture.get('pull'):
        pull = api.request('GET', path + '/pulls/' + str(fixture['pull']))
        if pull['head']['ref'] != fixture['head'] or pull['base']['ref'] != fixture['base']:
            raise ValueError('Disposable pull request scope changed; cleanup refused')
        if pull['state'] == 'open':
            api.request('PATCH', path + '/pulls/' + str(fixture['pull']), {'state': 'closed'})
    for branch in (fixture['base'], fixture['head']):
        ref = api.request('GET', path + '/git/ref/heads/' + branch, missing=True)
        if ref is not None:
            if ref['object']['sha'] not in (fixture['main_sha'], fixture.get('head_sha'), fixture.get('merged_sha')):
                raise ValueError('Foreign branch update; cleanup refused')
            api.request('DELETE', path + '/git/refs/heads/' + branch)
            if api.request('GET', path + '/git/ref/heads/' + branch, missing=True) is not None:
                raise ValueError('Disposable branch removal not observed')
    targets = [(key, row['repository']['full_name'], row['repository']['visibility']) for key, row in fixture['snapshot'].items()]
    observed = capture(api, targets)
    if declarations(observed) != declarations(fixture['snapshot']) or any(
            (observed[key]['branch'] or {}).get('commit', {}).get('sha') !=
            (fixture['snapshot'][key]['branch'] or {}).get('commit', {}).get('sha') for key in observed):
        raise ValueError('Existing repository settings, policy or history changed; recovery retained')
    if not delete_state(values['backend'], address(values['backend'], directory.name)):
        raise RuntimeError('Disposable state deletion pending; retry cleanup explicitly')
    fixture['phase'] = 'cleaned'
    write_json(directory / 'fixture.json', fixture)


def exercise(directory, values):
    fixture = recorded(directory)
    bound_values(fixture, values)
    if fixture['phase'] == 'cleaned':
        raise ValueError('Cleaned fixture cannot resume or certify again; start a new disposable qualification')
    if fixture['phase'] == 'prepared':
        fixture, desired, imports = create_fixture(directory, values)
    else:
        desired = json.loads((directory / 'desired.tfvars.json').read_text())
        imports = json.loads((directory / 'imports.json').read_text())
    current = client(directory, values)
    def phase(value):
        fixture['phase'] = value
        write_json(directory / 'fixture.json', fixture)
    if fixture['phase'] == 'prepared':
        import_existing(current, imports)
        phase('imported')
    else:
        require(current.native('init', '-input=false', '-lockfile=readonly', '-reconfigure'))
    api = GitHub(values['token'])
    rule_path = 'repos/' + target(fixture) + '/rulesets/' + str(fixture['rule_id'])
    if fixture['phase'] == 'imported':
        desired['repositories']['public_fixture']['description'] = fixture['name']
        desired['rulesets']['disposable']['name'] = fixture['name'] + '-native'
        apply_fixture(current, desired, 'native-update.tfplan')
        observed_rule = api.request('GET', rule_path)
        if observed_rule['id'] != fixture['rule_id'] or ruleset(observed_rule, 'public_platform') != desired['rulesets']['disposable']:
            raise ValueError('Native ruleset update or platform-default preservation failed')
        phase('updated')
    if fixture['phase'] == 'updated':
        upload_recovery(current, values, desired, imports, fixture)
        phase('recovered')
    fixture_repo = fixture['snapshot']['public_fixture']['repository']['full_name']
    if fixture['phase'] == 'recovered':
        api.request('PATCH', 'repos/' + fixture_repo, {'description': fixture['name'] + '-drift'})
        if plan(current, 'drift.tfplan')[0] != 2:
            raise ValueError('Disposable description drift was not detected')
        apply_fixture(current, desired, 'drift-repair.tfplan')
        phase('drift_repaired')
    if fixture['phase'] == 'drift_repaired':
        pr_enforcement(current, values, fixture, desired)
        phase('pr_enforced')
    if fixture['phase'] == 'pr_enforced':
        clone_access(values, fixture)
        phase('clones_proven')
    if fixture['phase'] == 'clones_proven':
        desired['repositories']['public_fixture']['description'] = fixture['snapshot']['public_fixture']['repository']['description']
        apply_fixture(current, desired, 'restore-description.tfplan')
        phase('restored')
    if plan(current, 'retained-repeat.tfplan')[0] != 0:
        raise ValueError('Restored fixture repeat plan is not empty')
    concurrent_apply_probe(directory, current.env, values)
    result = dict.fromkeys(('native_import', 'native_update', 'repeat_plan_empty', 'identities_policy_history_preserved',
        'disposable_drift_detected_repaired', 'provider_success_failed_upload_recovery', 'concurrent_apply_rejected',
        'public_private_clone_access', 'free_pr_enforcement'), True)
    result['source_hash'] = fixture['binding']['source_hash']
    result['declaration_hash'] = fixture['declaration_hash']
    write_json(directory / 'result.json', result)
    cleanup(directory, values)
    result['fixtures_removed'] = True
    write_json(directory / 'result.json', result)
    write_json(WORK / 'github/qualification-result.json', result)
    print(json.dumps(result))


def run():
    os.umask(0o077)
    values = bundle()
    if sys.argv[1:] == ['qualify']:
        pending = [path for path in (WORK / 'github').glob('qualification-*')
                   if (path / 'fixture.json').exists() and json.loads((path / 'fixture.json').read_text())['phase'] != 'cleaned']
        if pending:
            raise ValueError('Pending disposable fixture requires explicit resume or cleanup; no duplicate creation')
        baseline = json.loads(Path('/inputs/github/inventory-api.json').read_text())
        if set(baseline) != {'public_platform', 'private_config', 'public_fixture', 'private_fixture'}:
            raise ValueError('Complete designated private inventory required before qualification')
        api = GitHub(values['token'])
        targets = [(key, row['repository']['full_name'], row['repository']['visibility']) for key, row in baseline.items()]
        snapshot = capture(api, targets)
        desired, _ = declarations(snapshot)
        if api.request('GET', 'orgs/' + desired['owner']).get('plan', {}).get('name') != 'free':
            raise ValueError('Actual GitHub Free plan evidence required; do not infer available features')
        name = 'qualification-' + uuid.uuid4().hex
        directory = WORK / 'github' / name
        directory.mkdir(parents=True, mode=0o700)
        write_json(directory / 'fixture.json', {'name': name, 'base': name + '-base', 'head': name + '-head',
                   'rule_name': name, 'phase': 'prepared', 'binding': source_binding('github'), 'snapshot': snapshot,
                   'declaration_hash': declaration_hash(), 'backend_project_id': values['backend']['PROJECT_ID'],
                   'encryption_hash': digest(values['encryption']['PASSPHRASE'].encode()),
                   'credential_hash': digest(values['token'].encode()),
                   'main_sha': snapshot['public_platform']['branch']['commit']['sha']})
        print(json.dumps({'protected_qualification': str(directory)}), flush=True)
        exercise(directory, values)
    elif len(sys.argv) == 3 and sys.argv[1] in ('resume', 'cleanup'):
        directory = WORK / 'github' / sys.argv[2]
        fixture = recorded(directory)
        if fixture['declaration_hash'] != declaration_hash():
            raise ValueError('Pinned declarations changed; qualification cannot resume against a different provider contract')
        current_binding = source_binding('github')
        if fixture['binding'] != current_binding:
            fixture['binding'] = current_binding
            write_json(directory / 'fixture.json', fixture)
        if sys.argv[1] == 'cleanup':
            cleanup(directory, values)
            result_path = directory / 'result.json'
            if result_path.exists():
                result = json.loads(result_path.read_text())
                result['fixtures_removed'] = True
                write_json(result_path, result)
                write_json(WORK / 'github/qualification-result.json', result)
            print(json.dumps({'fixtures_removed': True}))
        else:
            exercise(directory, values)
    else:
        raise ValueError('Use qualify, resume qualification-UUID, or cleanup qualification-UUID')


def main():
    WORK.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (WORK / 'github.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        run()


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (RuntimeError, ValueError)) else
                         'GitHub qualification failed; protected recovery retained') from None
