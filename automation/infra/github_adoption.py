"""Exact designated GitHub inventory; unsupported policy never disappears silently."""
import copy
import fcntl
import json
import os
from pathlib import Path
import sys
import uuid

from playbooks.argocd.files.github_setup import GitHub, repository
from automation.infra.command import SCHEMAS, reject_unknown, validate_inventory, Client, WORK, source_binding, identity, digest
from automation.infra.cloudflare_adoption import write_json, import_document

REPOSITORY_FIELDS = tuple(SCHEMAS['github']['repositories']['*'])
PULL_REQUEST_FIELDS = tuple(SCHEMAS['github']['rulesets']['*']['pull_request'])
# GitHub owns these defaults; this provider cannot represent non-default values.
PROVIDER_DEFAULTS = {
    'require_extra_approval_for_unattributed_changes': True,
    'dismissal_restriction': {'enabled': False, 'allowed_actors': []},
    'required_reviewers': [],
}


def declaration_hash():
    root = Path('/workspace/infra/github')
    return digest(b''.join(path.name.encode() + b'\0' + path.read_bytes()
                           for path in sorted([*root.glob('*.tf'), root / '.terraform.lock.hcl'])))


def ruleset(value, key):
    if value.get('target') != 'branch' or value.get('enforcement') != 'active':
        raise ValueError('Only active existing branch rulesets support this handoff')
    conditions = value.get('conditions') or {}
    if set(conditions) != {'ref_name'} or set(conditions['ref_name']) != {'include', 'exclude'}:
        raise ValueError('Unsupported ruleset scope; adoption refused')
    rules = {rule['type']: rule for rule in value['rules']}
    supported = {'deletion', 'non_fast_forward', 'required_linear_history', 'pull_request', 'required_status_checks'}
    if len(rules) != len(value['rules']) or set(rules) - supported or 'pull_request' not in rules:
        raise ValueError('Unsupported or duplicate rule; current policy remains external')
    parameters = rules['pull_request']['parameters']
    if set(parameters) - set(PULL_REQUEST_FIELDS) - set(PROVIDER_DEFAULTS):
        raise ValueError('Unsupported review requirement; current policy remains external')
    if any(parameters.get(field, expected) != expected for field, expected in PROVIDER_DEFAULTS.items()):
        raise ValueError('Provider cannot preserve non-default review requirements')
    if set(PULL_REQUEST_FIELDS) - set(parameters):
        raise ValueError('Complete existing review requirements required')
    checks = rules.get('required_status_checks', {}).get('parameters', {})
    if set(checks) - {'required_status_checks', 'strict_required_status_checks_policy', 'do_not_enforce_on_create'}:
        raise ValueError('Unsupported status requirement; current policy remains external')
    if checks.get('do_not_enforce_on_create', False):
        raise ValueError('Provider declaration cannot discard status enforcement on creation')
    result = {'repository': key, 'name': value['name'],
              'include': copy.deepcopy(conditions['ref_name']['include']),
              'exclude': copy.deepcopy(conditions['ref_name']['exclude']),
              'bypass_actors': copy.deepcopy(value.get('bypass_actors', [])),
              'pull_request': {field: copy.deepcopy(parameters[field]) for field in PULL_REQUEST_FIELDS},
              'strict_status_checks': checks.get('strict_required_status_checks_policy', False),
              'status_checks': copy.deepcopy(checks.get('required_status_checks', []))}
    result.update({field: field in rules for field in ('deletion', 'non_fast_forward', 'required_linear_history')})
    return result


def declarations(snapshot):
    repositories, rulesets, imports = {}, {}, {}
    owners = set()
    for key, value in snapshot.items():
        current = value['repository']
        full_name = repository('https://github.com/' + current['full_name'] + '.git')
        owners.add(full_name.split('/')[0])
        if (current.get('fork') or current.get('archived') or current.get('visibility') not in ('public', 'private') or
                current.get('private') != (current['visibility'] == 'private') or not current.get('id') or not current.get('node_id')):
            raise ValueError('Existing repository identity and visibility required; recreation refused')
        desired = {field: copy.deepcopy(current[field]) for field in REPOSITORY_FIELDS if field != 'default_branch'}
        desired['default_branch'] = current['default_branch'] if value['branch'] is not None else None
        repositories[key] = desired
        address = 'github_repository.repository[' + json.dumps(key) + ']'
        imports[address] = {'id': current['name'], 'import_id': current['name'],
                            'repo_id': current['id'], 'node_id': current['node_id']}
        if desired['default_branch'] is not None:
            imports['github_branch_default.default[' + json.dumps(key) + ']'] = {
                'id': current['name'], 'import_id': current['name']}
        if current['private'] and value['rulesets']:
            raise ValueError('Private rulesets are outside the supported actual Free plan')
        for index, rule in enumerate(sorted(value['rulesets'], key=lambda rule: rule['id']), 1):
            rule_key = key + '_ruleset_' + str(index)
            rulesets[rule_key] = ruleset(rule, key)
            imports['github_repository_ruleset.ruleset[' + json.dumps(rule_key) + ']'] = {
                'id': str(rule['id']), 'import_id': current['name'] + ':' + str(rule['id'])}
    if len(owners) != 1 or not repositories:
        raise ValueError('Only designated existing repositories in one organization may be adopted')
    desired = {'owner': owners.pop(), 'repositories': repositories, 'rulesets': rulesets}
    reject_unknown(desired, SCHEMAS['github'])
    validate_inventory('github', desired, inventory(imports))
    return desired, imports


def inventory(imports):
    return {address: {key: value for key, value in resource.items() if key != 'import_id'}
            for address, resource in imports.items()}


def capture(api, targets):
    result = {}
    for key, full_name, visibility in targets:
        current = api.request('GET', 'repos/' + full_name)
        if current.get('full_name', '').lower() != full_name.lower() or current.get('visibility') != visibility:
            raise ValueError('Designated repository scope changed; maintenance required')
        rules = []
        if visibility == 'public':
            rows = api.request('GET', 'repos/' + full_name + '/rulesets?includes_parents=false&per_page=100')
            if len(rows) == 100:
                raise ValueError('Ruleset inventory exceeds supported bounded scope')
            rules = [api.request('GET', 'repos/' + full_name + '/rulesets/' + str(row['id'])) for row in rows]
        result[key] = {'repository': current, 'rulesets': rules,
                      'branch': api.request('GET', 'repos/' + full_name + '/branches/' + current['default_branch'], missing=True)}
    return result


def observe(desired, expected, token):
    targets = [(key, desired['owner'] + '/' + value['name'], value['visibility'])
               for key, value in desired['repositories'].items()]
    _, imports = declarations(capture(GitHub(token), targets))
    if inventory(imports) != expected:
        raise ValueError('Current repository scope or identities differ from private inventory; review maintenance')


def preserved(checkpoint, token, *, history=True):
    desired = checkpoint['desired']
    targets = [(key, desired['owner'] + '/' + value['name'], value['visibility'])
               for key, value in desired['repositories'].items()]
    current = capture(GitHub(token), targets)
    observed, imports = declarations(current)
    if observed != desired or imports != checkpoint['imports'] or (history and any(
            (current[key]['branch'] or {}).get('commit', {}).get('sha') !=
            (checkpoint['snapshot'][key]['branch'] or {}).get('commit', {}).get('sha') for key in current)):
        raise ValueError('Existing repository fields or history changed; keep ownership suspended and review privately')
    return {key: (value['branch'] or {}).get('commit', {}).get('sha') for key, value in current.items()}


def prepare(destination):
    from playbooks.secrets.files.vault import fields
    from playbooks.argocd.files import github_setup
    if (hasattr(github_setup, 'provision') and
            getattr(github_setup, 'REPOSITORY_CREATION_SUSPENDED', False) is not True):
        raise ValueError('Legacy repository creation must be suspended by reviewed source before native import')
    if (destination / 'handoff.json').exists():
        raise ValueError('Existing handoff must be resumed; preparation cannot replace it')
    baseline = json.loads((destination / 'inventory-api.json').read_text())
    if set(baseline) != {'public_platform', 'private_config', 'public_fixture', 'private_fixture'}:
        raise ValueError('All four designated repository roles must be inventoried privately')
    token = os.environ['GITHUB_TOKEN']
    targets = [(key, value['repository']['full_name'], value['repository']['visibility']) for key, value in baseline.items()]
    snapshot = capture(GitHub(token), targets)
    if any(snapshot[key]['repository']['id'] != baseline[key]['repository']['id'] for key in baseline):
        raise ValueError('Designated repository identity changed; adoption refused')
    desired, imports = declarations(snapshot)
    backend = fields('gitlab-state-github', ('PROJECT_ID', 'USERNAME', 'TOKEN'))
    encryption = fields('opentofu-state-github', ('PASSPHRASE',))
    binding = source_binding('github')
    documents = {'desired.tfvars.json': desired, 'backend.json': {'project_id': backend['PROJECT_ID']},
                 'encryption.json': {'passphrase': encryption['PASSPHRASE']}, 'inventory.json': inventory(imports),
                 'acceptance.json': {'root': 'github', 'status': 'prepared'}}
    for name, document in documents.items():
        write_json(destination / name, document)
    values = {'GITHUB_TOKEN': token, 'TF_HTTP_USERNAME': backend['USERNAME'], 'TF_HTTP_PASSWORD': backend['TOKEN']}
    if any('\n' in value or '\r' in value for value in values.values()):
        raise ValueError('Credential contains unsupported newline')
    (destination / 'credentials.env').write_text(''.join(key + '=' + value + '\n' for key, value in values.items()))
    write_json(destination / 'handoff.json', {'phase': 'prepared', 'binding': binding, 'desired': desired,
               'snapshot': snapshot, 'imports': imports, 'operation': uuid.uuid4().hex,
               'private_inputs': {name: digest((destination / name).read_bytes()) for name in (
                   'desired.tfvars.json', 'backend.json', 'credentials.env', 'encryption.json', 'inventory.json')}})
    print(json.dumps({'github_prepared': True, 'resources': len(imports), 'remote_mutations': 0}))


def require(result, allowed=(0,)):
    if result.returncode not in allowed:
        raise RuntimeError('Native GitHub maintenance failed; protected diagnostics and recovery retained')
    return result


def plan(client, name):
    result = require(client.native('plan', '-input=false', '-detailed-exitcode', '-lock-timeout=0s',
                                  '-var-file=desired.tfvars.json', '-out=' + name), (0, 2))
    return result.returncode, json.loads(require(client.native('show', '-json', name)).stdout)


def reviewed_import(client, checkpoint):
    _, document = plan(client, 'imports.tfplan')
    resources = {resource['address']: resource for resource in document.get('resource_changes', [])}
    if set(resources) != set(checkpoint['imports']) or any(
            resource['change']['actions'] != ['no-op'] or identity(resource, resource['change']['after']) !=
            inventory(checkpoint['imports'])[address] for address, resource in resources.items()):
        raise ValueError('Import proposes remote changes or identity replacement; ownership remains suspended')
    (client.path / 'import-review.txt').write_bytes(require(client.native('show', 'imports.tfplan')).stdout)


def status(client, destination, phase):
    document = {'root': 'github', 'status': phase}
    write_json(destination / 'acceptance.json', document)
    client.binding['inputs']['acceptance.json'] = digest(json.dumps(document, sort_keys=True).encode())
    client.unchanged_inputs()


def bound_client(checkpoint):
    client = Client('github', maintenance=True)
    names = {'desired.tfvars.json', 'backend.json', 'credentials.env', 'encryption.json', 'inventory.json'}
    if (set(checkpoint.get('private_inputs', {})) != names or
            any(client.binding['inputs'].get(name) != checksum for name, checksum in checkpoint['private_inputs'].items()) or
            client.desired != checkpoint['desired'] or client.inventory != inventory(checkpoint['imports'])):
        raise ValueError('Prepared backend, credentials, recovery key or inventory changed; maintenance refused')
    return client


def advance(destination):
    checkpoint = json.loads((destination / 'handoff.json').read_text())
    if checkpoint['binding'] != source_binding('github') or checkpoint['phase'] not in ('prepared', 'importing', 'imported'):
        raise ValueError('Resume handoff from its exact committed source and recorded phase')
    qualification = json.loads((WORK / 'github/qualification-result.json').read_text())
    gates = ('native_import', 'native_update', 'repeat_plan_empty', 'identities_policy_history_preserved',
             'disposable_drift_detected_repaired', 'provider_success_failed_upload_recovery',
             'concurrent_apply_rejected', 'public_private_clone_access', 'free_pr_enforcement', 'fixtures_removed')
    if (qualification.get('source_hash') != checkpoint['binding']['source_hash'] or
            qualification.get('declaration_hash') != declaration_hash() or
            any(qualification.get(gate) is not True for gate in gates)):
        raise ValueError('Exact native GitHub qualification and actual Free-plan behavior required before handoff')
    client = bound_client(checkpoint)
    preserved(checkpoint, client.env['GITHUB_TOKEN'])
    client.initialize()
    if checkpoint['phase'] != 'imported':
        write_json(client.path / 'imports.tf.json', import_document(checkpoint['imports']))
        reviewed_import(client, checkpoint)
        checkpoint['phase'] = 'importing'
        status(client, destination, 'importing')
        write_json(destination / 'handoff.json', checkpoint)
        client.unchanged_inputs()
        require(client.native('apply', '-input=false', '-lock-timeout=0s', 'imports.tfplan'))
        (client.path / 'imports.tf.json').unlink()
        checkpoint['phase'] = 'imported'
        status(client, destination, 'imported')
        write_json(destination / 'handoff.json', checkpoint)
    if plan(client, 'accepted-repeat.tfplan')[0] != 0:
        raise ValueError('Production GitHub repeat plan is not empty; keep both writers suspended')
    preserved(checkpoint, client.env['GITHUB_TOKEN'])
    status(client, destination, 'accepted')
    checkpoint['phase'] = 'accepted'
    write_json(destination / 'handoff.json', checkpoint)
    print(json.dumps({'github_ownership_accepted': True, 'repeat_plan_empty': True,
                      'identities_policy_history_preserved': True, 'free_pr_and_clone_checks_passed': True}))


def reverse(destination):
    from automation.infra.retention import ciphertext
    checkpoint = json.loads((destination / 'handoff.json').read_text())
    if checkpoint['phase'] not in ('accepted', 'imported', 'importing', 'reversing'):
        raise ValueError('Reverse requires recorded native ownership; ordinary lifecycle is forbidden')
    client = bound_client(checkpoint)
    history = preserved(checkpoint, client.env['GITHUB_TOKEN'], history=False)
    status(client, destination, 'reversing')
    checkpoint['phase'] = 'reversing'
    write_json(destination / 'handoff.json', checkpoint)
    client.initialize()
    (client.path / ('reverse-' + uuid.uuid4().hex + '.encrypted')).write_bytes(ciphertext(client.env))
    state = json.loads(require(client.native('state', 'pull')).stdout)
    addresses = []
    for resource in state.get('resources', []):
        for instance in resource.get('instances', []):
            address = resource['type'] + '.' + resource['name']
            if 'index_key' in instance:
                address += '[' + json.dumps(instance['index_key']) + ']'
            if address not in client.inventory or identity(resource, instance['attributes']) != client.inventory[address]:
                raise ValueError('Unexpected state identity; reverse ownership removal refused')
            addresses.append(address)
    if addresses:
        client.unchanged_inputs()
        require(client.native('state', 'rm', '-lock-timeout=0s', *addresses))
    if json.loads(require(client.native('state', 'pull')).stdout).get('resources'):
        raise ValueError('State ownership removal incomplete; keep legacy writer suspended')
    if preserved(checkpoint, client.env['GITHUB_TOKEN'], history=False) != history:
        raise ValueError('Repository history advanced during reverse; keep legacy writer suspended')
    checkpoint['phase'] = 'reversed'
    write_json(destination / 'handoff.json', checkpoint)
    print(json.dumps({'github_state_ownership_removed': True, 'remote_mutations': 0,
                      'legacy_writer_still_suspended': True, 'resume_legacy_requires_reviewed_source_change': True}))


def main():
    os.umask(0o077)
    if len(sys.argv) != 3 or sys.argv[1] not in ('prepare', 'advance', 'reverse'):
        raise ValueError('Use prepare, advance or reverse with an explicit writable private input directory')
    WORK.mkdir(parents=True, mode=0o700, exist_ok=True)
    with (WORK / 'github.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        {'prepare': prepare, 'advance': advance, 'reverse': reverse}[sys.argv[1]](Path(sys.argv[2]))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, (ValueError, RuntimeError)) else
                         'GitHub maintenance failed; protected recovery retained') from None
