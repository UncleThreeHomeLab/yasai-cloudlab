"""Prepare exact existing Cloudflare declarations; ownership changes are maintenance."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from dotenv import dotenv_values

from playbooks.infrastructure.files.command import SCHEMAS, reject_unknown, source_binding, identity


APPLICATION_FIELDS = ('name', 'domain', 'session_duration', 'allowed_idps', 'app_launcher_visible',
                      'auto_redirect_to_identity', 'enable_binding_cookie', 'options_preflight_bypass')
POLICY_FIELDS = ('id', 'name', 'decision', 'precedence', 'include', 'exclude', 'require')


def declarations(snapshot, bundle):
    """Preserve all selected policies, and reject any unsupported existing field."""
    account, zone = bundle['management']['ACCOUNT_ID'], bundle['dns']['ZONE_ID']
    tunnel = bundle['tunnel']['TUNNEL_ID']
    if snapshot['tunnel']['id'] != tunnel:
        raise ValueError('Existing tunnel identity differs from designated vault input')
    applications, routes, imports = {}, {}, {}
    for hostname, app in snapshot['applications'].items():
        key = hostname.split('.')[0]
        if key in applications or app.get('type') != 'self_hosted' or not app.get('aud'):
            raise ValueError('Access application needs a unique existing logical key and audience')
        value = {field: copy.deepcopy(app[field]) for field in APPLICATION_FIELDS}
        policies = sorted(app['policies'], key=lambda policy: policy['precedence'])
        if not policies or any(policy.get('reusable') is not False for policy in policies):
            raise ValueError('Selected policies must have certified application-scoped ownership')
        value['policies'] = {}
        for index, policy in enumerate(policies, 1):
            # Keys remain fixed in the private declaration after adoption, independent of mutable policy names.
            value['policies']['policy_' + str(index)] = {field: copy.deepcopy(policy[field]) for field in POLICY_FIELDS}
        applications[key] = value
        imports['cloudflare_zero_trust_access_application.application[' + json.dumps(key) + ']'] = {
            'id': app['id'], 'import_id': 'accounts/' + account + '/' + app['id'], 'aud': app['aud'],
            'policies': {policy['id']: False for policy in policies}}
    ingress = snapshot['configuration']['config']['ingress']
    if not ingress or ingress[-1] != {'service': 'http_status:404'}:
        raise ValueError('Existing tunnel requires its exact terminal deny route')
    for entry in ingress[:-1]:
        hostname = entry['hostname']
        key = hostname.split('.')[0]
        if key in routes or hostname not in snapshot['dns']:
            raise ValueError('Every selected tunnel route requires exactly one owned DNS record')
        record = snapshot['dns'][hostname]
        if (record['type'] != 'CNAME' or record['content'] != tunnel + '.cfargotunnel.com' or
                record['proxied'] is not True or record['ttl'] != 1):
            raise ValueError('Existing DNS scope differs from supported protected tunnel publication')
        routes[key] = {'hostname': hostname, 'service': entry['service'],
                       'application': key if key in applications else None, 'dns_comment': record.get('comment')}
        imports['cloudflare_dns_record.publication[' + json.dumps(key) + ']'] = {
            'id': record['id'], 'import_id': zone + '/' + record['id']}
    if {route['hostname'] for route in routes.values()} != set(snapshot['dns']):
        raise ValueError('Owned DNS inventory includes unrepresented routes')
    imports['cloudflare_zero_trust_tunnel_cloudflared_config.routing'] = {
        'id': tunnel, 'import_id': account + '/' + tunnel}
    desired = {'account_id': account, 'zone_id': zone, 'tunnel_id': tunnel,
               'team_name': snapshot['organization']['auth_domain'].removesuffix('.cloudflareaccess.com'),
               'applications': applications, 'routes': routes}
    reject_unknown(desired, SCHEMAS['cloudflare'])
    return desired, imports


def inventory(imports):
    return {address: {key: value for key, value in resource.items() if key != 'import_id'}
            for address, resource in imports.items()}


def import_document(imports):
    return {'import': [{'to': address, 'id': resource['import_id']} for address, resource in imports.items()]}


def declaration_hash():
    root = Path('/workspace/infra/cloudflare')
    result = hashlib.sha256()
    for path in sorted([*root.glob('*.tf'), root / '.terraform.lock.hcl']):
        result.update(path.name.encode() + b'\0' + path.read_bytes())
    return result.hexdigest()


def require_certification(directory):
    result = json.loads((directory / 'result.json').read_text())
    pin = json.loads(Path('/workspace/ansible/runner/cloudflare-provider.lock.json').read_text())
    if not re.fullmatch(r'[0-9a-f]{64}', pin['package_sha256']):
        raise ValueError('Provider package checksum has not completed review; handoff blocked')
    gates = ('native_import', 'dns_tunnel_application_update', 'legacy_policy_update_supported',
             'repeat_plan_empty', 'identity_audience_selectors_preserved', 'disposable_drift_detected_repaired',
             'provider_success_failed_upload_recovery', 'version_delete_preserves_current',
             'bounded_version_retention',
             'concurrent_apply_rejected',
             'disposable_resources_removed', 'disposable_state_removed')
    if (any(result.get(gate) is not True for gate in gates) or
            result.get('provider_package_sha256') != pin['package_sha256'] or
            result.get('declaration_hash') != declaration_hash()):
        raise ValueError('Exact pinned provider certification must pass before ownership maintenance')


def write_json(path, document):
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as stream:
        json.dump(document, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def prerequisites(state, snapshot):
    if any(state.get(key, {}).get('phase') != 'accepted' for key in ('identity_cutover', 'identity_provider')):
        raise ValueError('Accepted central Access integration required before ownership maintenance')
    from playbooks.keycloak.files.access_cutover import browser_gate
    browser_gate(snapshot['organization']['auth_domain'].removesuffix('.cloudflareaccess.com'), None)


def prepare(destination):
    """Write private inputs through an explicit writable mount; leave both writers unchanged."""
    from playbooks.infrastructure.files.snapshot import credentials, capture
    from playbooks.access.files.cloudflare import API
    from playbooks.access.files.checkpoint import transaction
    root = Path('/recovery/infra/cloudflare')
    fixtures = [path for path in root.glob('qualification-*') if (path / 'result.json').exists()]
    if not fixtures:
        raise ValueError('Completed disposable certification required')
    require_certification(max(fixtures, key=lambda path: path.stat().st_mtime))
    binding = source_binding('cloudflare')
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(destination.iterdir()):
        raise ValueError('Private handoff destination must be empty; resume existing preparation instead')
    bundle = credentials()
    admin, dns = API(bundle['management']['API_TOKEN']), API(bundle['dns']['API_TOKEN'])
    with transaction() as receipts:
        owner = receipts.load('external')
        if not owner or 'infra_owner' in owner or owner.get('phase') != 'configured':
            raise ValueError('Prepare requires the complete current legacy owner; no overlapping identity maintenance')
        snapshot = capture(admin, dns, owner, bundle['management'], bundle['tunnel'])
        prerequisites(owner, snapshot)
    desired, imports = declarations(snapshot, bundle)
    write_json(destination / 'desired.tfvars.json', desired)
    write_json(destination / 'backend.json', {'project_id': bundle['backend']['PROJECT_ID']})
    write_json(destination / 'encryption.json', {'passphrase': bundle['encryption']['PASSPHRASE']})
    write_json(destination / 'inventory.json', inventory(imports))
    write_json(destination / 'acceptance.json', {'root': 'cloudflare', 'status': 'prepared'})
    credential_values = {'TF_HTTP_USERNAME': bundle['backend']['USERNAME'], 'TF_HTTP_PASSWORD': bundle['backend']['TOKEN'],
                         'CLOUDFLARE_API_TOKEN': bundle['management']['API_TOKEN'], 'TF_VAR_dns_api_token': bundle['dns']['API_TOKEN']}
    if any('\n' in value or '\r' in value for value in credential_values.values()):
        raise ValueError('Credential input contains unsupported newlines')
    (destination / 'credentials.env').write_text(''.join(key + '=' + value + '\n' for key, value in credential_values.items()))
    write_json(destination / 'handoff.json', {'phase': 'prepared', 'binding': binding,
               'snapshot': snapshot, 'imports': imports, 'directory': 'handoff-' + uuid.uuid4().hex})
    print(json.dumps({'private_inputs': str(destination), 'prepared': True, 'production_mutations': 0}))


def current_scope(snapshot, bundle, state):
    from playbooks.infrastructure.files.snapshot import capture
    from playbooks.access.files.cloudflare import API
    observed = capture(API(bundle['management']['API_TOKEN']), API(bundle['dns']['API_TOKEN']),
                       snapshot['owner'], bundle['management'], bundle['tunnel'])
    if state.get('binding') != snapshot['owner']['binding']:
        raise ValueError('Legacy declaration binding advanced; ownership maintenance refused')
    if snapshot['owner']['objects'] != {key: state.get('objects', {}).get(key)
                                        for key in snapshot['owner']['objects']}:
        raise ValueError('Legacy object identities advanced; ownership maintenance refused')
    if any(observed[key] != snapshot[key] for key in ('applications', 'dns', 'configuration')):
        raise ValueError('Selected remote fields changed since preparation; keep writers suspended and inspect privately')


def maintained_root(inputs, checkpoint, bundle):
    from playbooks.infrastructure.files.backend import environment
    if not re.fullmatch(r'handoff-[a-f0-9]{32}', checkpoint['directory']):
        raise ValueError('Invalid protected handoff directory')
    directory = Path('/recovery/infra/cloudflare') / checkpoint['directory']
    directory.mkdir(mode=0o700, exist_ok=True)
    for source in Path('/workspace/infra/cloudflare').glob('*'):
        if source.is_file() and (source.suffix == '.tf' or source.name == '.terraform.lock.hcl'):
            shutil.copyfile(source, directory / source.name)
    shutil.copyfile(inputs / 'desired.tfvars.json', directory / 'desired.tfvars.json')
    project = json.loads((inputs / 'backend.json').read_text())['project_id']
    if str(project) != bundle['backend']['PROJECT_ID']:
        raise ValueError('Handoff backend differs from designated vault owner')
    desired = json.loads((inputs / 'desired.tfvars.json').read_text())
    reject_unknown(desired, SCHEMAS['cloudflare'])
    if checkpoint['phase'] in ('prepared', 'suspended', 'imported'):
        approved, approved_imports = declarations(checkpoint['snapshot'], bundle)
        if desired != approved or checkpoint['imports'] != approved_imports:
            raise ValueError('Prepared declarations or import identities changed; refused before live init or plan')
    if json.loads((inputs / 'inventory.json').read_text()) != inventory(checkpoint['imports']):
        raise ValueError('Private identity inventory changed; maintenance refused')
    if json.loads((inputs / 'encryption.json').read_text()) != {'passphrase': bundle['encryption']['PASSPHRASE']}:
        raise ValueError('Private recovery key differs from its independent vault owner')
    wanted_credentials = {'TF_HTTP_USERNAME': bundle['backend']['USERNAME'], 'TF_HTTP_PASSWORD': bundle['backend']['TOKEN'],
                          'CLOUDFLARE_API_TOKEN': bundle['management']['API_TOKEN'],
                          'TF_VAR_dns_api_token': bundle['dns']['API_TOKEN']}
    if dotenv_values(inputs / 'credentials.env', interpolate=False) != wanted_credentials:
        raise ValueError('Private credential inputs differ from their current vault owners')
    url = 'https://gitlab.com/api/v4/projects/' + str(project) + '/terraform/state/managed'
    env = environment(bundle['backend'], url, bundle['encryption']['PASSPHRASE'])
    env.update(CLOUDFLARE_API_TOKEN=bundle['management']['API_TOKEN'], TF_VAR_dns_api_token=bundle['dns']['API_TOKEN'])
    return directory, env


def advance(inputs):
    """Review state-only imports, suspend the old writer, resume import, and check real access."""
    from playbooks.infrastructure.files.snapshot import credentials
    from playbooks.infrastructure.files.native import native, require, document_plan, review_import
    from playbooks.access.files.checkpoint import transaction
    from playbooks.access.files.verify import run as access_verify
    checkpoint_path = inputs / 'handoff.json'
    checkpoint = json.loads(checkpoint_path.read_text())
    if checkpoint['binding'] != source_binding('cloudflare'):
        raise ValueError('Handoff source changed; explicitly review and prepare current declarations again')
    if checkpoint['phase'] not in ('prepared', 'suspended', 'imported'):
        raise ValueError('Handoff phase requires explicit maintenance review')
    bundle = credentials()
    directory, env = maintained_root(inputs, checkpoint, bundle)
    imports = checkpoint['imports']
    expected = inventory(imports)
    with transaction() as receipts:
        state = receipts.load('external')
        prerequisites(state, checkpoint['snapshot'])
        current_scope(checkpoint['snapshot'], bundle, state)
        recorded_owner = state.get('infra_owner')
        if checkpoint['phase'] == 'prepared' and recorded_owner is not None:
            if (not isinstance(recorded_owner, dict) or recorded_owner.get('source') != checkpoint['binding'] or
                    recorded_owner.get('operation') != checkpoint['directory']):
                raise ValueError('Another ownership maintenance operation already holds this scope')
            checkpoint['phase'] = 'suspended'
            write_json(checkpoint_path, checkpoint)
        if checkpoint['phase'] == 'prepared':
            if 'infra_owner' in state:
                raise ValueError('Another ownership maintenance operation already holds this scope')
            write_json(directory / 'imports.tf.json', import_document(imports))
            require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
            _, document = document_plan(directory, env, 'imports.tfplan')
            review_import(document, {address: value['id'] for address, value in imports.items()})
            if {resource['address']: identity(resource, resource['change']['after'])
                    for resource in document['resource_changes']} != expected:
                raise ValueError('Import changes an audience or nested policy identity; no writer suspension')
            state['infra_owner'] = {'phase': 'suspended', 'binding': state['binding'],
                                   'objects': copy.deepcopy(state['objects']), 'source': checkpoint['binding'],
                                   'operation': checkpoint['directory']}
            receipts.save('external', state)
            checkpoint['phase'] = 'suspended'
            write_json(checkpoint_path, checkpoint)
        owner = state.get('infra_owner')
        if (not isinstance(owner, dict) or owner.get('source') != checkpoint['binding'] or
                owner.get('operation') != checkpoint['directory']):
            raise ValueError('Suspended owner differs from this handoff; neither writer may mutate')
        require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
        if checkpoint['phase'] == 'suspended':
            write_json(directory / 'imports.tf.json', import_document(imports))
            require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
            _, document = document_plan(directory, env, 'imports.tfplan')
            review_import(document, {address: value['id'] for address, value in imports.items()})
            if {resource['address']: identity(resource, resource['change']['after'])
                    for resource in document['resource_changes']} != expected:
                raise ValueError('Resumed import differs from preserved identities; recovery retained')
            require(native(directory, env, 'apply', '-input=false', '-lock-timeout=0s', 'imports.tfplan'))
            (directory / 'imports.tf.json').unlink()
            if document_plan(directory, env, 'imported-repeat.tfplan')[0] != 0:
                raise ValueError('Imported production repeat plan is not empty; old writer remains suspended')
            current_scope(checkpoint['snapshot'], bundle, state)
            checkpoint['phase'] = 'imported'
            write_json(checkpoint_path, checkpoint)
    # Access fixtures keep their existing owner; this call performs no selected provider reconciliation.
    access = access_verify(failures=False, reconcile=False)
    write_json(directory / 'access-acceptance.json', access)
    with transaction() as receipts:
        state = receipts.load('external')
        current_scope(checkpoint['snapshot'], bundle, state)
        if (state.get('infra_owner', {}).get('source') != checkpoint['binding'] or
                state['infra_owner'].get('operation') != checkpoint['directory']):
            raise ValueError('Ownership checkpoint advanced during access checks; acceptance refused')
        if document_plan(directory, env, 'accepted-repeat.tfplan')[0] != 0:
            raise ValueError('Final production plan is not empty; old writer remains suspended')
        state['infra_owner']['phase'] = 'accepted'
        receipts.save('external', state)
        write_json(inputs / 'acceptance.json', {'root': 'cloudflare', 'status': 'accepted'})
        checkpoint['phase'] = 'accepted'
        write_json(checkpoint_path, checkpoint)
    print(json.dumps({'cloudflare_ownership_accepted': True, 'repeat_plan_empty': True,
                      'identity_and_credentials_preserved': True, 'existing_access_checks_passed': True}))


def reverse(inputs):
    """Withdraw acceptance and state ownership; source restoration resumes the retired writer."""
    from playbooks.infrastructure.files.snapshot import credentials
    from playbooks.infrastructure.files.native import native, require
    from playbooks.infrastructure.files.retention import ciphertext
    from playbooks.access.files.checkpoint import transaction
    checkpoint_path = inputs / 'handoff.json'
    checkpoint = json.loads(checkpoint_path.read_text())
    if checkpoint['phase'] not in ('accepted', 'imported', 'suspended', 'reversing'):
        raise ValueError('Reverse handoff requires recorded imported or suspended ownership')
    bundle = credentials()
    directory, env = maintained_root(inputs, checkpoint, bundle)
    with transaction() as receipts:
        state = receipts.load('external')
        current_scope(checkpoint['snapshot'], bundle, state)
        owner = state.get('infra_owner')
        if owner is None and checkpoint['phase'] == 'reversing':
            require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
            remaining = json.loads(require(native(directory, env, 'state', 'pull')).stdout)
            if remaining.get('resources'):
                raise ValueError('Reverse checkpoint lost its suspension with native resources remaining')
            checkpoint['phase'] = 'reversed'
            write_json(checkpoint_path, checkpoint)
            return
        if (not isinstance(owner, dict) or owner.get('source') != checkpoint['binding'] or
                owner.get('operation') != checkpoint['directory']):
            raise ValueError('Reverse handoff does not own this suspension')
        write_json(inputs / 'acceptance.json', {'root': 'cloudflare', 'status': 'reversing'})
        owner['phase'] = 'reversing'
        receipts.save('external', state)
        checkpoint['phase'] = 'reversing'
        write_json(checkpoint_path, checkpoint)
        require(native(directory, env, 'init', '-input=false', '-lockfile=readonly', '-reconfigure'))
        (directory / ('reverse-' + uuid.uuid4().hex + '.encrypted')).write_bytes(ciphertext(env))
        pulled = json.loads(require(native(directory, env, 'state', 'pull')).stdout)
        addresses = []
        for resource in pulled.get('resources', []):
            for instance in resource.get('instances', []):
                address = resource['type'] + '.' + resource['name']
                if 'index_key' in instance:
                    address += '[' + json.dumps(instance['index_key']) + ']'
                if address not in checkpoint['imports'] or identity(resource, instance['attributes']) != inventory(checkpoint['imports'])[address]:
                    raise ValueError('Reverse state scope differs; no ownership removal')
                addresses.append(address)
        if addresses:
            require(native(directory, env, 'state', 'rm', '-lock-timeout=0s', *addresses))
        remaining = json.loads(require(native(directory, env, 'state', 'pull')).stdout)
        if remaining.get('resources'):
            raise ValueError('Native ownership removal incomplete; keep legacy writer suspended')
        current_scope(checkpoint['snapshot'], bundle, state)
        state.pop('infra_owner')
        receipts.save('external', state)
        checkpoint['phase'] = 'reversed'
        write_json(checkpoint_path, checkpoint)
    print(json.dumps({'reverse_handoff_complete': True, 'remote_changes': 0, 'protected_recovery_retained': True,
                      'legacy_writer_still_suspended': True, 'resume_legacy_requires_reviewed_source_change': True}))


def main():
    os.umask(0o077)
    if len(sys.argv) != 3 or sys.argv[1] not in ('prepare', 'advance', 'reverse'):
        raise ValueError('Use prepare, advance, or reverse with an explicit writable private input directory')
    actions = {'prepare': prepare, 'advance': advance, 'reverse': reverse}
    actions[sys.argv[1]](Path(sys.argv[2]))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Cloudflare ownership maintenance incomplete; retain protected recovery and suspension', file=sys.stderr)
        raise SystemExit(1) from None
