"""Native SQL ownership experiment; never connect to production or manage data."""
import json
import os
from pathlib import Path
import shutil
import secrets
import subprocess
import time

WORK = Path('/candidate')


def tofu(*args):
    result = subprocess.run(['tofu', *args, '-no-color'], cwd=WORK, capture_output=True, text=True)
    if result.returncode:
        (WORK / 'private-error').write_text(result.stderr)
        summary = next((line for line in result.stderr.splitlines() if line.startswith('Error:')), 'No error summary')
        raise RuntimeError('Native data provider fixture failed at ' + args[0] + ': ' + summary)
    return result.stdout


def wait(name):
    deadline = time.monotonic() + 90
    while not (WORK / name).exists():
        if time.monotonic() > deadline:
            raise RuntimeError('Disposable SQL catalog check timed out: ' + name)
        time.sleep(1)


def plan():
    tofu('plan', '-input=false', '-out=check.tfplan')
    document = json.loads(tofu('show', '-json', 'check.tfplan'))
    return {r['address']: r['change']['actions'] for r in document.get('resource_changes', [])
            if r['change']['actions'] != ['no-op']}


def main():
    os.umask(0o077)
    for name in ('versions.tf', '.terraform.lock.hcl'):
        shutil.copyfile(Path('/workspace/automation/data/provider-fixture') / name, WORK / name)
    configuration = {'provider': {'postgresql': {'host': 'database', 'username': 'postgres',
                     'database': 'postgres', 'sslmode': 'disable', 'superuser': True}}, 'resource': {
        'postgresql_role': {'reader': {'name': 'provider_reader', 'login': True, 'connection_limit': 20,
                                     'skip_reassign_owned': False}},
        'postgresql_database': {'fixture': {'name': 'provider_fixture', 'owner': 'postgres'}},
        'postgresql_grant': {'connect': {'database': '${postgresql_database.fixture.name}',
                                        'role': '${postgresql_role.reader.name}',
                                        'object_type': 'database', 'privileges': ['CONNECT']}}}}
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    tofu('validate')
    wait('seeded')
    for address, remote in {'postgresql_role.reader': 'provider_reader',
                            'postgresql_database.fixture': 'provider_fixture'}.items():
        tofu('import', '-input=false', address, remote)
    unsupported = subprocess.run(['tofu', 'import', '-input=false', '-no-color',
                                  'postgresql_grant.connect', 'provider_reader_provider_fixture_database'],
                                 cwd=WORK, capture_output=True, text=True)
    if unsupported.returncode == 0 or "doesn't support import" not in unsupported.stderr:
        raise RuntimeError('Expected grant import gap changed; requalify SQL ownership')
    initial = plan()
    if initial != {'postgresql_grant.connect': ['create']}:
        native = json.loads(tofu('show', '-json', 'check.tfplan'))
        differences = {r['address']: sorted(k for k, v in (r['change'].get('before') or {}).items()
                       if v != (r['change'].get('after') or {}).get(k))
                       for r in native.get('resource_changes', []) if r['change']['actions'] != ['no-op']}
        raise RuntimeError('Imported SQL fixture has unintended changes: ' + json.dumps(differences))
    tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    if plan():
        raise RuntimeError('Native SQL declaration did not converge after grant adoption')
    (WORK / 'drift').touch()
    wait('drifted')
    drift = plan()
    if set(drift) != {'postgresql_role.reader', 'postgresql_grant.connect'}:
        raise RuntimeError('Native SQL provider did not detect both role and grant drift')
    tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    (WORK / 'repaired').touch()
    wait('verified')
    if plan():
        raise RuntimeError('Native SQL repeat plan is not empty')
    state = json.loads(tofu('show', '-json'))
    role = next(r['values'] for r in state['values']['root_module']['resources']
                if r['address'] == 'postgresql_role.reader')
    password_hash_in_state = bool(role.get('password'))
    supplied_password = secrets.token_urlsafe(32)
    configuration['resource']['postgresql_role']['reader']['password'] = supplied_password
    (WORK / 'main.tf.json').write_text(json.dumps(configuration))
    if plan() != {'postgresql_role.reader': ['update']}:
        raise RuntimeError('Supplied SQL password did not produce a bounded role update')
    tofu('apply', '-input=false', '-auto-approve', 'check.tfplan')
    supplied_password_in_state = supplied_password in tofu('show', '-json')
    if plan():
        raise RuntimeError('SQL credential update did not converge')
    tofu('destroy', '-input=false', '-auto-approve')
    (WORK / 'deleted').touch()
    wait('delete-verified')
    print(json.dumps({'opentofu': '1.13.1', 'provider': 'cyrilgdn/postgresql@1.27.0',
                      'api': 'PostgreSQL 18.4', 'imported_resources': 2, 'grant_import_supported': False,
                      'repeat_empty': True,
                      'role_and_grant_drift_repaired': True, 'scoped_delete': True,
                      'unrelated_role_preserved': True, 'password_hash_in_state': password_hash_in_state,
                      'supplied_password_in_state': supplied_password_in_state,
                      'native_tls_proven': False, 'cnpg_and_vault_rotation_parity_proven': False,
                      'scope': 'isolated trust-auth Compose; not production TLS/restore qualification'}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Disposable SQL provider failed; private diagnostics withheld') from None
    finally:
        for name in ('main.tf.json', 'check.tfplan', 'terraform.tfstate', 'terraform.tfstate.backup'):
            (WORK / name).unlink(missing_ok=True)
