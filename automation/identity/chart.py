"""Check official artifacts, chart ownership and safe realm-writer settings."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import yaml

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'platform/identity/keycloak'


def render(values=None):
    command = ['helm', 'template', 'cloudlab-keycloak', str(BASE), '--namespace', 'cloudlab-identity',
               '--kube-version', '1.36.5', '--values', '-']
    outputs = [subprocess.run(command, input=json.dumps(values or {}), text=True,
                              capture_output=True, timeout=90) for _ in range(2)]
    if any(r.returncode for r in outputs):
        raise ValueError('Identity chart render failed: ' + outputs[0].stderr)
    if outputs[0].stdout != outputs[1].stdout:
        raise ValueError('Identity chart rendering is not deterministic')
    return [obj for obj in yaml.safe_load_all(outputs[0].stdout) if obj]


def check():
    lock = json.loads((BASE / 'artifact.lock.json').read_text())
    for filename, item in lock['sources'].items():
        if hashlib.sha256((BASE / 'upstream' / filename).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('Official Operator artifact checksum mismatch')
    for filename in ('configuration.py', 'lease.py', 'health.py'):
        if (BASE / 'runtime' / filename).read_bytes() != (ROOT / 'automation/identity' / filename).read_bytes():
            raise ValueError('Packaged identity runtime differs from owning module')
    if render():
        raise ValueError('Identity must remain inactive until explicitly enabled')
    try:
        render({'enabled': True, 'serverEnabled': False})
    except ValueError as error:
        if 'isolated pinned Operator/server' not in str(error):
            raise
    else:
        if not lock['operator_install_verified']:
            raise ValueError('Unverified Operator installation must fail closed')
    values = {'enabled': True, 'operatorEnabled': lock['operator_install_verified'], 'reconciliationEnabled': True, 'privateStateEnabled': True,
              'trustedProxyAddresses': ['10.43.0.10/32', '10.43.0.11/32'],
              'databaseCA': 'fixture-ca'}
    objects = render(values)
    initial = render(dict(values, reconciliationEnabled=False, privateStateEnabled=False))
    initial_secrets = {o['metadata']['name'] for o in initial if o['kind'] == 'ExternalSecret'}
    if initial_secrets != {'keycloak-database', 'keycloak-bootstrap-admin', 'keycloak-realm-writers',
                           'keycloak-realm-health', 'keycloak-client-secrets'}:
        raise ValueError('Server phase must declare required ESO inputs before bootstrap validation')
    crds = [o['metadata']['name'] for o in objects if o['kind'] == 'CustomResourceDefinition']
    if set(crds) != ({'keycloaks.k8s.keycloak.org', 'keycloakrealmimports.k8s.keycloak.org'}
                     if lock['operator_install_verified'] else set()):
        raise ValueError('Preview client CRDs must not be dependencies')
    if any(o['kind'] in ('KeycloakRealmImport', 'KeycloakOIDCClient', 'KeycloakSAMLClient', 'PersistentVolumeClaim') for o in objects):
        raise ValueError('Identity contains forbidden ownership or storage resources')
    server = next(o for o in objects if o['kind'] == 'Keycloak')['spec']
    if server['instances'] != 1 or server['ingress']['enabled'] or not server['resources']['limits']:
        raise ValueError('Identity topology, privacy or resources changed')
    if not any(option == {'name': 'db-tls-mode', 'value': 'verify-server'} for option in server['additionalOptions']):
        raise ValueError('Identity database TLS must use the supported server identity verification mode')
    if any(o['kind'] == 'ExternalSecret' and o['spec']['refreshInterval'] != '1h' for o in objects):
        raise ValueError('Routine identity vault reads must stay within the existing subscription budget')
    for image in lock['images'].values():
        if not re.search(r'@sha256:[a-f0-9]{64}$', image):
            raise ValueError('Unpinned identity image')
    properties = (BASE / 'config-cli.properties').read_text()
    if 'import.cache.enabled=false' not in properties or 'import.remote-state.enabled=true' not in properties:
        raise ValueError('Drift repair and safe state tracking are required')
    if any(line.startswith('import.managed.') and not line.endswith('=no-delete') for line in properties.splitlines()):
        raise ValueError('Automatic identity deletion is forbidden')
    route = next(o for o in objects if o['kind'] == 'HTTPRoute' and o['metadata']['name'] == 'identity-protocols')
    paths = [match['path'] for rule in route['spec']['rules'] for match in rule['matches']]
    exact = {path['value'] for path in paths if path['type'] == 'Exact'}
    if ([path for path in paths if path['type'] != 'Exact'] != [{'type': 'PathPrefix', 'value': '/resources'}]
            or any('admin' in path or 'clients-registrations' in path or '..' in path or '%' in path for path in exact)):
        raise ValueError('Public identity must allow exact protocol paths and static resources only')
    denied = next(o for o in objects if o['kind'] == 'AuthorizationPolicy')['spec']['rules'][0]['to'][0]['operation']['notPaths']
    if set(denied) != exact | {'/resources', '/resources/*'}:
        raise ValueError('Gateway policy and protocol route allowlists differ')
    for realm in ('platform', 'applications'):
        required = {'/realms/' + realm + '/.well-known/openid-configuration',
                    '/realms/' + realm + '/login-actions/required-action'}
        required.update('/realms/' + realm + '/protocol/openid-connect/' + endpoint
                        for endpoint in ('auth', 'token', 'certs', 'userinfo', 'logout'))
        if not required <= exact:
            raise ValueError('Required OIDC and MFA browser paths are missing')
    for obj in objects:
        if obj['kind'] not in ('Job', 'CronJob'):
            continue
        job = obj['spec']['jobTemplate']['spec'] if obj['kind'] == 'CronJob' else obj['spec']
        if job['template']['spec'].get('serviceAccountName') == 'identity-writer' and (
                job['template']['spec'].get('activeDeadlineSeconds') != 210 or
                job['template'].get('metadata', {}).get('labels', {}).get('cloudlab.io/identity-writer') != 'true'):
            raise ValueError('Writer pods require independent deadlines and previous-holder identity checks')
        if job['activeDeadlineSeconds'] + job['template']['spec']['terminationGracePeriodSeconds'] >= 240:
            raise ValueError('Realm job can outlive its exclusive lease')
    bootstrap = render(dict(values, bootstrapMode=True))
    scheduled = next(o for o in objects if o['kind'] == 'CronJob' and o['metadata']['name'] == 'identity-reconcile')
    sync = next(o for o in objects if o['kind'] == 'Job' and o['metadata']['name'] == 'identity-reconcile-sync')
    if ('acquire(skip_busy=True)' not in scheduled['spec']['jobTemplate']['spec']['template']['spec']['initContainers'][0]['args'][0]
            or 'acquire(skip_busy=False)' not in sync['spec']['template']['spec']['initContainers'][0]['args'][0]):
        raise ValueError('Only scheduled runs may skip a busy valid writer lock; sync must retry')
    if any(o['kind'] == 'Lease' for o in objects + bootstrap):
        raise ValueError('Argo always excludes Leases; the job must initialize its operational lock')
    writer_role = next(o for o in objects if o['kind'] == 'Role' and o['metadata']['name'] == 'identity-writer')
    lease_rules = [r for r in writer_role['rules'] if r.get('resources') == ['leases']]
    if lease_rules != [dict(apiGroups=['coordination.k8s.io'], resources=['leases'], resourceNames=['identity-writer'], verbs=['get', 'update']),
                       dict(apiGroups=['coordination.k8s.io'], resources=['leases'], verbs=['create'])]:
        raise ValueError('Only the named writer may read/update its lock; creation is namespace-scoped')
    if any(o['kind'] == 'CronJob' for o in bootstrap):
        raise ValueError('Bootstrap credentials must never enter scheduled reconciliation')
    primary = render(dict(values, bootstrapMode=True, primaryAdminEnabled=True))
    if not any(o['kind'] == 'ExternalSecret' and o['metadata']['name'] == 'keycloak-primary-admin' for o in primary):
        raise ValueError('Primary initialization requires ESO-owned credentials')
    primary_job = next(o for o in primary if o['kind'] == 'Job')['spec']['template']['spec']
    scoped_secrets = {o['metadata']['name'] for o in objects if o['kind'] == 'ExternalSecret'}
    if 'keycloak-primary-admin' not in scoped_secrets:
        raise ValueError('Scoped reconciliation must retain the primary ESO owner after initialization')
    for obj in objects:
        if obj['kind'] not in ('Job', 'CronJob'):
            continue
        job = obj['spec']['jobTemplate']['spec'] if obj['kind'] == 'CronJob' else obj['spec']
        if any(volume.get('secret', {}).get('secretName') == 'keycloak-primary-admin'
               for volume in job['template']['spec'].get('volumes', [])):
            raise ValueError('Normal writers must never mount primary credentials')
    if '--import.remote-state.enabled=false' not in primary_job['containers'][0]['args'][0]:
        raise ValueError('Creation-only credentials must not enter normal realm state tracking')
    try:
        render(dict(values, primaryAdminEnabled=True))
    except ValueError:
        pass
    else:
        raise ValueError('Normal reconciliation must never mount primary passwords')
    maintenance = render(dict(values, maintenance=True))
    if next(o for o in maintenance if o['kind'] == 'Keycloak')['spec']['instances'] != 0:
        raise ValueError('Monthly capture must quiesce the identity server')
    if any(o['kind'] == 'Job' for o in maintenance) or any(not o['spec']['suspend'] for o in maintenance if o['kind'] == 'CronJob'):
        raise ValueError('Monthly capture must suspend all realm writers')
    removal = render(dict(values, operation={'action': 'remove-client', 'realm': 'applications', 'client': 'reference'}))
    if not next(o for o in removal if o['kind'] == 'CronJob' and o['metadata']['name'] == 'identity-reconcile')['spec']['suspend']:
        raise ValueError('Explicit lifecycle operation must suspend the regular writer schedule')
    if 'unsupported' in server:
        raise ValueError('Unsupported Operator pod-template overrides are forbidden')
    return {'identity_resources': len(objects), 'official_crds': len(crds),
            'default_enabled': False, 'automatic_deletion': False, 'checksum_cache': False,
            'operator_install_verified': lock['operator_install_verified']}


if __name__ == '__main__':
    print(json.dumps(check(), sort_keys=True))
