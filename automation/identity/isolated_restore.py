"""Exercise restored signing state without opening an issuer to real clients."""
import base64
import json
import secrets
import subprocess

from automation.data import control
from automation.identity.configuration import REALMS, bootstrap_writer, bootstrap_health, restrict_password_grants
from automation.identity.recovery import restore_configuration, signature_state
from automation.mesh.kube import application_ready, condition, get, kube, wait

NAMESPACE = 'cloudlab-data-restore'
ORIGIN = 'https://identity-restore.' + NAMESPACE + '.svc:8443'
LABEL = {'cloudlab.io/fixture': 'application-data-restore', 'cloudlab.io/identity-restore': 'true'}


def metadata(name):
    return {'name': name, 'namespace': NAMESPACE, 'labels': LABEL}


def pod(name, role, image, command, *, env=None, mounts=None, volumes=None, memory='512Mi'):
    return {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {
        **metadata(name), 'labels': {**LABEL, 'cloudlab.io/restore-role': role}},
        'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
            'activeDeadlineSeconds': 1800, 'terminationGracePeriodSeconds': 20,
            'securityContext': {'runAsNonRoot': True, 'runAsUser': 1000, 'runAsGroup': 1000,
                                'fsGroup': 1000, 'seccompProfile': {'type': 'RuntimeDefault'}},
            'containers': [{'name': 'identity', 'image': image, 'command': command,
                'env': env or [], 'volumeMounts': mounts or [],
                'securityContext': {'allowPrivilegeEscalation': False, 'capabilities': {'drop': ['ALL']}},
                'resources': {'requests': {'cpu': '100m', 'memory': memory},
                              'limits': {'cpu': '500m', 'memory': memory}}}],
            'volumes': volumes or []}}


def policies():
    peer = lambda role: {'podSelector': {'matchLabels': {'cloudlab.io/restore-role': role,
                                                       'cloudlab.io/identity-restore': 'true'}}}
    dns = {'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': 'kube-system'}},
           'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}}}
    return [
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': metadata('identity-restore-isolation'), 'spec': {
             'podSelector': {'matchLabels': {'cloudlab.io/identity-restore': 'true'}},
             'policyTypes': ['Ingress', 'Egress'],
             'ingress': [{'from': [peer('probe'), peer('writer')],
                          'ports': [{'protocol': 'TCP', 'port': 8443}]}],
             'egress': [{'to': [dns], 'ports': [{'protocol': protocol, 'port': 53} for protocol in ('TCP', 'UDP')]},
                        {'to': [{'podSelector': {'matchLabels': {'cloudlab.io/restore': 'postgres'}}}],
                         'ports': [{'protocol': 'TCP', 'port': 5432}]},
                        {'to': [peer('server')], 'ports': [{'protocol': 'TCP', 'port': 8443}]}]}},
        {'apiVersion': 'networking.k8s.io/v1', 'kind': 'NetworkPolicy',
         'metadata': metadata('identity-restore-database'), 'spec': {
             'podSelector': {'matchLabels': {'cloudlab.io/restore': 'postgres'}}, 'policyTypes': ['Ingress'],
             'ingress': [{'from': [peer('server'), peer('bootstrap')],
                          'ports': [{'protocol': 'TCP', 'port': 5432}]}]}},
    ]


def secret(name):
    value = get('secret', name, 'cloudlab-identity')
    external = get('externalsecret.external-secrets.io', name, 'cloudlab-identity')
    if not value or not condition(external, 'Ready') or not any(
            row.get('uid') == external['metadata']['uid'] and row.get('kind') == 'ExternalSecret'
            for row in value['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Current identity recovery credentials require ready ESO ownership')
    return {key: base64.b64decode(data, validate=True).decode() for key, data in value['data'].items()}


def request(path, *, form=None, token=None):
    # Requests and bearer credentials travel through stdin; responses never become logs.
    script = """import sys,json;sys.path.insert(0,'/code')
from configuration import private_request
try:
 value=json.load(sys.stdin)
 print(json.dumps(private_request(value['url'],form=value['form'],token=value['token'])))
except Exception: raise SystemExit('Isolated identity request failed') from None
"""
    result = subprocess.run(['/usr/local/bin/k3s', 'kubectl', 'exec', '-i', '-n', NAMESPACE,
        'identity-restore-probe', '--', 'python', '-c', script],
        input=json.dumps({'url': ORIGIN + path, 'form': form, 'token': token}),
        capture_output=True, text=True, timeout=45)
    if result.returncode:
        raise RuntimeError('Isolated identity request failed; private diagnostics withheld')
    return json.loads(result.stdout)



def client_inventory(realm, token):
    rows = []
    for first in range(0, 10000, 100):
        page = request('/admin/realms/' + realm + '/clients?first=' + str(first) + '&max=100', token=token)
        if (not isinstance(page, list) or len(page) > 100 or
                any(not isinstance(row, dict) or not isinstance(row.get('clientId'), str) for row in page)):
            raise RuntimeError('Restored client inventory is malformed')
        rows.extend(page)
        if len({row['clientId'] for row in rows}) != len(rows):
            raise RuntimeError('Restored client inventory is ambiguous')
        if len(page) < 100:
            return rows
    raise RuntimeError('Restored client inventory exceeds its bounded limit')


def completed(name):
    def done():
        current = get('pod', name, NAMESPACE)
        phase = (current or {}).get('status', {}).get('phase')
        if phase == 'Failed':
            raise RuntimeError('Isolated identity operation failed; private diagnostics withheld')
        return phase == 'Succeeded'
    wait(done, 'isolated identity operation', timeout=600)


def run(manifest, sql):
    if 'identity' not in manifest:
        return {'identity_issuer_restore_proven': False, 'identity_state_present': False}
    identity = manifest['identity']
    namespace = get('namespace', NAMESPACE)
    if not namespace or namespace['metadata'].get('labels', {}).get('cloudlab.io/fixture') != LABEL['cloudlab.io/fixture']:
        raise RuntimeError('Identity recovery requires the authorized isolated physical restore owner')
    if get('pod', 'identity-restore-server', NAMESPACE):
        raise RuntimeError('Previous isolated identity server must be removed before offline recovery')
    private_app = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd') or {}
    revision = private_app.get('status', {}).get('sync', {}).get('revision')
    if not revision or not application_ready('cloudlab-identity-private', revision):
        raise RuntimeError('Current private identity source is unavailable; restore replay refused')
    private = get('configmap', 'identity-private-state', 'cloudlab-identity')
    if not private or not private['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-identity-private:'):
        raise RuntimeError('Current identity recovery inputs have conflicting ownership')
    source, revoked = [json.loads(private['data'][key]) for key in ('desired_state', 'revocations')]
    database = secret('keycloak-database')
    writers, health = secret('keycloak-realm-writers'), secret('keycloak-realm-health')
    credentials = json.loads(secret('keycloak-client-secrets')['client_secrets'])
    # Complete current inputs must validate before any isolated account is created.
    for realm in REALMS:
        restore_configuration(realm, 'identity-restore.' + NAMESPACE + '.svc', source, credentials, revoked, [])
    app = get('application.argoproj.io', 'cloudlab-identity', 'argocd') or {}
    settings = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
    if settings.get('database') != identity['database'] or settings.get('databaseRole') != identity['role']:
        raise RuntimeError('Identity recovery requires a reviewed current database mapping')
    if database['username'] != identity['role']:
        raise RuntimeError('Restored identity database role differs from current recovery input')
    sql('ALTER ROLE ' + control.identity(identity['role']) + " LOGIN PASSWORD '" + database['password'].replace("'", "''") + "';")
    images = json.loads((control.ROOT / 'platform/identity/keycloak/artifact.lock.json').read_text())['images']
    for document in policies():
        kube('apply', '-f', '-', document=document)
    kube('apply', '-f', '-', document={'apiVersion': 'cert-manager.io/v1', 'kind': 'Certificate',
        'metadata': metadata('identity-restore'), 'spec': {'secretName': 'identity-restore-tls',
            'dnsNames': ['identity-restore.' + NAMESPACE + '.svc'],
            'issuerRef': {'name': 'restore-sql', 'kind': 'Issuer'}}})
    wait(lambda: condition(get('certificate.cert-manager.io', 'identity-restore', NAMESPACE), 'Ready'), 'isolated issuer TLS')
    emergency_id, emergency_secret = 'restore-' + secrets.token_hex(8), secrets.token_urlsafe(48)
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata('identity-restore-credentials'),
        'stringData': {'database_username': database['username'], 'database_password': database['password'],
                       'emergency_secret': emergency_secret}})
    ca_volume = {'name': 'trust', 'secret': {'secretName': 'data-restore-ca'}}
    ca_mount = {'name': 'trust', 'mountPath': '/trust', 'readOnly': True}
    env = [{'name': 'KC_DB', 'value': 'postgres'}, {'name': 'KC_DB_TLS_MODE', 'value': 'verify-full'},
           {'name': 'KC_DB_URL', 'value': 'jdbc:postgresql://data-restore-rw.' + NAMESPACE + '.svc:5432/' + identity['database']},
           {'name': 'KC_TRUSTSTORE_PATHS', 'value': '/trust'},
           *[{'name': 'KC_DB_' + field.upper(), 'valueFrom': {'secretKeyRef': {
               'name': 'identity-restore-credentials', 'key': 'database_' + field}}} for field in ('username', 'password')]]
    bootstrap = pod('identity-restore-bootstrap', 'bootstrap', images['server'],
        ['/opt/keycloak/bin/kc.sh', 'bootstrap-admin', 'service', '--client-id=' + emergency_id,
         '--client-secret:env=RECOVERY_SECRET', '--no-prompt'], env=env + [{'name': 'RECOVERY_SECRET',
         'valueFrom': {'secretKeyRef': {'name': 'identity-restore-credentials', 'key': 'emergency_secret'}}}],
         mounts=[ca_mount], volumes=[ca_volume], memory='1Gi')
    kube('create', '-f', '-', document=bootstrap)
    completed('identity-restore-bootstrap')
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Service', 'metadata': metadata('identity-restore'),
        'spec': {'type': 'ClusterIP', 'selector': {'cloudlab.io/restore-role': 'server',
                 'cloudlab.io/identity-restore': 'true'}, 'ports': [{'port': 8443, 'targetPort': 8443}]}})
    server = pod('identity-restore-server', 'server', images['server'], ['/opt/keycloak/bin/kc.sh', 'start',
        '--http-enabled=false', '--hostname=' + ORIGIN, '--hostname-admin=' + ORIGIN, '--hostname-strict=true',
        '--https-certificate-file=/tls/tls.crt', '--https-certificate-key-file=/tls/tls.key',
        '--health-enabled=true', '--http-management-scheme=http', '--log-level=WARN'], env=env,
        mounts=[ca_mount, {'name': 'tls', 'mountPath': '/tls', 'readOnly': True}],
        volumes=[ca_volume, {'name': 'tls', 'secret': {'secretName': 'identity-restore-tls'}}], memory='1Gi')
    server['spec']['containers'][0]['readinessProbe'] = {'httpGet': {'path': '/health/ready', 'port': 9000},
                                                       'periodSeconds': 5, 'failureThreshold': 60}
    kube('create', '-f', '-', document=server)
    wait(lambda: condition(get('pod', 'identity-restore-server', NAMESPACE), 'Ready'), 'isolated identity startup', timeout=600)
    code = (control.ROOT / 'automation/identity/configuration.py').read_text()
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'ConfigMap', 'metadata': metadata('identity-restore-code'),
        'data': {'configuration.py': code, 'config-cli.properties': (control.ROOT / 'platform/identity/keycloak/config-cli.properties').read_text()}})
    code_volume = {'name': 'code', 'configMap': {'name': 'identity-restore-code'}}
    code_mount = {'name': 'code', 'mountPath': '/code', 'readOnly': True}
    kube('create', '-f', '-', document=pod('identity-restore-probe', 'probe', images['python'],
        ['python', '-c', 'import time;time.sleep(1700)'], env=[{'name': 'SSL_CERT_FILE', 'value': '/trust/ca.crt'}],
        mounts=[ca_mount, code_mount], volumes=[ca_volume, code_volume], memory='64Mi'))
    wait(lambda: condition(get('pod', 'identity-restore-probe', NAMESPACE), 'Ready'), 'isolated issuer probe')
    admin = lambda: request('/realms/master/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': emergency_id, 'client_secret': emergency_secret})['access_token']
    token = admin()
    imports = {}
    for realm in REALMS:
        rows = client_inventory(realm, token)
        state = restrict_password_grants(restore_configuration(realm, 'identity-restore.' + NAMESPACE + '.svc',
            source, credentials, revoked, rows))
        # Preserve unmanaged realm attributes while giving the restored issuer a distinct origin.
        attributes = request('/admin/realms/' + realm, token=token).get('attributes', {})
        state['attributes'] = dict(attributes, frontendUrl=ORIGIN)
        state = bootstrap_health(bootstrap_writer(state, writers[realm + '_client_secret']), health[realm + '_client_secret'])
        imports[realm + '.json'] = json.dumps(state, sort_keys=True)
    proof_id, proof_secret = 'restore-proof-' + secrets.token_hex(8), secrets.token_urlsafe(48)
    if any(row.get('clientId') == proof_id for row in rows):
        raise RuntimeError('Isolated proof client conflicts with a restored identity')
    applications = json.loads(imports['applications.json'])
    applications['clients'].append({'clientId': proof_id, 'enabled': True, 'protocol': 'openid-connect',
        'publicClient': False, 'secret': proof_secret, 'serviceAccountsEnabled': True, 'standardFlowEnabled': False,
        'directAccessGrantsEnabled': False, 'implicitFlowEnabled': False, 'fullScopeAllowed': False,
        'redirectUris': [], 'webOrigins': [], 'defaultClientScopes': ['basic'], 'optionalClientScopes': [],
        'protocolMappers': [{'name': 'restore-audience', 'protocol': 'openid-connect', 'protocolMapper': 'oidc-audience-mapper',
                            'config': {'included.custom.audience': proof_id, 'access.token.claim': 'true', 'id.token.claim': 'false'}}]})
    imports['applications.json'] = json.dumps(applications, sort_keys=True)
    kube('apply', '-f', '-', document={'apiVersion': 'v1', 'kind': 'Secret', 'metadata': metadata('identity-restore-imports'), 'stringData': imports})
    writer = pod('identity-restore-writer', 'writer', images['config_cli'], ['/bin/sh', '-ec',
        'keytool -importcert -noprompt -alias restore-ca -file /trust/ca.crt -keystore /tmp/trust.p12 -storepass restore-trust >/tmp/private-result 2>&1; '
        'for realm in platform applications; do export IMPORT_FILES_LOCATIONS="/imports/$realm.json"; '
        'java -Djavax.net.ssl.trustStore=/tmp/trust.p12 -Djavax.net.ssl.trustStorePassword=restore-trust '
        '-jar /app/keycloak-config-cli.jar --spring.config.additional-location=file:/code/config-cli.properties '
        '--import.cache.key=isolated-restore >/tmp/private-result 2>&1 || exit 1; done'],
        env=[{'name': 'KEYCLOAK_URL', 'value': ORIGIN}, {'name': 'KEYCLOAK_LOGINREALM', 'value': 'master'},
             {'name': 'KEYCLOAK_CLIENTID', 'value': emergency_id}, {'name': 'KEYCLOAK_GRANTTYPE', 'value': 'client_credentials'},
             {'name': 'KEYCLOAK_SKIPSERVERINFO', 'value': 'true'}, {'name': 'KEYCLOAK_CLIENTSECRET',
              'valueFrom': {'secretKeyRef': {'name': 'identity-restore-credentials', 'key': 'emergency_secret'}}}],
        mounts=[ca_mount, code_mount, {'name': 'imports', 'mountPath': '/imports', 'readOnly': True}, {'name': 'tmp', 'mountPath': '/tmp'}],
        volumes=[ca_volume, code_volume, {'name': 'imports', 'secret': {'secretName': 'identity-restore-imports'}},
                 {'name': 'tmp', 'emptyDir': {'medium': 'Memory', 'sizeLimit': '64Mi'}}])
    kube('create', '-f', '-', document=writer)
    completed('identity-restore-writer')
    if signature_state(sql, identity['database']) != identity['signing_state_sha256']:
        raise RuntimeError('Restored signing state changed during recovery-input replay')
    from automation.identity.tokens import validated_claims
    realm_issuer = ORIGIN + '/realms/applications'
    discovery = request('/realms/applications/.well-known/openid-configuration')
    if discovery['issuer'] != realm_issuer:
        raise RuntimeError('Restored issuer must remain distinct from production')
    proof_token = request('/realms/applications/protocol/openid-connect/token', form={
        'grant_type': 'client_credentials', 'client_id': proof_id, 'client_secret': proof_secret})['access_token']
    validated_claims(proof_token, request('/realms/applications/protocol/openid-connect/certs'),
                     realm_issuer, proof_id, 'Bearer')
    if (secret('keycloak-database') != database or secret('keycloak-realm-writers') != writers or
            secret('keycloak-realm-health') != health or
            json.loads(secret('keycloak-client-secrets')['client_secrets']) != credentials):
        raise RuntimeError('Current recovery credentials changed during replay; review and repeat')
    if (get('configmap', 'identity-private-state', 'cloudlab-identity')['data'] != private['data'] or
            not application_ready('cloudlab-identity-private', revision)):
        raise RuntimeError('Current recovery inputs changed during replay; review and repeat')
    return {'identity_issuer_restore_proven': True, 'restored_signing_jwt_verified': True,
            'current_vault_and_private_inputs_replayed': True, 'restored_identity_issuer_exposed': False,
            'restored_removed_client_tombstones_applied': True, 'membership_revocation_review_required_before_reopening': True}
