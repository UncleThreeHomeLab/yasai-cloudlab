"""Identity ownership, private-input and source-handoff guards; no mutations."""
from datetime import datetime
import copy
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
if not (ROOT / 'platform').is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
sys.path.insert(0, str(ROOT))
from playbooks.data.files.control import identity
from playbooks.keycloak.files.configuration import compile_state, exact_url
from playbooks.keycloak.files.maintenance import APP, NAMESPACE, OWNER, BASE
from playbooks.istio.files.kube import application_ready, condition, get
from playbooks.argocd.files.private_sources import PEM_TEMPLATE

PHASES = ('server', 'bootstrap', 'primary', 'scoped')
INSTALLATION_REVISION = '526891f62eb9b9a50a0ffaf6ef020269d09e7746'
PUBLIC_REPOSITORY = 'https://github.com/UncleThreeHomeLab/yasai-cloudlab.git'
INSTALLATION_FIELDS = ('loginHost', 'adminHost', 'database', 'databaseRole', 'databaseHost', 'databasePort', 'databaseCA', 'trustedProxyAddresses')
OPERATION_FIELDS = ('maintenance', 'operation', 'bootstrapAdminEnabled', 'retiredEmergencyItem')


def installation_values(document, *, telemetry=False):
    """Select the finite private installation contract; no Application overrides."""
    if (not isinstance(document, dict) or set(document) != set(INSTALLATION_FIELDS) | {'installationRevision', 'retiredEmergencyItem'}
            or document['installationRevision'] != INSTALLATION_REVISION
            or type(document['databasePort']) is not int
            or not isinstance(document['trustedProxyAddresses'], list) or not 1 <= len(document['trustedProxyAddresses']) <= 8
            or any(not isinstance(document[key], str) for key in INSTALLATION_FIELDS if key not in ('databasePort', 'trustedProxyAddresses'))):
        raise RuntimeError('Identity installation input refused')
    if (len(document['loginHost']) > 240 or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+', document['loginHost'])
            or len(document['databaseCA']) > 16384):
        raise RuntimeError('Identity installation input refused')
    import ipaddress
    for address in document['trustedProxyAddresses']:
        network = ipaddress.ip_network(address, strict=True)
        if (network.version != 4 or network.prefixlen < 24 or str(network) != address
                or not any(network.subnet_of(ipaddress.ip_network(prefix)) for prefix in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'))):
            raise RuntimeError('Native identity requires canonical private IPv4 Pod ranges of /24 or narrower')
    if len(set(document['trustedProxyAddresses'])) != len(document['trustedProxyAddresses']):
        raise RuntimeError('Identity proxy ranges must be unique')
    return application({'values': {key: document[key] for key in INSTALLATION_FIELDS}, 'repository': PUBLIC_REPOSITORY,
        'branch': INSTALLATION_REVISION, 'telemetry_enabled': telemetry}, 'scoped', retired=True,
        retired_item=document['retiredEmergencyItem'])['spec']


def installation_context(*, preparing=False):
    """Authenticate the current public owner and render its exact native contract."""
    from playbooks.data.files import native
    deadline = time.monotonic() + 180
    coordinates = {'publicSource': {'repository': PUBLIC_REPOSITORY, 'branch': 'main'}}
    public, revision = native.published_source(coordinates, deadline=deadline)
    target = native.root_guard(coordinates, public, revision)
    if type(public.get('identity', {}).get('application', {}).get('enabled')) is not bool:
        raise RuntimeError('Identity installation owner requires explicit public intent')
    if not preparing and not public['identity']['application']['enabled']:
        raise RuntimeError('Native identity installation owner is disabled')
    files = native.source_snapshot.chart_files({'repository': PUBLIC_REPOSITORY, 'revision': revision, 'path': 'gitops/roots/public'}, deadline=deadline)
    values = copy.deepcopy(public); values['identity']['argo'] = target
    if preparing: values['identity']['application']['enabled'] = True
    objects = native.render_objects(files, [values])
    desired = {obj['kind']: obj for obj in objects if obj.get('metadata', {}).get('name') == APP
        and obj['kind'] in ('ApplicationSet', 'AppProject')}
    if set(desired) != {'ApplicationSet', 'AppProject'}:
        raise RuntimeError('Authenticated public owner lacks the native identity contract')
    root = get('application.argoproj.io', 'cloudlab-public-root', 'argocd') or {}
    project = get('appproject.argoproj.io', APP, 'argocd') or {}
    return public, revision, target, files, desired, root, project, deadline


def ownership_receipt(base):
    path = base / 'ownership.json'
    if any(entry.is_symlink() for entry in (*path.parents, path)):
        raise RuntimeError('Identity ownership receipt must not be redirected')
    return json.loads(path.read_text()) if path.exists() else {}


def installation_revision(platform_revision, *, base=BASE):
    """Select installation readiness separately from current platform prerequisites."""
    state = ownership_receipt(base)
    return INSTALLATION_REVISION if state.get('native') else platform_revision


def prepare_native(payload, current, state, retirement, *, base=BASE):
    """Under owner.lock, record the exact accepted scope before freezing main."""
    from playbooks.data.files import native
    from playbooks.data.files.control import atomic
    from playbooks.keycloak.files.bootstrap import writer_idle
    from playbooks.istio.files.kube import kube
    if native.receipt(base / 'ownership.json') != state or native.receipt(base / 'retirement.json') != retirement:
        raise RuntimeError('Native identity handoff requires unchanged protected ownership receipts')
    if state.get('native', {}).get('phase') == 'accepted':
        accepted_application(current, revision=INSTALLATION_REVISION, base=base)
        return False
    public, head, _, _, desired, root, project, deadline = installation_context(preparing=True)
    source = current.get('spec', {}).get('source', {})
    values = source.get('helm', {}).get('valuesObject', {})
    server = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
    if (state.get('phase') != 'scoped' or state.get('uid') != current.get('metadata', {}).get('uid')
            or retirement.get('phase') != 'accepted' or retirement.get('application_uid') != state['uid']
            or retirement.get('keycloak_uid') != server.get('metadata', {}).get('uid')
            or not native.quiet(current) or not native.quiet(project)
            or current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or values.get('maintenance') is not False or values.get('operation') or values.get('bootstrapAdminEnabled') is not False
            or values.get('retiredEmergencyItem') != 'keycloak-emergency-' + retirement['nonce']
            or not condition(server, 'Ready') or not writer_idle()
            or source.get('targetRevision') not in ('main', INSTALLATION_REVISION)):
        raise RuntimeError('Native identity handoff requires its accepted idle scoped Application and server')
    recorded = state.get('native')
    if ((source['targetRevision'] == INSTALLATION_REVISION and recorded is None)
            or (recorded is not None and recorded.get('original_revision') != 'main')):
        raise RuntimeError('Only the recorded initial main source freeze may resume at the native pin')
    for pattern in ('startup-recovery.json', 'proof-*.json', 'remove-*.json'):
        for path in base.glob(pattern):
            checkpoint = native.receipt(path)
            if (checkpoint.get('phase') in ('prepared', 'created', 'stopping', 'starting')
                    or (path.name.startswith('remove-') and checkpoint.get('complete') is not True)):
                raise RuntimeError('Complete pending identity operations before native handoff')
    document = {key: values.get(key) for key in INSTALLATION_FIELDS}
    document.update(installationRevision=INSTALLATION_REVISION, retiredEmergencyItem=values.get('retiredEmergencyItem'))
    expected = installation_values(document, telemetry=public['observability']['enabled'])
    expected['source']['targetRevision'] = source['targetRevision']
    if current.get('spec') != expected:
        raise RuntimeError('Native identity handoff must preserve the exact existing installation')
    old_project = copy.deepcopy(desired['AppProject']['spec']); old_project['sourceRepos'] = [PUBLIC_REPOSITORY]
    if (project.get('spec') != old_project or project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
            'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP
            or get('applicationset.argoproj.io', APP, 'argocd')
            or get('externalsecret.external-secrets.io', 'cloudlab-identity-installation-source', 'argocd')
            or get('secret', 'cloudlab-identity-installation-source', 'argocd')):
        raise RuntimeError('Native identity handoff refuses foreign or prematurely created control objects')
    resolved = head if source['targetRevision'] == 'main' else INSTALLATION_REVISION
    if not application_ready(APP, resolved) or not native.matches_revision(current, resolved):
        raise RuntimeError('Identity installation must converge before its source freeze')
    pinned = native.source_snapshot.chart_files({'repository': PUBLIC_REPOSITORY, 'revision': INSTALLATION_REVISION, 'path': 'platform/identity/keycloak'}, deadline=deadline)
    if resolved != INSTALLATION_REVISION and pinned != native.source_snapshot.chart_files(
            {'repository': PUBLIC_REPOSITORY, 'revision': resolved, 'path': 'platform/identity/keycloak'}, deadline=deadline):
        raise RuntimeError('Identity installation chart changed; source freeze cannot upgrade code')
    captured = {'phase': 'prepared', 'root_uid': root['metadata']['uid'], 'project_uid': project['metadata']['uid'],
        'application_uid': state['uid'], 'keycloak_uid': server['metadata']['uid'], 'values': copy.deepcopy(values),
        'original_revision': state.get('native', {}).get('original_revision', source['targetRevision'])}
    if state.get('native') is not None and state['native'] != captured:
        raise RuntimeError('Recorded native identity handoff scope changed')
    patches = []
    if source['targetRevision'] != INSTALLATION_REVISION:
        # Historical retirement pins remain evidence; this content-identical freeze has its own exact intent.
        patches = [{'op': 'test', 'path': '/metadata/uid', 'value': state['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
            {'op': 'test', 'path': '/spec', 'value': copy.deepcopy(current['spec'])},
            {'op': 'replace', 'path': '/spec/source/targetRevision', 'value': INSTALLATION_REVISION}]
    state.update(native=captured, revision=INSTALLATION_REVISION)
    changed = atomic(base / 'ownership.json', state)
    if patches:
        kube('patch', 'application.argoproj.io', APP, '-n', 'argocd', '--type=json', '--field-manager=' + OWNER,
            '-p', json.dumps(patches))
        changed = True
    return changed


def accepted_application(app, *, revision=None, base=BASE, register=False):
    """Observe a legacy owner or authenticate the one registered native parent."""
    path = base / 'ownership.json'
    state = ownership_receipt(base)
    captured = state.get('native')
    owners = app.get('metadata', {}).get('ownerReferences', [])
    if captured is None:
        if owners: raise RuntimeError('Unregistered native identity owner; complete the scoped handoff')
        return None
    from playbooks.data.files import native
    state = native.receipt(path)
    captured = state['native']
    fields = {'phase', 'root_uid', 'project_uid', 'application_uid', 'keycloak_uid', 'values', 'original_revision'}
    if captured.get('phase') == 'accepted': fields |= {'parent_uid', 'reader_uid', 'secret_uid'}
    if (set(captured) != fields or captured.get('phase') not in ('prepared', 'accepted')
            or any(not isinstance(captured[key], str) or not captured[key] for key in fields if key.endswith('_uid'))
            or not isinstance(captured['values'], dict) or captured['original_revision'] not in ('main', INSTALLATION_REVISION)
            or state.get('phase') != 'scoped' or state.get('uid') != captured['application_uid']
            or app.get('metadata', {}).get('uid') != captured['application_uid']
            or app['metadata'].get('deletionTimestamp') or app['metadata'].get('finalizers')
            or app['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
            or (revision is not None and revision != INSTALLATION_REVISION)
            or state.get('revision') != INSTALLATION_REVISION):
        raise RuntimeError('Native identity installation owner or requested pin changed')
    retired = native.receipt(base / 'retirement.json')
    server = get('keycloak.k8s.keycloak.org', 'cloudlab-keycloak', NAMESPACE) or {}
    if (retired.get('phase') != 'accepted' or retired.get('application_uid') != captured['application_uid']
            or retired.get('keycloak_uid') != captured['keycloak_uid']
            or server.get('metadata', {}).get('uid') != captured['keycloak_uid'] or server['metadata'].get('deletionTimestamp')):
        raise RuntimeError('Native identity handoff lost its accepted server or retirement identity')
    public, _, target, _, desired, root, project, _ = installation_context(preparing=captured['phase'] == 'prepared' and not owners)
    if (root.get('metadata', {}).get('uid') != captured['root_uid'] or project.get('metadata', {}).get('uid') != captured['project_uid']):
        raise RuntimeError('Native identity trusted Root or project was replaced')
    project_spec = copy.deepcopy(desired['AppProject']['spec'])
    if not public['identity']['application']['enabled']: project_spec['sourceRepos'] = [PUBLIC_REPOSITORY]
    if (not native.quiet(project) or project.get('spec') != project_spec
            or project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') !=
                'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP):
        raise RuntimeError('Native identity project scope or tracking changed')
    current_values = app.get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {})
    document = {key: current_values.get(key) for key in INSTALLATION_FIELDS}
    document.update(installationRevision=INSTALLATION_REVISION, retiredEmergencyItem=current_values.get('retiredEmergencyItem'))
    expected = installation_values(document, telemetry=public['observability']['enabled'])
    actual = copy.deepcopy(app.get('spec', {}))
    for field in OPERATION_FIELDS:
        expected['source']['helm']['valuesObject'].pop(field, None)
        actual.get('source', {}).get('helm', {}).get('valuesObject', {}).pop(field, None)
    if (actual != expected or type(current_values.get('maintenance')) is not bool
            or type(current_values.get('bootstrapAdminEnabled')) is not bool
            or current_values.get('operation') is not None and not isinstance(current_values['operation'], dict)):
        raise RuntimeError('Native identity child source or bounded installation contract changed')
    parent = get('applicationset.argoproj.io', APP, 'argocd')
    if captured['phase'] == 'prepared' and not owners and parent is None:
        if {key: value for key, value in current_values.items() if key not in OPERATION_FIELDS} != {
                key: value for key, value in captured['values'].items() if key not in OPERATION_FIELDS}:
            raise RuntimeError('Prepared identity installation values changed before native adoption')
        return INSTALLATION_REVISION
    if (not native.quiet(parent) or parent.get('spec') != desired['ApplicationSet']['spec']
            or parent['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != 'cloudlab-public-root:argoproj.io/ApplicationSet:argocd/' + APP
            or not native.quiet(project) or project.get('spec') != desired['AppProject']['spec']
            or project['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id') != 'cloudlab-public-root:argoproj.io/AppProject:argocd/' + APP
            or not native.condition(parent, 'ParametersGenerated') or native.condition(parent, 'ErrorOccurred')
            or owners != [{'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'ApplicationSet', 'name': APP,
                'uid': parent['metadata']['uid'], 'controller': True, 'blockOwnerDeletion': True}]):
        raise RuntimeError('Native identity parent, project or exact controller ownership changed')
    before = {kind: (get(kind, 'cloudlab-identity-installation-source', 'argocd') or {}).get('metadata', {}).get('uid')
        for kind in ('externalsecret.external-secrets.io', 'secret')}
    native.source_credentials(target['valuesRepository'], 'cloudlab-identity-installation-source', APP)
    observed = {'parent_uid': parent['metadata']['uid'],
        'reader_uid': get('externalsecret.external-secrets.io', 'cloudlab-identity-installation-source', 'argocd')['metadata']['uid'],
        'secret_uid': get('secret', 'cloudlab-identity-installation-source', 'argocd')['metadata']['uid']}
    if before != {'externalsecret.external-secrets.io': observed['reader_uid'], 'secret': observed['secret_uid']}:
        raise RuntimeError('Native identity source credential changed during authentication')
    if captured['phase'] == 'accepted':
        if any(captured[key] != uid for key, uid in observed.items()):
            raise RuntimeError('Native identity parent or source credential was replaced')
    elif register:
        if current_values != captured['values'] or not application_ready(APP, INSTALLATION_REVISION):
            raise RuntimeError('Native identity adoption must preserve the complete prepared installation')
        from playbooks.data.files.control import atomic
        state['native'] = dict(captured, phase='accepted', **observed)
        atomic(path, state)
    else:
        raise RuntimeError('Complete native identity adoption through the retained owner before operations')
    return INSTALLATION_REVISION


def completed_job_retention(job, crons, retired, now):
    metadata, status = job.get('metadata', {}), job.get('status', {})
    if (metadata.get('namespace') != NAMESPACE or metadata.get('deletionTimestamp') or
            not metadata.get('uid') or not metadata.get('resourceVersion') or status.get('active') or
            job.get('spec', {}).get('ttlSecondsAfterFinished') is not None):
        return []
    finished = [c for c in status.get('conditions', []) if c.get('type') in ('Complete', 'Failed') and c.get('status') == 'True']
    if len(finished) != 1:
        return []
    try:
        successes = [datetime.fromisoformat(crons[name]['status']['lastSuccessfulTime'].replace('Z', '+00:00')).timestamp()
                     for name in ('identity-health', 'identity-reconcile')]
        completed = datetime.fromisoformat(finished[0]['lastTransitionTime'].replace('Z', '+00:00')).timestamp()
        if any(not 0 <= now - success <= 900 for success in successes) or completed >= min(successes):
            return []
        ttl = crons['identity-health']['spec']['jobTemplate']['spec']['ttlSecondsAfterFinished']
    except (KeyError, TypeError, ValueError):
        return []
    if type(ttl) is not int or not 300 <= ttl <= 86400:
        raise RuntimeError('Completed identity jobs require bounded declared retention')
    owners = metadata.get('ownerReferences', [])
    cron_owned = any(ref.get('kind') == 'CronJob' and ref.get('apiVersion') == 'batch/v1' and ref.get('controller') is True and
                     ref.get('name') in ('identity-health', 'identity-reconcile') and ref.get('uid') and
                     ref['uid'] == crons[ref['name']].get('metadata', {}).get('uid') for ref in owners)
    hook_owned = (retired and not owners and metadata.get('name') == 'identity-bootstrap-retirement' and
                  metadata.get('annotations', {}).get('argocd.argoproj.io/tracking-id') ==
                  APP + ':batch/Job:' + NAMESPACE + '/identity-bootstrap-retirement' and
                  job.get('spec', {}).get('template', {}).get('spec', {}).get('serviceAccountName') == 'identity-writer')
    if not cron_owned and not hook_owned:
        return []
    return [{'op': 'test', 'path': '/metadata/uid', 'value': metadata['uid']},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': metadata['resourceVersion']},
            {'op': 'add', 'path': '/spec/ttlSecondsAfterFinished', 'value': ttl}]


def check_private_owner(kind, actual, saved):
    metadata = actual.get('metadata', {}) if actual else {}
    finalizers = metadata.get('finalizers') or []
    expected = ['externalsecrets.external-secrets.io/externalsecret-cleanup'] if kind == 'ExternalSecret' else []
    if (saved and (not actual or metadata.get('uid') != saved)) or (actual and (
            metadata.get('labels', {}).get('cloudlab.io/owner') != OWNER or
            (finalizers and finalizers != expected) or metadata.get('ownerReferences') or
            metadata.get('deletionTimestamp'))):
        raise RuntimeError('Private identity source owner conflicts or changed identity')


def private_resources(payload):
    name = 'cloudlab-identity-private'
    metadata = lambda: {'name': name, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}}
    project = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'AppProject', 'metadata': metadata(),
        'spec': {'sourceRepos': [payload['private_repository']],
            'destinations': [{'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE}],
            'clusterResourceWhitelist': [], 'namespaceResourceWhitelist': [{'group': '', 'kind': 'ConfigMap'}]}}
    credential = {'apiVersion': 'external-secrets.io/v1', 'kind': 'ExternalSecret', 'metadata': metadata(),
        'spec': {'refreshInterval': '24h', 'secretStoreRef': {'name': 'cloudlab', 'kind': 'ClusterSecretStore'},
            'target': {'name': name, 'creationPolicy': 'Owner', 'deletionPolicy': 'Retain',
                'template': {'engineVersion': 'v2', 'mergePolicy': 'Replace',
                    'metadata': {'labels': {'argocd.argoproj.io/secret-type': 'repository'}},
                    'data': {'type': 'git', 'url': payload['private_repository'], 'project': name,
                        'githubAppID': '{{ .APP_ID }}', 'githubAppInstallationID': '{{ .INSTALLATION_ID }}',
                        'githubAppPrivateKey': PEM_TEMPLATE}}},
            'dataFrom': [{'extract': {'key': 'github-argocd'}}]}}
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application', 'metadata': metadata(),
        'spec': {'project': name, 'source': {'repoURL': payload['private_repository'],
                'targetRevision': payload['private_branch'], 'path': 'identity',
                'directory': {'include': 'configmap.yaml'}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true']}}}
    return [project, credential, app]


def discover():
    import base64
    import ipaddress
    certificate = get('certificate.cert-manager.io', 'cloudlab-gateway', 'cloudlab-gateway-private')
    if not condition(certificate, 'Ready'):
        raise RuntimeError('Independent private TLS must be ready before identity')
    names = certificate['spec']['dnsNames']
    if (len(names) != 2 or not names[0].startswith('*.internal.') or
            names[1] != 'login.' + names[0][11:]):
        raise RuntimeError('Private TLS domain contract changed')
    domain = names[0][11:]
    proxies = []
    nodes = {node['metadata']['name']: node for node in get('nodes')['items']}
    for namespace in ('cloudlab-gateway-public', 'cloudlab-gateway-private'):
        for pod in get('pods', namespace=namespace)['items']:
            if pod['metadata'].get('labels', {}).get('gateway.networking.k8s.io/gateway-name') == 'cloudlab':
                value = pod.get('status', {}).get('podIP')
                if value:
                    address = ipaddress.ip_address(value)
                    ranges = nodes[pod['spec']['nodeName']]['spec'].get('podCIDRs') or [nodes[pod['spec']['nodeName']]['spec']['podCIDR']]
                    matching = [ipaddress.ip_network(cidr, strict=True) for cidr in ranges
                                if ipaddress.ip_network(cidr, strict=True).version == address.version
                                and address in ipaddress.ip_network(cidr, strict=True)]
                    if len(matching) != 1 or pod['spec'].get('hostNetwork'):
                        raise RuntimeError('Gateway proxy source must belong to its verified node Pod range')
                    # Gateway-only NetworkPolicy selects the peers; node Pod ranges
                    # retain forwarding trust when the sole gateway owner replaces Pods.
                    proxies.append(str(matching[0]))
    if not proxies:
        raise RuntimeError('Verified gateway proxy peers are unavailable')
    cluster = get('cluster.postgresql.cnpg.io', 'cloudlab-postgres', 'cloudlab-data')
    ca = get('secret', 'cloudlab-postgres-ca', 'cloudlab-data')
    database = get('database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data')
    if not condition(cluster, 'Ready') or not ca or not database:
        raise RuntimeError('Ready CNPG database and certificate authority are required')
    if not any(ref.get('uid') == cluster['metadata']['uid'] for ref in ca['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Database CA is not owned by the verified CNPG cluster')
    return {'loginHost': 'login.' + domain, 'adminHost': 'identity-admin.internal.' + domain,
            'database': database['spec']['name'], 'databaseRole': database['spec']['owner'],
            'databaseHost': 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local', 'databasePort': 5432,
            'databaseCA': base64.b64decode(ca['data']['ca.crt'], validate=True).decode(),
            'trustedProxyAddresses': sorted(set(proxies))}


def application(payload, phase, retired=False, retired_item=''):
    import ipaddress
    if phase not in PHASES:
        raise ValueError('Unsupported identity bootstrap phase')
    if type(retired) is not bool or (retired and phase != 'scoped'):
        raise ValueError('Retired bootstrap access requires normal scoped reconciliation')
    import re
    if (retired and not re.fullmatch('keycloak-emergency-[a-f0-9]{32}', retired_item)) or (not retired and retired_item):
        raise ValueError('Retirement requires its persistent ESO credential owner')
    values = payload['values']
    allowed = set(INSTALLATION_FIELDS)
    if set(values) != allowed:
        raise ValueError('Runtime identity requires its complete bounded input contract')
    for key in ('loginHost', 'adminHost'):
        exact_url('https://' + values[key] + '/')
        if '/' in values[key] or ':' in values[key]:
            raise ValueError('Identity host must be a DNS name')
    if (not values['loginHost'].startswith('login.') or
            values['adminHost'] != 'identity-admin.internal.' + values['loginHost'][6:]):
        raise ValueError('Identity hosts must use the designated owned-domain contract')
    for key in ('database', 'databaseRole'):
        identity(values[key])
    if (values['databaseHost'] != 'cloudlab-postgres-rw.cloudlab-data.svc.cluster.local'
            or values['databasePort'] != 5432 or not values['databaseCA'] or not values['trustedProxyAddresses']):
        raise ValueError('Identity requires the verified CNPG TLS and proxy-peer inputs')
    if not isinstance(values['trustedProxyAddresses'], list) or not 1 <= len(values['trustedProxyAddresses']) <= 8:
        raise ValueError('Proxy trust must contain a bounded exact peer inventory')
    for value in values['trustedProxyAddresses']:
        network = ipaddress.ip_network(value, strict=True)
        if network.prefixlen < (24 if network.version == 4 else 64) or not network.network_address.is_private:
            raise ValueError('Proxy trust must use bounded verified private gateway Pod ranges')
    desired = dict(values, enabled=True, operatorEnabled=False, serverEnabled=True,
                   maintenance=False, reconciliationEnabled=phase != 'server', bootstrapMode=phase in ('bootstrap', 'primary'),
                   primaryAdminEnabled=phase == 'primary', privateStateEnabled=phase != 'server', bootstrapAdminEnabled=not retired)
    desired['telemetryEnabled'] = payload.get('telemetry_enabled', False)
    if retired:
        desired['retiredEmergencyItem'] = retired_item
    return {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': APP, 'namespace': 'argocd', 'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': APP, 'source': {'repoURL': payload['repository'], 'targetRevision': payload['branch'],
            'path': 'platform/identity/keycloak', 'helm': {'releaseName': APP, 'valuesObject': desired}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': NAMESPACE},
            'syncPolicy': {'automated': {'enabled': True, 'prune': False, 'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true',
                                'RespectIgnoreDifferences=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '30s', 'factor': 2, 'maxDuration': '2m'}}}}}


def prerequisites(payload, *, access_recovery=None):
    # Require recovery evidence on disk; controller health alone is insufficient.
    backup = json.loads(Path('/var/lib/cloudlab/application-data/longhorn-monthly-receipt.json').read_text())
    if not backup.get('retention_complete') or not backup.get('restore', {}).get('physical_restore'):
        raise RuntimeError('Verified CNPG physical recovery must precede identity')
    access = json.loads(Path('/var/lib/cloudlab/connectivity/receipts/acceptance.json').read_text())
    if not access.get('verified_at') or not access.get('external_binding'):
        raise RuntimeError('Independent public/private access proof must precede identity')
    for name in ('cloudlab-keycloak-operator', 'cloudlab-argocd'):
        if not application_ready(name, payload['revision']):
            raise RuntimeError('Identity prerequisite Application is not converged')
    from playbooks.access.files.native import prerequisite as access_prerequisite
    access_prerequisite(payload, recovery=access_recovery)
    from playbooks.data.files.native import prerequisite as data_prerequisite
    data = data_prerequisite(payload, recovery=access_recovery)
    if data.get('identity') != {'enabled': True, 'database': payload['values']['database'], 'role': payload['values']['databaseRole']}:
        raise RuntimeError('Identity dedicated CNPG contract is not enabled by its data owner')
    database = get('database.postgresql.cnpg.io', 'keycloak', 'cloudlab-data') or {}
    if (not database.get('status', {}).get('applied') or
            database.get('status', {}).get('observedGeneration') != database.get('metadata', {}).get('generation')):
        raise RuntimeError('Dedicated identity database is not ready')


def private_inputs(payload):
    import base64
    app = get('application.argoproj.io', 'cloudlab-identity-private', 'argocd') or {}
    revision = app.get('status', {}).get('sync', {}).get('revision')
    if (app.get('spec', {}).get('source', {}).get('repoURL') != payload['private_repository'] or
            not revision or not application_ready('cloudlab-identity-private', revision)):
        raise RuntimeError('Required private identity source is unavailable or not converged; no realm imports allowed')
    private = get('configmap', 'identity-private-state', NAMESPACE)
    secrets = get('secret', 'keycloak-client-secrets', NAMESPACE)
    if not private or not secrets:
        raise RuntimeError('Ready private inventory and vault client credentials are required')
    if not private['metadata'].get('annotations', {}).get('argocd.argoproj.io/tracking-id', '').startswith('cloudlab-identity-private:'):
        raise RuntimeError('Private inventory must belong to its designated Argo source')
    external = get('externalsecret.external-secrets.io', 'keycloak-client-secrets', NAMESPACE)
    if not condition(external, 'Ready') or not any(ref.get('uid') == external['metadata']['uid']
            for ref in secrets['metadata'].get('ownerReferences', [])):
        raise RuntimeError('Client credentials must be owned by ready ESO')
    source = json.loads(private['data']['desired_state'])
    revoked = json.loads(private['data']['revocations'])
    credentials = json.loads(base64.b64decode(secrets['data']['client_secrets'], validate=True))
    for realm in ('platform', 'applications'):
        compile_state(realm, payload['values']['loginHost'], source, credentials, revoked)
    return source, revoked, revision


def branch_handoff_patches(current, desired, retirement):
    if (not retirement or current['spec']['source']['targetRevision'] != retirement['revision'] or
            current['spec']['source']['targetRevision'] == desired['spec']['source']['targetRevision']):
        return []
    values = current['spec']['source']['helm']['valuesObject']
    if (retirement.get('phase') != 'accepted' or current['metadata']['uid'] != retirement['application_uid'] or
            current.get('operation') or values.get('maintenance') or values.get('operation')):
        raise RuntimeError('Branch handoff requires accepted retirement and an idle unchanged Application')
    # The phase's Update ownership otherwise conflicts with normal server-side Apply.
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': retirement['application_uid']},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': current['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/spec/source/targetRevision', 'value': retirement['revision']},
        {'op': 'replace', 'path': '/spec/source/targetRevision',
         'value': desired['spec']['source']['targetRevision']}]


def enrollment_handoff(current, state, directory):
    """Only a completed nonce-owned enrollment may release its source pin."""
    revision = current['spec']['source']['targetRevision']
    if not state or revision != state.get('revision'):
        return None
    accepted = []
    for path in directory.glob('proof-*.json'):
        record = json.loads(path.read_text())
        nonce = record.get('nonce')
        if (not isinstance(nonce, str) or not re.fullmatch('[a-f0-9]{32}', nonce) or
                path.name != 'proof-'+nonce+'.json'):
            raise RuntimeError('Disposable source checkpoint identity is malformed')
        if record.get('revision') == revision and record.get('phase') in ('prepared', 'created'):
            raise RuntimeError('Complete pending disposable enrollment before source handoff')
        if record.get('phase') == 'enrolled' and record.get('revision') == revision:
            if record.get('application_uid') != state['uid'] or not record.get('user_id'):
                raise RuntimeError('Disposable source checkpoint resource identity changed')
            accepted.append(record)
    if not accepted:
        return None
    return {'phase':'accepted','revision':revision,'application_uid':state['uid']}
