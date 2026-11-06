"""Qualify one native Namespace guard candidate in an isolated local cluster.

Use compose.namespace-proof.yaml with one unique namespace-proof-<run> project:
  docker compose -p <project> -f <file> up -d cluster
  docker compose -p <project> -f <file> run --build --rm -T proof prepare
Inspect the exact cluster ID from `docker compose ... ps -q cluster`, then:
  docker inspect <cluster-ID> | docker compose ... run --rm -T proof before
  docker compose ... run -d --name <unique-monitor> proof monitor
Wait for `docker compose ... run --rm -T proof status` to report armed.
Restart ONLY the ID accepted by before: `docker restart <cluster-ID>`.
  docker inspect <cluster-ID> | docker compose ... run --rm -T proof after
  docker wait <unique-monitor>
Require exit 0 and status complete. No Docker socket is mounted in the proof.
After inspecting its project/purpose labels, remove the exited monitor ID with
`docker rm <unique-monitor>` before removing project volumes.
Inspect exact project/purpose resources, preserve failed receipts, then remove
only that project with `docker compose ... down --volumes`.
"""
import copy
from datetime import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

from playbooks.admission.files.chart import render
from playbooks.admission.files.verify import NAMESPACE_GUARD_NAME, namespace_guard_desired, namespace_guard_denied, namespace_guard_validate
from playbooks.admission.tests.fixtures import namespace
from playbooks.argocd.tests.fixtures import NativeAPI, require

STATE = Path('/receipts/state.json')
ROOT = Path(__file__).resolve().parents[4]
ADMISSION = '/apis/admissionregistration.k8s.io/v1/'
PURPOSE = 'namespace-startup-proof'


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def read(path):
    raw = path.read_bytes()
    require(len(raw) <= 65536, 'Fixture record exceeds bound')
    return json.loads(raw)


def save(path, value):
    pending = path.with_suffix('.pending')
    pending.write_text(json.dumps(value, sort_keys=True))
    pending.chmod(0o600)
    os.replace(pending, path)


def project():
    value = os.environ.get('FIXTURE_PROJECT', '')
    require(re.fullmatch(r'namespace-proof-[a-z0-9][a-z0-9-]{0,39}', value), 'Use a unique namespace-proof-<run> project')
    return value


def state():
    value = read(STATE)
    require(value['version'] == 1 and value['project'] == project() and
        value['candidateSHA256'] == fingerprint(namespace_guard_desired()) and
        value['driverSHA256'] == hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'Fixture candidate or project changed')
    return value


def inspect_cluster(value, expected_project):
    """Consume Docker CLI inspection data without granting the proof daemon access."""
    require(isinstance(value, list) and len(value) == 1, 'Inspect exactly one fixture cluster')
    row = value[0]
    labels = row.get('Config', {}).get('Labels', {})
    expected_image = yaml.safe_load((ROOT / 'ansible/playbooks/access/tests/compose.permissions-proof.yaml').read_text())['services']['cluster']['image']
    mounts = row.get('Mounts', [])
    data = [item for item in mounts if item.get('Destination') == '/fixture']
    networks = row.get('NetworkSettings', {}).get('Networks', {})
    require(re.fullmatch('[a-f0-9]{64}', row.get('Id', '')) and
        labels.get('com.docker.compose.project') == expected_project and
        labels.get('com.docker.compose.service') == 'cluster' and labels.get('cloudlab.io/purpose') == PURPOSE and
        row.get('Config', {}).get('Image') == expected_image and row.get('State', {}).get('Running') is True and
        '--data-dir=/fixture/cluster-data' in row.get('Config', {}).get('Cmd', []) and len(data) == 1 and
        data[0].get('Type') == 'volume' and data[0].get('Name') == expected_project + '_credentials' and data[0].get('RW') is True and
        all(item.get('Type') == 'tmpfs' or item.get('Type') == 'volume' and (item.get('Name') == expected_project + '_credentials' or
            re.fullmatch('[a-f0-9]{64}', item.get('Name', ''))) for item in mounts) and
        set(networks) == {expected_project + '_fixture'} and networks[expected_project + '_fixture'].get('IPAddress') == '10.245.240.2',
        'Restart inspection does not identify the exact owned pinned fixture cluster and data mount')
    started = row['State']['StartedAt']
    require(isinstance(started, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z', started) and
        datetime.fromisoformat(started).timestamp() > 0 and re.fullmatch('sha256:[a-f0-9]{64}', row.get('Image', '')),
        'Fixture cluster start time is invalid')
    return {'id': row['Id'], 'project': expected_project, 'purpose': PURPOSE, 'image': expected_image,
        'imageID': row['Image'], 'dataVolume': data[0]['Name'], 'startedAt': started,
        'volumes': sorted([item['Name'], item['Destination']] for item in mounts if item.get('Type') == 'volume')}


class API(NativeAPI):
    def probe(self, document, update=False):
        require(document.get('apiVersion') == 'v1' and document.get('kind') == 'Namespace' and
            re.fullmatch(r'(?:cloudlab-app-|external-)native-proof-[a-f0-9]{8}-[a-z-]+', document['metadata']['name']),
            'Namespace probe escaped its fixed synthetic scope')
        path = '/api/v1/namespaces' + ('/' + document['metadata']['name'] if update else '')
        request = urllib.request.Request('https://cluster:6443' + path + '?dryRun=All&fieldValidation=Strict',
            method='PUT' if update else 'POST', data=json.dumps(document).encode(), headers={'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=5) as response:
                require(response.status in (200, 201), 'Unexpected Namespace probe success status')
                return response.status, ''
        except urllib.error.HTTPError as error:
            body = error.read(8193)
            require(len(body) <= 8192, 'Namespace denial exceeds bound')
            return error.code, body.decode('utf-8')


def client(directory):
    stop = time.monotonic() + 180
    while time.monotonic() < stop:
        try:
            document = yaml.safe_load(Path('/fixture/kubeconfig').read_text())
            if isinstance(document, dict) and document.get('users') and document.get('clusters'):
                return API(directory, document, field_manager='namespace-startup-fixture')
        except (OSError, ValueError, yaml.YAMLError):
            pass
        time.sleep(0.5)
    raise RuntimeError('Fixture credentials did not become available')


def guard_path(kind):
    return ADMISSION + ('validatingadmissionpolicies' if kind == 'ValidatingAdmissionPolicy' else
                        'validatingadmissionpolicybindings') + '/' + NAMESPACE_GUARD_NAME


def identities(api, names):
    rows = {'clusterNamespace': api.request('/api/v1/namespaces/kube-system')}
    rows.update({row['kind']: api.request(guard_path(row['kind'])) for row in namespace_guard_desired()})
    rows.update({name: api.request('/api/v1/namespaces/' + name) for name in names})
    return {name: row['metadata']['uid'] for name, row in rows.items()}


def denial_evidence(case, code, diagnostic, message):
    require(isinstance(case, str) and re.fullmatch(r'[A-Za-z0-9./_-]{1,96}', case), 'Invalid synthetic probe case')
    try:
        body = json.loads(diagnostic)
    except ValueError:
        body = {}
    body = body if isinstance(body, dict) else {}
    text = body.get('message', '')
    text = text if isinstance(text, str) else ''
    return {'case': case, 'httpCode': code,
        'statusMatches': code == 422 and body.get('kind') == 'Status' and body.get('status') == 'Failure' and
            body.get('reason') == 'Invalid' and type(body.get('code')) is int and body['code'] == 422,
        'attributionMatches': namespace_guard_denied(text, ''), 'messageMatches': message in text}


def native_denial(evidence):
    return all(evidence[key] for key in ('statusMatches', 'attributionMatches', 'messageMatches'))


def deny(api, document, message, update=False, *, case):
    code, diagnostic = api.probe(document, update)
    evidence = denial_evidence(case, code, diagnostic, message)
    value = read(STATE)
    value['lastProbe'] = evidence
    save(STATE, value)
    require(native_denial(evidence), 'Namespace violation lacks exact typed native policy and binding denial')


def allow(api, document, update=False):
    require(api.probe(document, update)[0] in (200, 201), 'Supported Namespace operation was not admitted')


def guard_snapshot(api):
    documents = [api.request(guard_path(row['kind'])) for row in namespace_guard_desired()]
    namespace_guard_validate(documents)
    require(all(row['metadata'].get('uid') and row['metadata'].get('generation') for row in documents),
            'Initial guard identity is incomplete')
    return [{'uid': row['metadata']['uid'], 'generation': row['metadata']['generation'],
             'spec': copy.deepcopy(row['spec']), 'annotations': copy.deepcopy(row['metadata']['annotations'])}
            for row in documents]


def qualify_initial_install(probe, unchanged, record, message, *, clock=time.monotonic, pause=time.sleep):
    """Journal first-install dispatch separately; strict matrix and restart never settle."""
    started = clock()
    stop = started + 30
    for attempt in range(16):
        require(clock() < stop, 'Initial Namespace dispatch exceeded its bounded deadline')
        unchanged()
        require(clock() < stop, 'Initial Namespace dispatch exceeded its bounded deadline')
        try:
            code, diagnostic = probe()
            evidence = denial_evidence('initial-install', code, diagnostic, message)
            evidence.update(unsafeAdmission=code in (200, 201), knownUnavailable=server_unavailable(code, diagnostic))
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            reason = error.reason if isinstance(error, urllib.error.URLError) else error
            evidence = {'case': 'initial-install', 'httpCode': None, 'statusMatches': False,
                'attributionMatches': False, 'messageMatches': False, 'unsafeAdmission': False,
                'knownUnavailable': unavailable(error) and not isinstance(reason, ssl.SSLError), 'errorType': type(error).__name__}
        evidence.update(attempt=attempt + 1, elapsedSeconds=round(clock() - started, 3))
        record(evidence)
        unchanged()
        require(clock() < stop, 'Initial Namespace dispatch exceeded its bounded deadline')
        if native_denial(evidence):
            return
        require(evidence['unsafeAdmission'] or evidence['knownUnavailable'],
                'Unexpected failure during initial Namespace dispatch qualification')
        pause(min(2, max(0, stop - clock())))
    raise RuntimeError('Initial Namespace dispatch remained unqualified after 16 attempts')


def prepare(api):
    require(not STATE.exists(), 'Existing receipt blocks a new proof')
    candidate = namespace_guard_desired()
    rendered = [row for row in render(True) if row['kind'] in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding') and
        row['metadata']['name'] == NAMESPACE_GUARD_NAME]
    require(sorted(rendered, key=lambda row: row['kind']) == sorted(candidate, key=lambda row: row['kind']),
        'Rendered native candidate differs from declared Namespace contract')
    value = {'version': 1, 'project': project(), 'phase': 'preparing', 'run': secrets.token_hex(4),
        'candidateSHA256': fingerprint(candidate), 'driverSHA256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    save(STATE, value)
    stop = time.monotonic() + 180
    while True:
        try:
            api.request('/api/v1/namespaces/kube-system')
            break
        except (OSError, urllib.error.URLError, RuntimeError):
            require(time.monotonic() < stop, 'Fixture API did not become available')
            time.sleep(0.5)
    require(all(api.absent(guard_path(row['kind'])) for row in candidate), 'Native candidate already exists')
    prefix = 'cloudlab-app-native-proof-' + value['run'] + '-'
    fixtures = {key: namespace(prefix + key, composition=key == 'composition')
                for key in ('ordinary', 'composition', 'unowned', 'foreign', 'migration')}
    fixtures['unowned']['metadata'].pop('labels')
    fixtures['foreign']['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
    fixtures['migration']['metadata']['labels'] = {'cloudlab.io/owner': 'service-platform'}
    fixtures['outside'] = namespace('external-native-proof-' + value['run'] + '-owned')
    for key, document in fixtures.items(): fixtures[key] = api.apply(document)
    for row in copy.deepcopy(candidate):
        row['metadata']['annotations']['argocd.argoproj.io/tracking-id'] = (
            'cloudlab-workload-policy:admissionregistration.k8s.io/' + row['kind'] + ':cloudlab-policy/' + NAMESPACE_GUARD_NAME)
        api.apply(row)
    stop = time.monotonic() + 60
    while True:
        try:
            namespace_guard_validate([api.request(guard_path(row['kind'])) for row in candidate])
            break
        except RuntimeError:
            require(time.monotonic() < stop, 'Native candidate type-checking did not converge')
            time.sleep(0.2)
    messages = [row['message'] for row in candidate[0]['spec']['validations']]
    value['initialInstall'] = {'attempts': [], 'unsafeAdmissionCount': 0, 'knownUnavailableCount': 0, 'qualified': False}
    save(STATE, value)
    snapshot = guard_snapshot(api)
    value['initialInstall']['guardSnapshot'] = snapshot
    save(STATE, value)
    def unchanged():
        require(guard_snapshot(api) == snapshot, 'Initial Namespace guard identity or specification changed')
    def record(evidence):
        journal = value['initialInstall']
        journal['attempts'].append(evidence)
        journal['unsafeAdmissionCount'] += int(evidence['unsafeAdmission'])
        journal['knownUnavailableCount'] += int(evidence['knownUnavailable'])
        save(STATE, value)
    initial = namespace(prefix + 'initial')
    initial['metadata']['labels']['cloudlab.io/owner'] = 'foreign'
    qualify_initial_install(lambda: api.probe(initial), unchanged, record, messages[0])
    value['initialInstall']['qualified'] = True
    save(STATE, value)
    good = namespace(prefix + 'fresh')
    allow(api, good)
    allow(api, namespace(prefix + 'static-composition', composition=True))
    unrelated = {'apiVersion': 'v1', 'kind': 'Namespace', 'metadata': {'name': 'external-native-proof-' + value['run'] + '-unrelated'}}
    allow(api, unrelated)
    checks = 3
    for key in good['metadata']['labels']:
        for remove in (False, True):
            bad = copy.deepcopy(good)
            if remove: del bad['metadata']['labels'][key]
            else: bad['metadata']['labels'][key] = ('privileged' if key == 'pod-security.kubernetes.io/enforce' else
                'latest' if key == 'pod-security.kubernetes.io/enforce-version' else 'foreign')
            deny(api, bad, messages[1] if key == 'pod-security.kubernetes.io/enforce' and not remove else messages[0],
                 case='baseline-' + key + ('-remove' if remove else '-change'))
            checks += 1
    bad = copy.deepcopy(good); bad['metadata'].pop('labels')
    deny(api, bad, messages[0], case='baseline-all-labels-remove'); checks += 1
    for key in ('cloudlab.io/composition', 'pod-security.kubernetes.io/audit', 'pod-security.kubernetes.io/warn'):
        bad = namespace(prefix + 'bad-composition', composition=True)
        bad['metadata']['labels'][key] = 'foreign' if key == 'cloudlab.io/composition' else 'privileged'
        deny(api, bad, messages[1], case='composition-' + key + '-change'); checks += 1
    for key in ('ordinary', 'composition'):
        old = fixtures[key]
        changed = copy.deepcopy(old)
        changed['metadata'].setdefault('annotations', {})['example.invalid/review'] = 'synthetic'
        changed['metadata']['finalizers'] = ['example.invalid/cleanup']
        allow(api, changed, True); checks += 1
        changed['metadata'].pop('labels')
        deny(api, changed, messages[0], True, case=key + '-all-labels-remove'); checks += 1
    for key in ('unowned', 'foreign'):
        changed = copy.deepcopy(fixtures[key]); changed['metadata']['labels'] = copy.deepcopy(good['metadata']['labels'])
        deny(api, changed, messages[2], True, case='adoption-' + key); checks += 1
    changed = copy.deepcopy(fixtures['outside']); changed['metadata'].pop('labels')
    deny(api, changed, messages[0], True, case='previous-owner-selection'); checks += 1
    for key in ('composition', 'migration'):
        changed = copy.deepcopy(fixtures[key]); changed['metadata']['labels'] = copy.deepcopy(good['metadata']['labels'])
        allow(api, changed, True); checks += 1
    value = read(STATE)
    value.update(phase='prepared', checks=checks, namespaces=[row['metadata']['name'] for row in fixtures.values()],
        identities=identities(api, [row['metadata']['name'] for row in fixtures.values()]),
        unsafe=bad, positive=good, denialMessage=messages[1],
        limits=['local pinned API server, Kyverno absent', 'static Namespace contract only; no composition lookup qualification',
                'label-based owner only; no authenticated historical ownership', 'one controlled restart; no general timing guarantee',
                'initial install dispatch qualification is not an activation interlock; prequalification admissions are unsafe'])
    save(STATE, value)


def record_inspection(after=False):
    value = state()
    require(value['phase'] == ('armed' if after else 'prepared'), 'Restart inspection is out of phase')
    raw = sys.stdin.buffer.read(65537)
    require(len(raw) <= 65536, 'Docker inspection exceeds bound')
    inspection = inspect_cluster(json.loads(raw), value['project'])
    target = STATE.parent / ('after.json' if after else 'before.json')
    require(not target.exists(), 'Existing restart evidence cannot be replaced')
    if after:
        before = read(STATE.parent / 'before.json')
        require({key: item for key, item in before.items() if key != 'startedAt'} ==
            {key: item for key, item in inspection.items() if key != 'startedAt'} and
            datetime.fromisoformat(inspection['startedAt']).timestamp() > datetime.fromisoformat(before['startedAt']).timestamp() and
            datetime.fromisoformat(inspection['startedAt']).timestamp() >= value['armedAt'],
            'Restart evidence changed fixture identity or predates the armed monitor')
    save(target, inspection)
    print(json.dumps({'restartContainerID': inspection['id'], 'phase': 'after' if after else 'before'}))


def unavailable(error):
    reason = error.reason if isinstance(error, urllib.error.URLError) else error
    return isinstance(reason, (ConnectionError, TimeoutError, socket.gaierror, ssl.SSLEOFError,
                              http.client.RemoteDisconnected, http.client.IncompleteRead))


def server_unavailable(code, diagnostic):
    try:
        body = json.loads(diagnostic)
    except ValueError:
        return False
    return (isinstance(body, dict) and body.get('kind') == 'Status' and body.get('status') == 'Failure' and
        code in (503, 504) and body.get('reason') in ('ServiceUnavailable', 'ServerTimeout', 'Timeout'))


def monitor(api):
    value = state()
    require(value['phase'] == 'prepared' and (STATE.parent / 'before.json').exists(), 'Prepare and inspect the exact cluster before monitoring')
    require(identities(api, value['namespaces']) == value['identities'], 'Prepared fixture identity changed')
    value.update(phase='armed', armedAt=time.time(), denied=0, unavailable=0)
    save(STATE, value)
    stop = time.monotonic() + 180
    while time.monotonic() < stop:
        denied = False
        try:
            code, diagnostic = api.probe(value['unsafe'])
            value['lastHTTPStatus'] = code
            value['lastProbe'] = denial_evidence('restart-unsafe-create', code, diagnostic, value['denialMessage'])
            save(STATE, value)
            if server_unavailable(code, diagnostic): value['unavailable'] += 1
            else:
                require(native_denial(value['lastProbe']),
                    'Unsafe Namespace was admitted or lacked exact native attribution during restart')
                value['denied'] += 1
                denied = True
        except (OSError, urllib.error.URLError, http.client.HTTPException) as error:
            require(unavailable(error), 'Unexpected transport or TLS failure during restart')
            value['unavailable'] += 1
        if (STATE.parent / 'after.json').exists() and denied:
            require(value['unavailable'] > 0, 'Monitor did not observe restart unavailability')
            require(identities(api, value['namespaces']) == value['identities'], 'Cluster or policy identity changed across restart')
            namespace_guard_validate([api.request(guard_path(row['kind'])) for row in namespace_guard_desired()])
            allow(api, value['positive'])
            value.update(phase='complete', restart=read(STATE.parent / 'after.json'), elapsedSeconds=round(180 - (stop - time.monotonic()), 3))
            save(STATE, value)
            return
        time.sleep(0.1)
    raise RuntimeError('Native restart proof exceeded its bounded recovery window')


def main():
    os.umask(0o077)
    require(len(sys.argv) == 2 and sys.argv[1] in ('prepare', 'before', 'monitor', 'after', 'status'), 'Select one explicit proof phase')
    phase = sys.argv[1]
    if phase in ('before', 'after'):
        record_inspection(phase == 'after')
    elif phase == 'status':
        value = state()
        print(json.dumps({key: value[key] for key in ('phase', 'candidateSHA256', 'checks') if key in value}))
    else:
        with tempfile.TemporaryDirectory() as directory:
            api = client(Path(directory))
            try:
                (prepare if phase == 'prepare' else monitor)(api)
            except Exception as error:
                if STATE.exists():
                    value = read(STATE); value.update(failurePhase=value['phase'], phase='failed', failureType=type(error).__name__)
                    if isinstance(error, RuntimeError): value['failure'] = str(error)[:256]
                    save(STATE, value)
                raise


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Native Namespace proof incomplete; inspect the exact fixture receipt; diagnostics withheld') from None
