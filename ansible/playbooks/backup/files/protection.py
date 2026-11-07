"""Accepted protection profiles, private bindings, and delivery planning.

Public profiles (platform/recovery/profiles.yaml) select existing coordinated
capture, retention, and write windows from their owning contracts; they define
no new schedule. Private bindings (services/<name>/protection.yaml) attach
protected resources and destination references. This module validates both,
compiles the exact host policy/timer bytes and Longhorn parity expectations,
and guards every delivery plan. It never restores, deletes, exports, or starts
a recovery job. Control machine only; never installed on hosts.
"""
import hashlib
import json
from pathlib import Path
import re

import yaml
from jsonschema import validate

ROOT = Path(__file__).resolve().parents[4]
RECOVERY = ROOT / 'platform/recovery'
PROFILES_SCHEMA = RECOVERY / 'profiles.schema.json'
BINDING_SCHEMA = RECOVERY / 'protection.schema.json'
BACKUP_POLICY = Path(__file__).resolve().parent / 'policy.json'
LONGHORN_POLICY = ROOT / 'platform/storage/longhorn-backup/policy.json'

PROFILE = 'coordinated-monthly'
# Setup byte order for the installed host policy; the reconciler compiles the
# identical bytes so an unchanged profile plans zero actions.
HOST_POLICY_KEYS = ('calendar', 'freshness_calendar', 'max_age_seconds',
                     'max_archive_bytes', 'max_source_bytes', 'staging_ceiling_bytes',
                     'minimum_free_fraction', 'password_item', 'prefix', 'tag')
CAMEL = {'calendar': 'calendar', 'freshness_calendar': 'freshnessCalendar',
         'max_age_seconds': 'maxAgeSeconds', 'max_archive_bytes': 'maxArchiveBytes',
         'max_source_bytes': 'maxSourceBytes', 'staging_ceiling_bytes': 'stagingCeilingBytes',
         'minimum_free_fraction': 'minimumFreeFraction', 'password_item': 'passwordItem',
         'prefix': 'prefix', 'tag': 'tag'}
HOST_POLICY_PATH = '/opt/cloudlab/playbooks/backup/files/policy.json'
HOST_CREDENTIALS_PATH = '/etc/cloudlab/recovery/credentials.json'
HOST_TIMERS = {'cloudlab-recovery': 'calendar',
               'cloudlab-recovery-freshness': 'freshnessCalendar'}
TIMER_DIR = '/etc/systemd/system'
JOB_LOCK = '/var/lib/cloudlab/recovery/job.lock'
FRESHNESS_TOOL = '/opt/cloudlab/playbooks/backup/files/backup.py'
# The only host mutations a protection plan may contain. There is no restore,
# delete, export, enable, or start action in this vocabulary.
PLAN_ACTIONS = frozenset({'write-policy', 'write-timer', 'daemon-reload',
                           'refresh-credentials'})
MANAGED_PATHS = frozenset({HOST_POLICY_PATH, HOST_CREDENTIALS_PATH} | {
    TIMER_DIR + '/' + name + '.timer' for name in HOST_TIMERS})

MONTHLY = re.compile(r'\*-\*-01 [0-9]{2}:[0-9]{2}:[0-9]{2} UTC')
FRESHNESS = re.compile(r'hourly|\*-\*-\* [0-9]{2}:[0-9]{2}:[0-9]{2} UTC')
TITLE = re.compile(r'[a-z][a-z0-9-]{0,99}')
MIN_CYCLE_SECONDS = 2419200  # 28 days: freshness spans a full monthly cycle.


def fail(message):
    raise ValueError(message)


def load_document(path):
    try:
        text = Path(path).read_text()
    except OSError:
        fail('Cannot read ' + str(path))
    try:
        if str(path).endswith('.json'):
            return json.loads(text)
        return yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        fail('Invalid YAML or JSON in ' + str(path))


def load_profiles(path=None):
    """Schema plus presence checks; returns the accepted profiles mapping."""
    document = load_document(Path(path) if path else RECOVERY / 'profiles.yaml')
    schema = json.loads(PROFILES_SCHEMA.read_text())
    try:
        validate(document, schema)
    except Exception as error:
        fail('Protection profiles violate their schema: ' + str(error).splitlines()[0])
    profiles = document['profiles']
    if PROFILE not in profiles:
        fail('Protection profiles must accept ' + PROFILE)
    return profiles


def catalog_requests(document):
    """Indexes catalog data requests and workloads for binding validation."""
    requests = {}
    for entry in document.get('catalog', []):
        if not isinstance(entry, dict):
            continue
        approval, definition = entry.get('approval', {}), entry.get('definition', {})
        name = approval.get('name') if isinstance(approval, dict) else None
        if not isinstance(name, str) or not isinstance(definition, dict):
            continue
        data = definition.get('data', {})
        if not isinstance(data, dict):
            continue
        requests[name] = {
            'database': {request.get('name') for kind, request in data.items()
                         if kind == 'database' and isinstance(request, dict)},
            'bucket': {request.get('name') for kind, request in data.items()
                       if kind == 'bucket' and isinstance(request, dict)},
            'workload': definition.get('name') if isinstance(definition.get('persistence'), dict)
            and definition['persistence'].get('enabled') is True else None,
        }
    return requests


def validate_binding(document, service, catalog):
    """Schema plus catalog checks; returns the normalized binding."""
    schema = json.loads(BINDING_SCHEMA.read_text())
    try:
        validate(document, schema)
    except Exception as error:
        fail('Protection binding violates its schema: ' + str(error).splitlines()[0])
    if document.get('service') != service:
        fail('Protection declaration must match its service directory: ' + service)
    declared = document['protection']
    if declared.get('profile') != PROFILE:
        fail('Unsupported protection profile: ' + service)
    requests = catalog.get(service, {})
    resources = []
    for resource in declared['resources']:
        kind, reference = resource['kind'], resource['reference']
        if kind == 'pvc':
            if reference != requests.get('workload'):
                fail('PVC protection must reference the approved workload: ' + service)
        elif reference not in requests.get(kind, set()):
            fail('Protection resource must match a catalog data request: ' + service)
        resources.append((kind, reference))
    if len(set(resources)) != len(resources):
        fail('Protection resources must be unique: ' + service)
    destination = declared['destinationReference']
    if not TITLE.fullmatch(destination or ''):
        fail('Invalid protection destination reference: ' + service)
    return {'service': service, 'profile': PROFILE, 'resources': resources,
            'destination': destination}


def compile_host_policy(profiles, profile=PROFILE):
    """Exact installed host policy plus timer calendars in setup byte order."""
    if profile not in profiles:
        fail('Unknown protection profile: ' + profile)
    control = profiles[profile]['controlPlane']
    policy = {key: control[CAMEL[key]] for key in HOST_POLICY_KEYS}
    timers = {name: control[field] for name, field in HOST_TIMERS.items()}
    return {'policy': policy, 'timers': timers}


def policy_bytes(policy):
    return (json.dumps(policy, indent=2) + '\n').encode()


def render_timer(name, calendar):
    """Exact timer unit bytes matching the setup template output.

    Jinja drops the template's trailing newline; Ansible renders the same
    default, so the reconciled bytes carry none either.
    """
    if name not in HOST_TIMERS:
        fail('Unknown recovery timer: ' + name)
    return ('[Unit]\nDescription=Cloudlab ' + name + ' schedule\n\n[Timer]\nOnCalendar='
            + calendar + '\nPersistent=false\nAccuracySec=1s\nUnit=' + name
            + '.service\n\n[Install]\nWantedBy=timers.target').encode()


def compile_longhorn(profiles, profile=PROFILE):
    """Expected chart schedule/retention fields for the parity check."""
    if profile not in profiles:
        fail('Unknown protection profile: ' + profile)
    owner = profiles[profile]['longhorn']
    return {key: owner[key] for key in ('job', 'cron', 'retain', 'concurrency', 'prefix')}


def check_longhorn_parity(compiled):
    """The profile must match the accepted chart policy; Argo owns delivery."""
    try:
        chart = json.loads(LONGHORN_POLICY.read_text())
    except (OSError, ValueError):
        fail('Longhorn backup policy is unavailable')
    for key, value in compiled.items():
        if chart.get('job_name' if key == 'job' else key) != value:
            fail('Protection profile diverges from the accepted Longhorn backup policy')
    return True


def coverage(binding, profiles, profile=PROFILE):
    """Per-resource coverage rows; PVCs stay uncovered until separately verified."""
    windows = {'database': ('application-data-module',
                             profiles[profile]['data']['monthlyCalendar']),
               'bucket': ('application-data-module',
                          profiles[profile]['data']['monthlyCalendar']),
               'pvc': ('longhorn-backup', profiles[profile]['longhorn']['cron'])}
    rows = []
    for kind, reference in binding['resources']:
        owner, window = windows[kind]
        if kind == 'pvc':
            rows.append({'kind': kind, 'reference': reference, 'coverage': 'uncovered',
                         'detail': 'service PVCs need separately verified backup coverage',
                         'owner': owner, 'window': window})
        else:
            rows.append({'kind': kind, 'reference': reference, 'coverage': 'covered',
                         'detail': 'data owner monthly export covers shared SQL/S3 volumes',
                         'owner': owner, 'window': window})
    return rows


def plan_guard(plan):
    """Refuse any plan that escapes the coordinated protection contract."""
    if set(plan.get('actions', ())) - PLAN_ACTIONS:
        fail('Protection plan carries an unowned action')
    policy, timers = plan['policy'], plan['timers']
    if not MONTHLY.fullmatch(policy['calendar'] or ''):
        fail('Monthly recovery must keep its coordinated day-1 UTC window')
    if sorted(timers) != sorted(HOST_TIMERS):
        fail('Protection plan must carry exactly the managed recovery timers')
    if not FRESHNESS.fullmatch(timers['cloudlab-recovery-freshness'] or ''):
        fail('Recovery freshness checks must run at least daily')
    if policy['max_age_seconds'] < MIN_CYCLE_SECONDS:
        fail('Recovery freshness must span a full monthly cycle')
    cron = plan['longhorn']['cron'].split()
    if len(cron) != 5 or cron[2] != '1':
        fail('Longhorn protection must keep its coordinated day-1 schedule')
    if plan['longhorn']['retain'] < 1 or plan['longhorn']['concurrency'] < 1:
        fail('Longhorn protection must retain its accepted schedule and retention')
    for owner in ('data', 'harbor'):
        block = plan[owner]
        if (block['remoteGenerations'] < 1
                or block['remoteMaxAgeSeconds'] < MIN_CYCLE_SECONDS
                or not MONTHLY.fullmatch(block['monthlyCalendar'] or '')):
            fail('Protection profile must keep its coordinated retention and windows')
    return plan


def plan_digest(plan):
    """Stable digest over the canonical planned change set for approval binding."""
    canonical = {'actions': sorted(plan['actions']),
                 'policy': hashlib.sha256(policy_bytes(plan['policy'])).hexdigest(),
                 'timers': {name: hashlib.sha256(render_timer(name, plan['timers'][name])).hexdigest()
                            for name in sorted(plan['timers'])},
                 'credentials': bool(plan.get('credentialsChanged'))}
    return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()


def binding_digest(profiles_bytes, bindings):
    """Stable digest over accepted profiles plus every binding's exact bytes."""
    digest = hashlib.sha256()
    digest.update(profiles_bytes)
    for service in sorted(bindings):
        digest.update(b'\0' + service.encode() + b'\0' + bindings[service])
    return digest.hexdigest()


def validate_approval(text, binding_hex):
    """Merged {binding, plan} approves exactly one input hash and plan digest."""
    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError:
        fail('Protection approval binding invalid; recovery retained')
    if (not isinstance(document, dict) or set(document) != {'binding', 'plan'}
            or not isinstance(document['binding'], str)
            or not isinstance(document['plan'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', document['binding'])
            or not re.fullmatch(r'[a-f0-9]{64}', document['plan'])):
        fail('Protection approval binding invalid; recovery retained')
    return binding_hex == document['binding'], document['plan']


def managed(path):
    if path not in MANAGED_PATHS:
        fail('Protection delivery refuses an unmanaged host path')
    return path


def stage_command(path, mode):
    """Stdin upload to a staging sibling; the caller verifies before finalizing."""
    return 'install -m %s /dev/stdin %s.protection-new' % (mode, managed(path))


def verify_command(path):
    return 'sha256sum ' + managed(path)


def verify_staged_command(path):
    return 'sha256sum ' + managed(path) + '.protection-new'


def finalize_command(path):
    return 'mv %s.protection-new %s' % (managed(path), managed(path))


def daemon_reload_command():
    return 'systemctl daemon-reload'


def list_timers_command():
    return ("ls -1 " + TIMER_DIR + " | grep -E '^cloudlab-recovery[^.]*\\.timer$' || true")


def timer_state_command(name):
    if name not in HOST_TIMERS:
        fail('Unknown recovery timer: ' + name)
    return 'systemctl show ' + name + '.timer -p ActiveState,UnitFileState --value'


def parse_timer_state(output):
    """Parse timer_state_command output; a wrong line count refuses delivery."""
    lines = output.splitlines()
    if len(lines) != 2:
        # Refused delivery uses RuntimeError like the reconciler's host-state gates.
        raise RuntimeError('Host recovery timer state is unreadable; refusing delivery')
    active, enabled = lines
    return {'active': active == 'active', 'enabled': enabled == 'enabled'}


def freshness_command():
    return 'python3 ' + FRESHNESS_TOOL + ' freshness'


def job_free_command():
    return 'flock -n ' + JOB_LOCK + ' true'


def read_command(path):
    return 'cat ' + managed(path) + ' 2>/dev/null || true'
