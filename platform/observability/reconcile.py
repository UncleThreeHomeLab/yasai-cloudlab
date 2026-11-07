"""Trusted independent uptime executor and external-owner status exporter.

Control-machine only: this service runs outside the monitored cluster. It
reads reviewed public uptime declarations at protected main, joins each with
its approved public exposure host and private notification binding, preflights
the live endpoint, and reconciles the owned UptimeRobot monitor. Merging the
declaration is the approval: standing reconciliation applies. Provider guards
(Free eligibility, registered-email contact, duplicate detection, explicit URL
migration, paused refusal, uncertain-mutation recovery) fail closed.
Unrelated monitors are never adopted; undeclared owned monitors are retained
and reported, never deleted.

Each cycle also exports redacted external-owner status snapshots per
infra/status.contract.json. Disabled, missing, future, or stale evidence
reports unavailable, never healthy.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

import yaml
from jsonschema import validate
from jsonschema.exceptions import ValidationError

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, '/workspace/ansible')

import uptimerobot

sys.path.insert(0, '/workspace/infra')
import status

ROOT = Path('/workspace')
WORK = Path('/infra-work/uptime')
INPUTS = Path('/inputs/uptime')
EVIDENCE = Path('/evidence')
MAX_FILE_BYTES = 65536
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_DECLARATIONS = 20


def fail(message):
    raise RuntimeError(message)


def configuration():
    from dotenv import dotenv_values
    interval = os.environ.get('UPTIME_INTERVAL', '300')
    try:
        interval = int(interval)
    except ValueError:
        fail('UPTIME_INTERVAL must be seconds')
    if not 60 <= interval <= 86400:
        fail('UPTIME_INTERVAL must be between 60 and 86400 seconds')
    values = dotenv_values(str(ROOT / '.env'), interpolate=False)
    if values.get('OP_SERVICE_ACCOUNT_TOKEN'):
        os.environ.setdefault('OP_SERVICE_ACCOUNT_TOKEN',
                              values['OP_SERVICE_ACCOUNT_TOKEN'])
    return {'interval': interval}


def reviewed_revision():
    """Accept only a clean checkout at protected main; merges declare intent."""
    git = ['git', '--no-optional-locks', '-c', 'safe.directory=/workspace',
           '-C', str(ROOT)]
    head = subprocess.run(git + ['rev-parse', 'HEAD'], capture_output=True,
                          text=True, timeout=30, check=True).stdout.strip()
    dirty = subprocess.run(git + ['status', '--porcelain'], capture_output=True,
                           text=True, timeout=60, check=True).stdout.strip()
    main = remote_main()
    if dirty or not re.fullmatch(r'[a-f0-9]{40}', head) or head != main:
        fail('Uptime checkout must be clean at reviewed origin/main')
    return head


def remote_main():
    """Fetch protected main from true upstream; never mutate mounts."""
    try:
        git = ['git', '--no-optional-locks', '-c', 'safe.directory=/workspace',
               '-C', str(ROOT)]
        upstream = subprocess.run(
            git + ['remote', 'get-url', 'origin'], capture_output=True,
            text=True, timeout=30, check=True).stdout.strip()
        if not upstream:
            fail('Uptime freshness check failed; refused')
        WORK.mkdir(parents=True, exist_ok=True)
        copy = WORK / 'freshness'
        if copy.exists():
            shutil.rmtree(copy)
        subprocess.run(['git', 'clone', '--quiet', '--no-checkout', str(ROOT),
                        str(copy)],
                       capture_output=True, text=True, timeout=120, check=True)
        subprocess.run(['git', '-C', str(copy), 'remote', 'set-url', 'origin',
                        upstream],
                       capture_output=True, text=True, timeout=30, check=True)
        subprocess.run(['git', '-C', str(copy), 'fetch', '--quiet', 'origin',
                        'main'],
                       capture_output=True, text=True, timeout=120, check=True)
        return subprocess.run(['git', '-C', str(copy), 'rev-parse',
                               'origin/main'],
                              capture_output=True, text=True, timeout=30,
                              check=True).stdout.strip()
    except RuntimeError:
        raise
    except (subprocess.SubprocessError, OSError):
        fail('Uptime freshness check failed; refused')


def contract():
    try:
        return json.loads((ROOT / 'infra/status.contract.json').read_text())
    except (ValueError, OSError):
        fail('Status contract unavailable; monitors retained')


def declarations():
    """Reviewed uptime declarations keyed by service, plus per-file errors."""
    paths = sorted((ROOT / 'services').glob('*/uptime.yaml'))
    if len(paths) > MAX_DECLARATIONS:
        fail('Uptime declarations exceed their bound')
    schema = json.loads((HERE / 'uptime.schema.json').read_text())
    docs, errors = {}, {}
    for path in paths:
        service = path.parent.name
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError('too large')
            document = yaml.safe_load(path.read_text())
            validate(document, schema)
            if document['service'] != service:
                raise ValueError('service binding mismatch')
            docs[service] = document
        except (ValueError, ValidationError, yaml.YAMLError, OSError,
                KeyError):
            errors[service] = 'Uptime declaration invalid; monitor retained'
    return docs, errors


def exposures():
    """Approved public exposures keyed by service."""
    try:
        text = (ROOT / 'services/exposures.yaml').read_text()
        if len(text.encode()) > MAX_FILE_BYTES:
            raise ValueError('too large')
        schema = json.loads(
            (ROOT / 'infra/cloudflare/exposures.schema.json').read_text())
        document = yaml.safe_load(text)
        validate(document, schema)
    except (ValueError, ValidationError, yaml.YAMLError, OSError):
        fail('Approved public exposures unavailable; monitors retained')
    entries = document['exposures']
    if any(entry['service'] != key for key, entry in entries.items()):
        fail('Approved public exposures unavailable; monitors retained')
    return entries


def private_inputs():
    """Private notification bindings and status expectations."""
    try:
        raw = (INPUTS / 'private.json').read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError('too large')
        document = json.loads(raw)
    except (ValueError, OSError):
        fail('Uptime private inputs unavailable; monitors retained')
    if (not isinstance(document, dict) or set(document)
            != {'notification_profiles', 'external_owner_status'}):
        fail('Uptime private inputs invalid; monitors retained')
    profiles = document['notification_profiles']
    if not isinstance(profiles, dict) or len(profiles) > MAX_DECLARATIONS:
        fail('Uptime private inputs invalid; monitors retained')
    for name, identifier in profiles.items():
        if (not isinstance(name, str)
                or re.fullmatch(r'[a-z][a-z0-9-]{0,63}', name) is None
                or type(identifier) is not int
                or not 1 <= identifier <= 2147483647):
            fail('Uptime private inputs invalid; monitors retained')
    try:
        expectations = status.validate_expectations(
            document['external_owner_status'], contract())
    except ValueError:
        fail('Uptime private inputs invalid; monitors retained')
    return {'notification_profiles': profiles,
            'external_owner_status': expectations}


def resolve_host(service, exposure_reference, entries):
    """Approved public exposure host; protected entries fail closed."""
    entry = entries.get(service)
    if not isinstance(entry, dict):
        fail('Uptime declaration lacks its approved public exposure: '
             + service)
    exposure = entry.get('exposure', {})
    host = exposure.get('hostname')
    if (entry.get('service') != service
            or entry.get('publication') != 'published'
            or exposure_reference != 'public'
            or exposure.get('class') != 'public'
            or exposure.get('access') != 'public'
            or not isinstance(host, str) or len(host) > 253
            or re.fullmatch(r'[a-z0-9]([a-z0-9.-]*[a-z0-9])?', host) is None
            or 'internal' in host.split('.')
            or host.split('.')[0] != service):
        fail('Uptime declaration lacks its approved public exposure: '
             + service)
    return host


def reconcile_uptime(revision, docs, errors, entries, profiles, *,
                     apply_allowed):
    """Compile, preflight, and reconcile every declared monitor."""
    from playbooks.secrets.files.vault import fields
    api = uptimerobot.API(
        fields('uptimerobot-management', ('API_KEY',))['API_KEY'])
    registered = uptimerobot.contact(api)
    rows = uptimerobot.monitors(api)
    retained = sorted(row['friendlyName'][len(uptimerobot.PREFIX):]
                      for row in rows
                      if isinstance(row.get('friendlyName'), str)
                      and row['friendlyName'].startswith(uptimerobot.PREFIX)
                      and row['friendlyName'][len(uptimerobot.PREFIX):]
                      not in docs)
    monitors, applied = {}, 0
    for key in sorted(docs):
        monitoring = docs[key]['independentMonitoring']
        if monitoring['notificationProfile'] not in profiles:
            monitors[key] = {
                'configured': False, 'blocked': True,
                'error': 'Uptime declaration lacks its approved '
                         'notification binding'}
            continue
        if profiles[monitoring['notificationProfile']] != registered:
            monitors[key] = {
                'configured': False, 'blocked': True,
                'error': 'Configured notification contact differs from the '
                         'registered email'}
            continue
        try:
            host = resolve_host(key, monitoring['exposureReference'], entries)
            target = uptimerobot.declared(docs[key], host,
                                          profiles[monitoring[
                                              'notificationProfile']])
            plan = uptimerobot.reconcile(api, key, target['url'],
                                         profiles[monitoring[
                                             'notificationProfile']])
            if plan['changes'] and apply_allowed:
                uptimerobot.probe(target['url'], 200)
                plan = uptimerobot.reconcile(api, key, target['url'],
                                             profiles[monitoring[
                                                 'notificationProfile']],
                                             apply=True)
                applied += 1
            monitors[key] = {'configured': plan['configured'],
                             'changes': plan['changes']}
        except (ValueError, RuntimeError) as error:
            monitors[key] = {'configured': False, 'blocked': True,
                             'error': str(error)}
    for key in sorted(errors):
        monitors[key] = {'configured': False, 'blocked': True,
                         'error': errors[key]}
    blocked = sorted(key for key, value in monitors.items()
                     if value.get('blocked'))
    return {'revision': revision, 'ready': not blocked,
            'provider_checked': True, 'contact_verified': True,
            'declared': len(docs), 'applied': applied, 'blocked': blocked,
            'retained': retained, 'monitors': monitors}


def atomic_write(path, text):
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def export_status(contract_doc, expectations, now):
    """Redacted per-root snapshots and metrics from executor evidence."""
    observed = {}
    for root, (relative, _section) in status.SOURCES.items():
        path = EVIDENCE / relative
        try:
            if path.stat().st_size > MAX_EVIDENCE_BYTES:
                raise ValueError('too large')
            observed[root] = (json.loads(path.read_text()),
                              int(path.stat().st_mtime))
        except (ValueError, OSError):
            observed[root] = (None, None)
    previous = {}
    for root in contract_doc['roots']:
        try:
            previous[root] = json.loads(
                (WORK / 'status' / (root + '.json')).read_text())
        except (ValueError, OSError):
            previous[root] = None
    snapshots = status.compile_all(contract_doc, expectations, observed,
                                   previous, now)
    (WORK / 'status').mkdir(parents=True, exist_ok=True)
    for root, snapshot in snapshots.items():
        atomic_write(WORK / 'status' / (root + '.json'),
                     json.dumps(snapshot, sort_keys=True))
    atomic_write(WORK / 'status' / 'metrics.prom',
                 status.metrics(snapshots, now, contract_doc))
    return {'roots': {
        root: {'enabled': expectations['roots'].get(root) is True,
               'results': {action: record['result']
                           for action, record in snapshot['actions'].items()}}
        for root, snapshot in snapshots.items()}}


def report(status_doc):
    WORK.mkdir(parents=True, exist_ok=True)
    path = WORK / 'status.json'
    path.write_text(json.dumps(status_doc, sort_keys=True))
    os.chmod(path, 0o600)
    print(json.dumps(status_doc, sort_keys=True), flush=True)


def once(*, apply_allowed):
    expectations = {'roots': {},
                    'maximum_observation_age_seconds': 86400}
    try:
        contract_doc = contract()
        revision = reviewed_revision()
        docs, errors = declarations()
        entries = exposures()
        private = private_inputs()
        expectations = private['external_owner_status']
        uptime = reconcile_uptime(
            revision, docs, errors, entries,
            private['notification_profiles'], apply_allowed=apply_allowed)
        export = export_status(contract_doc, expectations, int(time.time()))
        status_doc = {'ok': uptime['ready'], 'uptime': uptime,
                      'status_export': export}
    except RuntimeError as error:
        status_doc = {'ok': False, 'uptime': {'ready': False,
                                              'error': str(error)}}
        try:
            status_doc['status_export'] = export_status(
                contract(), expectations, int(time.time()))
        except RuntimeError:
            pass
    except Exception:
        status_doc = {'ok': False, 'uptime': {
            'ready': False,
            'error': 'Uptime reconciliation failed; monitors retained'}}
    report(status_doc)
    return status_doc


def main(argv):
    if argv[:1] not in (['once'], ['loop'], ['verify']):
        raise SystemExit('Uptime reconciler requires once, loop, or verify')
    import fcntl
    os.umask(0o077)
    WORK.mkdir(parents=True, exist_ok=True)
    with (WORK / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise SystemExit('Another uptime reconciliation holds the lock')
        config = configuration()
        if argv[0] == 'once':
            status_doc = once(apply_allowed=True)
            raise SystemExit(0 if status_doc['ok'] else 1)
        if argv[0] == 'verify':
            status_doc = once(apply_allowed=False)
            raise SystemExit(0 if status_doc['ok'] else 1)
        while True:
            try:
                once(apply_allowed=True)
            except RuntimeError as error:
                report({'ok': False, 'error': str(error)})
            except Exception:
                report({'ok': False,
                        'error': 'Uptime reconciliation failed; '
                                 'monitors retained'})
            time.sleep(config['interval'])


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except RuntimeError as error:
        raise SystemExit('uptime reconciler: ' + str(error)) from None
    except Exception:
        raise SystemExit('uptime reconciler: Uptime reconciliation failed; '
                         'monitors retained') from None
