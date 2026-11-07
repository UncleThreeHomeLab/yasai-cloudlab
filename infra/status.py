"""External-owner status evidence compiler for infra/status.contract.json.

Terminal evidence only. Root executors publish loop status or verify proofs;
they never publish running heartbeats, so this module emits no running
results and fabricates none. Each root yields one atomic snapshot with one
evidence record per contract action: revision, started/completed times,
result, failure category, change count, and the preserved last success.

Completion times come from the source evidence file write time; root
executors publish completion evidence, not per-action start times, so
started_at always equals completed_at. Actions absent from the current
source carry their previous record forward and age honestly. Disabled,
missing, future, or stale evidence reports unavailable, never healthy.
No endpoints, names, plans, diagnostics, or error text ever enter a
snapshot or metric.
"""
import re

SOURCES = {'cloudflare': ('cloudflare/connectivity/status.json', 'cloudflare'),
           'github': ('github/github/status.json', 'governance')}

SHA = re.compile(r'[a-f0-9]{40}')
LABEL = re.compile(r'[a-z][a-z0-9_]*')
MAX_TIMESTAMP = 4102444800
MAX_AGE_SECONDS = 86400
MAX_CHANGES = 1000000
MAX_METRIC_AGE = 999999999


def fail(message):
    raise ValueError(message)


def _contract_lists(contract):
    if not isinstance(contract, dict):
        fail('Status contract is invalid')
    for key in ('roots', 'actions', 'results', 'failure_categories'):
        values = contract.get(key)
        if (not isinstance(values, list) or not values
                or any(not isinstance(value, str) for value in values)):
            fail('Status contract is invalid')
    age = contract.get('maximum_observation_age_seconds')
    if type(age) is not int or not 60 <= age <= MAX_AGE_SECONDS:
        fail('Status contract is invalid')
    return contract


def _moment(value):
    return type(value) is int and 0 <= value <= MAX_TIMESTAMP


def _sha(value):
    if isinstance(value, str) and SHA.fullmatch(value) is not None:
        return value
    return None


def _evidence(contract, *, revision, started_at, completed_at, result,
              failure, changes, last_success_at):
    if revision is not None and _sha(revision) is None:
        fail('Status evidence revision is invalid')
    for moment in (started_at, completed_at):
        if moment is not None and not _moment(moment):
            fail('Status evidence time is invalid')
    if result not in contract['results']:
        fail('Status evidence result is invalid')
    if failure not in contract['failure_categories']:
        fail('Status evidence failure is invalid')
    if (changes is not None
            and (type(changes) is not int or not 0 <= changes <= MAX_CHANGES)):
        fail('Status evidence changes are invalid')
    if last_success_at is not None and not _moment(last_success_at):
        fail('Status evidence last success is invalid')
    return {'revision': revision, 'started_at': started_at,
            'completed_at': completed_at, 'result': result,
            'failure': failure, 'changes': changes,
            'last_success_at': last_success_at}


def validate_expectations(document, contract):
    """Enabled-root expectations; enabling declares evidence is expected."""
    _contract_lists(contract)
    if (not isinstance(document, dict) or 'roots' not in document
            or set(document) - {'roots', 'maximumObservationAgeSeconds'}):
        fail('Status expectations are invalid')
    roots = document['roots']
    if not isinstance(roots, list) or not 1 <= len(roots) <= 8:
        fail('Status expectations are invalid')
    enabled = {}
    for entry in roots:
        if (not isinstance(entry, dict) or set(entry) != {'name', 'enabled'}
                or entry['name'] not in contract['roots']
                or type(entry['enabled']) is not bool
                or entry['name'] in enabled):
            fail('Status expectations are invalid')
        enabled[entry['name']] = entry['enabled']
    age = document.get('maximumObservationAgeSeconds', MAX_AGE_SECONDS)
    if (type(age) is not int or not 60 <= age <= MAX_AGE_SECONDS
            or age > contract['maximum_observation_age_seconds']):
        fail('Status expectations are invalid')
    return {'roots': enabled, 'maximum_observation_age_seconds': age}


def validate_snapshot(raw, contract):
    """Previous snapshot actions, or None when absent or unusable."""
    try:
        _contract_lists(contract)
        if (not isinstance(raw, dict) or set(raw) != {'root', 'actions'}
                or not isinstance(raw.get('root'), str)
                or not isinstance(raw.get('actions'), dict)
                or set(raw['actions']) != set(contract['actions'])):
            return None
        checked = {}
        for action, record in raw['actions'].items():
            if not isinstance(record, dict) or set(record) != {
                    'revision', 'started_at', 'completed_at', 'result',
                    'failure', 'changes', 'last_success_at'}:
                return None
            checked[action] = _evidence(contract, **record)
        return checked
    except ValueError:
        return None


def _reported_changes(section):
    if 'changes' not in section:
        return None
    changes = section['changes']
    if (isinstance(changes, dict) and type(changes.get('changed')) is int
            and 0 <= changes['changed'] <= MAX_CHANGES):
        return changes['changed']
    return 'invalid'


def _loop_actions(section, completed_at, contract):
    """Apply/drift evidence from one loop section; None keeps carried evidence."""
    ready = section.get('ready')
    if ready is not True and ready is not False:
        return None, None
    for key in ('changed', 'drifted', 'approved', 'pending_review'):
        if key in section and type(section[key]) is not bool:
            return None, None
    revision = _sha(section.get('revision'))
    if ready is False:
        if section.get('skipped') is True:
            return None, None
        return _evidence(contract, revision=revision,
                         started_at=completed_at, completed_at=completed_at,
                         result='failure', failure='operation', changes=0,
                         last_success_at=None), None
    changed = _reported_changes(section)
    if changed == 'invalid':
        return None, None
    if section.get('drifted') or section.get('pending_review'):
        drift = _evidence(contract, revision=revision,
                          started_at=completed_at, completed_at=completed_at,
                          result='drift', failure='none', changes=changed,
                          last_success_at=None)
        if section.get('changed') and section.get('approved'):
            return _evidence(contract, revision=revision,
                             started_at=completed_at,
                             completed_at=completed_at, result='success',
                             failure='none', changes=changed,
                             last_success_at=None), drift
        return None, drift
    if section.get('changed'):
        return _evidence(contract, revision=revision,
                         started_at=completed_at, completed_at=completed_at,
                         result='success', failure='none', changes=changed,
                         last_success_at=None), None
    settled = changed if changed is not None else 0
    converged = _evidence(contract, revision=revision,
                          started_at=completed_at, completed_at=completed_at,
                          result='success', failure='none', changes=settled,
                          last_success_at=None)
    return converged, dict(converged)


def _verify_action(section, completed_at, contract):
    if type(section.get('verified')) is not bool or section.get('skipped'):
        return None
    verified = section['verified']
    return _evidence(contract, revision=_sha(section.get('revision')),
                     started_at=completed_at, completed_at=completed_at,
                     result='success' if verified else 'failure',
                     failure='none' if verified else 'operation',
                     changes=0 if verified else None, last_success_at=None)


def compile_root(root, *, enabled, document, completed_at, previous,
                 maximum_age, now, contract):
    """One snapshot for one root; unknown inputs stay unavailable."""
    _contract_lists(contract)
    if type(now) is not int or not _moment(now):
        fail('Status export time is invalid')
    if type(maximum_age) is not int or not 60 <= maximum_age <= MAX_AGE_SECONDS:
        fail('Status observation age is invalid')
    if completed_at is not None and not _moment(completed_at):
        fail('Status observation time is invalid')
    if not isinstance(previous, dict):
        fail('Status previous snapshot is invalid')
    if enabled is not True and enabled is not False:
        fail('Status root expectation is invalid')
    fresh = {}
    source = SOURCES.get(root)
    section = None
    if enabled and source is not None and isinstance(document, dict):
        candidate = document.get(source[1])
        if isinstance(candidate, dict):
            section = candidate
    if section is not None and completed_at is not None:
        if 'verified' in section:
            verify = _verify_action(section, completed_at, contract)
            if verify is not None:
                fresh['verify'] = verify
        elif 'ready' in section:
            apply, drift = _loop_actions(section, completed_at, contract)
            if apply is not None:
                fresh['apply'] = apply
            if drift is not None:
                fresh['drift'] = drift
    actions = {}
    for action in contract['actions']:
        carried = previous.get(action)
        if not isinstance(carried, dict):
            carried = None
        if action in fresh:
            record = dict(fresh[action])
        elif carried is not None:
            record = dict(carried)
        else:
            record = {'revision': None, 'started_at': None,
                      'completed_at': None, 'result': 'unavailable',
                      'failure': 'none', 'changes': None,
                      'last_success_at': None}
        record = _evidence(contract, **record)
        if record['result'] == 'success':
            record['last_success_at'] = record['completed_at']
        elif carried is not None and record['last_success_at'] is None:
            record['last_success_at'] = carried['last_success_at']
        completed = record['completed_at']
        if (completed is None or completed > now
                or now - completed > maximum_age):
            record['result'] = 'unavailable'
            record['failure'] = 'none'
        if not enabled:
            # A disabled executor never appears healthy, however fresh its
            # carried evidence is; last success stays visible history.
            record['result'] = 'unavailable'
            record['failure'] = 'none'
        actions[action] = record
    return {'root': root, 'actions': actions}


def compile_all(contract, expectations, observed, previous_docs, now):
    """Snapshots for every contract root; unknown roots stay unavailable."""
    _contract_lists(contract)
    if (not isinstance(expectations, dict)
            or set(expectations) != {'roots', 'maximum_observation_age_seconds'}
            or not isinstance(expectations['roots'], dict)):
        fail('Status expectations are invalid')
    snapshots = {}
    for root in contract['roots']:
        seen = (observed or {}).get(root)
        if isinstance(seen, (tuple, list)) and len(seen) == 2:
            document, completed_at = seen
        else:
            document, completed_at = None, None
        previous = validate_snapshot((previous_docs or {}).get(root),
                                     contract) or {}
        snapshots[root] = compile_root(
            root, enabled=expectations['roots'].get(root) is True,
            document=document, completed_at=completed_at, previous=previous,
            maximum_age=expectations['maximum_observation_age_seconds'],
            now=now, contract=contract)
    return snapshots


def metrics(snapshots, now, contract):
    """Allowlisted bounded series only; anything else fails closed."""
    _contract_lists(contract)
    if (not isinstance(snapshots, dict)
            or set(snapshots) != set(contract['roots'])):
        fail('Status metrics require every root snapshot')
    lines = ['# HELP cloudlab_status_result Current contract result for one root and action.',
             '# TYPE cloudlab_status_result gauge',
             '# HELP cloudlab_status_evidence_age_seconds Seconds since the action evidence completed.',
             '# TYPE cloudlab_status_evidence_age_seconds gauge',
             '# HELP cloudlab_status_changes Reported change count; absent when the source publishes none.',
             '# TYPE cloudlab_status_changes gauge']
    for root in sorted(snapshots):
        snapshot = snapshots[root]
        if (not isinstance(snapshot, dict) or snapshot.get('root') != root
                or not isinstance(snapshot.get('actions'), dict)
                or set(snapshot['actions']) != set(contract['actions'])):
            fail('Status metrics require every root snapshot')
        for action in contract['actions']:
            record = _evidence(contract, **snapshot['actions'][action])
            for label in (root, action, record['result']):
                if LABEL.fullmatch(label) is None:
                    fail('Status metrics label is invalid')
            lines.append('cloudlab_status_result{root="%s",action="%s",result="%s"} 1'
                         % (root, action, record['result']))
            if record['completed_at'] is not None:
                age = min(max(0, now - record['completed_at']), MAX_METRIC_AGE)
                lines.append('cloudlab_status_evidence_age_seconds{root="%s",action="%s"} %d'
                             % (root, action, age))
            if record['changes'] is not None:
                lines.append('cloudlab_status_changes{root="%s",action="%s"} %d'
                             % (root, action, record['changes']))
    return '\n'.join(lines) + '\n'
