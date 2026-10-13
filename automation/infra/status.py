"""Redacted current evidence for each root; scheduling and export belong to delivery."""
import json
import math
from pathlib import Path
import re

ROOTS = ('cloudflare', 'github')
ACTIONS = ('apply', 'drift', 'verify')
RESULTS = ('running', 'success', 'drift', 'failure', 'unavailable')
FAILURES = ('none', 'operation', 'interrupted', 'authentication', 'backend', 'lock', 'verification')
MAX_AGE_SECONDS = 86400
MAX_DURATION_SECONDS = 3600


def validate(document):
    if not isinstance(document, dict) or set(document) != {'format', 'root', 'actions'}:
        raise ValueError('Root status requires its complete redacted contract')
    if (type(document['format']) is not int or document['format'] != 1 or document['root'] not in ROOTS or
            not isinstance(document['actions'], dict) or set(document['actions']) - set(ACTIONS)):
        raise ValueError('Unsupported root status scope')
    for action, event in document['actions'].items():
        if set(event) != {'revision', 'started_at', 'completed_at', 'result', 'failure', 'changes', 'last_success_at'}:
            raise ValueError('Status must not contain provider output or resource identifiers')
        if not isinstance(event['revision'], str) or not re.fullmatch('[a-f0-9]{40}', event['revision']):
            raise ValueError('Status requires an immutable source revision')
        for key in ('started_at', 'completed_at', 'last_success_at'):
            if type(event[key]) not in (int, float) or not math.isfinite(event[key]) or event[key] < 0:
                raise ValueError('Status time must be finite and nonnegative')
        if (event['result'] not in RESULTS or event['failure'] not in FAILURES or
                type(event['changes']) is not int or not 0 <= event['changes'] <= 10000 or
                event['last_success_at'] > max(event['started_at'], event['completed_at'])):
            raise ValueError('Status result is invalid')
        if event['result'] == 'running':
            if event['completed_at'] != 0 or event['failure'] != 'none':
                raise ValueError('Running status cannot claim completion')
        elif event['completed_at'] < event['started_at']:
            raise ValueError('Completion cannot precede start')
        if ((event['result'] in ('success', 'drift', 'running') and event['failure'] != 'none') or
                (event['result'] in ('failure', 'unavailable') and event['failure'] == 'none')):
            raise ValueError('Status failure category conflicts with result')
        if event['result'] == 'drift' and (action == 'apply' or event['changes'] < 1):
            raise ValueError('Drift requires observed plan changes')
        if event['result'] == 'success' and action != 'apply' and event['changes']:
            raise ValueError('Unchanged verification cannot claim plan changes')
    return document


def update(path, root, action, revision, now, *, result='running', failure='none', changes=0):
    if action not in ACTIONS or root not in ROOTS:
        raise ValueError('Status scope is invalid')
    path = Path(path)
    document = validate(json.loads(path.read_text())) if path.exists() else {'format': 1, 'root': root, 'actions': {}}
    if document['root'] != root:
        raise ValueError('Status root changed; refuse overwrite')
    old = document['actions'].get(action, {})
    if result != 'running' and (old.get('result') != 'running' or old.get('revision') != revision):
        raise ValueError('Completion requires the same running revision')
    previous_success = old.get('last_success_at', 0)
    document['actions'][action] = {'revision': revision,
        'started_at': now if result == 'running' else old['started_at'],
        'completed_at': 0 if result == 'running' else now,
        'result': result, 'failure': failure, 'changes': changes,
        'last_success_at': now if result == 'success' else previous_success}
    validate(document)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix('.tmp')
    with temporary.open('w') as output:
        temporary.chmod(0o600)
        json.dump(document, output, sort_keys=True)
    temporary.replace(path)
    return document


def evidence(document, action, now):
    validate(document)
    if action not in ACTIONS:
        raise ValueError('Unsupported root status action')
    event = document['actions'].get(action)
    if event is None: return 'unavailable'
    if now < event['started_at'] or now < event['completed_at']: return 'unavailable'
    if event['result'] == 'running':
        return 'interrupted' if now - event['started_at'] > MAX_DURATION_SECONDS else 'running'
    if now - event['completed_at'] > MAX_AGE_SECONDS: return 'stale'
    return event['result']


def metrics(document, now):
    validate(document)
    lines = []
    for action in ACTIONS:
        event = document['actions'].get(action, {})
        labels = 'root="' + document['root'] + '",action="' + action + '"'
        state = evidence(document, action, now)
        lines.extend([
            'cloudlab_infra_evidence_timestamp_seconds{' + labels + '} ' + str(event.get('completed_at', 0)),
            'cloudlab_infra_last_success_timestamp_seconds{' + labels + '} ' + str(event.get('last_success_at', 0)),
            'cloudlab_infra_changes{' + labels + '} ' + str(event.get('changes', 0)),
        ])
        for candidate in (*RESULTS, 'interrupted', 'stale'):
            lines.append('cloudlab_infra_result{' + labels + ',result="' + candidate + '"} ' + str(int(state == candidate)))
    return '\n'.join(lines) + '\n'


def alerts():
    # Expected/enabled series come from reviewed 06a workflows, never inferred from success.
    enabled = 'on(root,action) (cloudlab_infra_workflow_enabled == 1)'
    return [
        {'alert': 'InfrastructureRunFailed', 'expr':
            'cloudlab_infra_result{result=~"failure|interrupted|unavailable"} == 1 and ' + enabled,
         'for': '1m', 'labels': {'severity': 'warning'},
         'annotations': {'summary': 'Infrastructure execution failed or evidence is unavailable'}},
        {'alert': 'InfrastructureEvidenceMissing', 'expr':
            '(cloudlab_infra_workflow_enabled == 1) unless on(root,action) cloudlab_infra_evidence_timestamp_seconds',
         'for': '15m', 'labels': {'severity': 'warning'},
         'annotations': {'summary': 'Enabled infrastructure workflow has no evidence'}},
        {'alert': 'InfrastructureEvidenceStale', 'expr':
            '(time() - cloudlab_infra_evidence_timestamp_seconds > 86400) and ' + enabled,
         'for': '15m', 'labels': {'severity': 'warning'},
         'annotations': {'summary': 'Infrastructure evidence is older than its daily observation bound'}},
        {'alert': 'InfrastructureDrift', 'expr':
            'cloudlab_infra_result{result="drift"} == 1 and ' + enabled,
         'for': '5m', 'labels': {'severity': 'warning'},
         'annotations': {'summary': 'Infrastructure drift requires review; no automatic repair'}},
    ]
