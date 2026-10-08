"""Create missing task-owned vault items without exposing the local writer token."""
import json
import os
import re
import subprocess


def command(arguments, token, document=None):
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith('OP_')}
    environment['OP_SERVICE_ACCOUNT_TOKEN'] = token
    try:
        result = subprocess.run(['op', *arguments, '--format', 'json'],
                                input=json.dumps(document) if document is not None else None,
                                capture_output=True, text=True, timeout=60, env=environment)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('1Password provisioning did not complete; inspect item existence before retrying') from None
    if result.returncode:
        raise RuntimeError('1Password provisioning failed; verify CloudLab Read Items and Write Items permissions')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise RuntimeError('1Password returned an invalid provisioning response') from None


def ensure_items(token, definitions):
    """definitions maps titles to {field: (field type, lazy value factory)}.

    Call only for an explicitly scoped task. One provisioning process at a time;
    the vault API does not provide atomic create-if-title-absent semantics.
    """
    if not token:
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if not definitions or any(not re.fullmatch(r'[a-z][a-z0-9-]{0,99}', name) for name in definitions):
        raise ValueError('Provisioning requires explicit, valid item titles')
    existing = command(['item', 'list', '--vault', 'CloudLab'], token)
    inventory = {}
    for name, fields in definitions.items():
        if not fields or any(kind not in ('STRING', 'CONCEALED') or not callable(factory)
                             for kind, factory in fields.values()):
            raise ValueError('Invalid vault field definition')
        matches = [item for item in existing if item.get('title') == name]
        if len(matches) > 1:
            raise RuntimeError('Duplicate CloudLab item title: ' + name)
        inventory[name] = matches[0] if matches else None
    # Validate every existing item before creating anything. Read failures are
    # never interpreted as an absent item.
    for name, item in inventory.items():
        if item is None:
            continue
        current = command(['item', 'get', item['id'], '--vault', 'CloudLab'], token)
        for label, (kind, _) in definitions[name].items():
            matches = [field for field in current.get('fields', []) if field.get('label') == label]
            if len(matches) != 1 or not matches[0].get('value') or matches[0].get('type') != kind:
                raise RuntimeError('Incompatible field in ' + name + ': ' + label)
    result = {'created': [], 'preserved': []}
    for name, fields in definitions.items():
        if inventory[name] is not None:
            result['preserved'].append(name)
            continue
        # A fresh inventory narrows the race with another provisioning client.
        current = command(['item', 'list', '--vault', 'CloudLab'], token)
        if any(item.get('title') == name for item in current):
            raise RuntimeError('CloudLab item appeared during provisioning; rerun to validate it')
        document = {'title': name, 'category': 'SECURE_NOTE',
                    'tags': ['cloudlab-managed'],
                    'fields': [{'id': label, 'label': label, 'type': kind, 'value': factory()}
                               for label, (kind, factory) in fields.items()]}
        if any(not isinstance(field['value'], str) or not field['value'] for field in document['fields']):
            raise ValueError('Generated vault fields must be nonempty strings')
        created = command(['item', 'create', '-', '--vault', 'CloudLab'], token, document)
        if not created.get('id') or created.get('title') != name:
            raise RuntimeError('Created item response is incomplete; inspect existence before retrying')
        result['created'].append(name)
    return result
