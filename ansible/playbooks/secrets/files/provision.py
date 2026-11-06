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
        if 'too many requests' in result.stderr.lower():
            raise RuntimeError('1Password request quota exhausted; wait for its reset before provisioning')
        raise RuntimeError('1Password provisioning failed; verify CloudLab Read Items and Write Items permissions')
    try:
        return json.loads(result.stdout)
    except ValueError:
        raise RuntimeError('1Password returned an invalid provisioning response; inspect item existence before retrying') from None


def inventory_items(token):
    items = command(['item', 'list', '--vault', 'CloudLab'], token)
    if (not isinstance(items, list) or any(
            not isinstance(item, dict) or
            not isinstance(item.get('id'), str) or not item['id'] or
            not isinstance(item.get('title'), str) or not item['title']
            for item in items)):
        raise RuntimeError('1Password returned an invalid item inventory')
    return items


def ensure_items(token, definitions, *, placeholders=False):
    """definitions maps titles to {field: (field type, lazy value factory)}.

    With placeholders=True, factories must be None; pending reports empty fields.
    Call only for an explicitly scoped task. One provisioning process at a time;
    the vault API does not provide atomic create-if-title-absent semantics.
    """
    if not token:
        raise RuntimeError('Missing .env input: OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if (not isinstance(definitions, dict) or not definitions or any(
            not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,99}', name)
            for name in definitions)):
        raise ValueError('Provisioning requires explicit, valid item titles')
    if not isinstance(placeholders, bool):
        raise ValueError('Invalid placeholder mode')
    for fields in definitions.values():
        if (not isinstance(fields, dict) or not fields or any(
                not isinstance(label, str) or not label or
                not isinstance(field, (tuple, list)) or len(field) != 2 or
                field[0] not in ('STRING', 'CONCEALED') or
                (field[1] is not None if placeholders else not callable(field[1]))
                for label, field in fields.items())):
            raise ValueError('Invalid vault field definition')
    existing = inventory_items(token)
    inventory = {}
    for name in definitions:
        matches = [item for item in existing if item.get('title') == name]
        if len(matches) > 1:
            raise RuntimeError('Duplicate CloudLab item title: ' + name)
        inventory[name] = matches[0] if matches else None
    # Validate every existing item before creating anything. Read failures are
    # never interpreted as an absent item.
    pending = {}
    for name, item in inventory.items():
        if item is None:
            continue
        current = command(['item', 'get', item['id'], '--vault', 'CloudLab'], token)
        if (not isinstance(current, dict) or
                not isinstance(current.get('fields'), list) or
                any(not isinstance(field, dict) for field in current['fields'])):
            raise RuntimeError('1Password returned invalid item fields')
        if placeholders and (current.get('id') != item['id'] or
                             current.get('title') != name or
                             current.get('category') != 'SECURE_NOTE'):
            raise RuntimeError('Incompatible item identity or category: ' + name)
        for label, (kind, _) in definitions[name].items():
            matches = [field for field in current['fields'] if field.get('label') == label]
            if len(matches) != 1 or matches[0].get('type') != kind:
                raise RuntimeError('Incompatible field in ' + name + ': ' + label)
            value = matches[0].get('value')
            if placeholders and (value is None or value == ''):
                pending.setdefault(name, []).append(label)
            elif not isinstance(value, str) or not value:
                raise RuntimeError('Incompatible field in ' + name + ': ' + label)
    result = {'created': [], 'preserved': []}
    if placeholders:
        result['pending'] = pending
    for name, fields in definitions.items():
        if inventory[name] is not None:
            result['preserved'].append(name)
            continue
        # A fresh inventory narrows the race with another provisioning client.
        current = inventory_items(token)
        if any(item.get('title') == name for item in current):
            raise RuntimeError('CloudLab item appeared during provisioning; rerun to validate it')
        document = {'title': name, 'category': 'SECURE_NOTE',
                    'tags': ['cloudlab-managed'],
                    'fields': [{'id': label, 'label': label, 'type': kind,
                                'value': '' if placeholders else factory()}
                               for label, (kind, factory) in fields.items()]}
        if not placeholders and any(not isinstance(field['value'], str) or not field['value']
                                    for field in document['fields']):
            raise ValueError('Generated vault fields must be nonempty strings')
        created = command(['item', 'create', '-', '--vault', 'CloudLab'], token, document)
        if (not isinstance(created, dict) or not isinstance(created.get('id'), str) or
                not created['id'] or created.get('title') != name):
            raise RuntimeError('Created item response is incomplete; inspect existence before retrying')
        result['created'].append(name)
        if placeholders:
            pending[name] = list(fields)
    return result
