"""Local vault-owned robot inputs; never deliver the provisioning identity."""
import fcntl
import json
import os
from pathlib import Path
import secrets

from dotenv import dotenv_values

from automation.credentials.provision import ensure_items, command
from automation.harbor.preflight import CONTRACT

PROJECTS = tuple(CONTRACT['projects'])


def definitions():
    return {f'harbor-{project}-{role}': {
        'username': ('STRING', lambda project=project, role=role: f'robot${project}+{role}'),
        'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
        'secret_version': ('STRING', lambda: '1')}
        for project in PROJECTS for role in ('push', 'pull')}


def read_robot(token, title, username):
    """Read back durable input before any registry mutation; never infer absence."""
    inventory = command(['item', 'list', '--vault', 'CloudLab'], token)
    matches = [item for item in inventory if item.get('title') == title]
    if len(matches) != 1:
        raise RuntimeError('Robot vault input missing or ambiguous; no registry mutation')
    document = command(['item', 'get', matches[0]['id'], '--vault', 'CloudLab'], token)
    return robot_values(document, username)


def robot_values(document, username):
    values = {}
    for name, kind in CONTRACT['robot_fields'].items():
        rows = [field for field in document.get('fields', []) if field.get('label') == name]
        if len(rows) != 1 or rows[0].get('type') != kind or not rows[0].get('value'):
            raise RuntimeError('Robot vault field incompatible; no registry mutation')
        values[name] = rows[0]['value']
    if values['username'] != username or values['secret_version'] != '1' or len(values['password']) < 32:
        raise RuntimeError('Robot vault identity/version incompatible; no registry mutation')
    return values


def provision(lock_path=Path('/state/harbor-provision.lock')):
    values = dotenv_values(Path('/workspace/.env'), interpolate=False)
    token = values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    os.umask(0o077)
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        inventory = command(['item', 'list', '--vault', 'CloudLab'], token)
        for project in PROJECTS:
            for role in ('push', 'pull'):
                rows = [item for item in inventory if item.get('title') == f'harbor-{project}-{role}']
                if len(rows) > 1:
                    raise RuntimeError('Duplicate robot input; no vault creation')
                if rows:
                    robot_values(command(['item', 'get', rows[0]['id'], '--vault', 'CloudLab'], token),
                                 f'robot${project}+{role}')
        result = ensure_items(token, definitions())
        for project in PROJECTS:
            for role in ('push', 'pull'):
                read_robot(token, f'harbor-{project}-{role}', f'robot${project}+{role}')
        return dict(result, registry_mutations=0)


if __name__ == '__main__':
    try:
        print(json.dumps(provision(), sort_keys=True))
    except Exception:
        raise SystemExit('Harbor vault inputs incomplete; existing values preserved and no registry mutation') from None
