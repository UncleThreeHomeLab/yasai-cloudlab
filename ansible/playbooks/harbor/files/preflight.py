"""Inventory external inputs without exposing values or mutating any service."""
import argparse
import json
import os
from pathlib import Path

from dotenv import dotenv_values

from playbooks.secrets.files.provision import command
from playbooks.argocd.files.github_setup import repository

CONTRACT = json.loads((Path(__file__).parent / 'contract.json').read_text())
CONTRACT['projects'] = list(json.loads((Path(__file__).resolve().parents[4] / 'infra/harbor/contract.json').read_text())['projects'])


def targets(values):
    result = {key: repository(values.get(key)) for key in (
        'PRIVATE_CONFIG_REPOSITORY', 'PUBLIC_TEST_REPOSITORY', 'PRIVATE_TEST_REPOSITORY')}
    if len(set(name.lower() for name in result.values())) != 3 or len({
            name.split('/')[0].lower() for name in result.values()}) != 1:
        raise ValueError('Harbor requires distinct designated configuration/public/private repositories in the same owner')
    return result


def inspect(token):
    if not token:
        raise ValueError('Read-only vault token required')
    inventory = command(['item', 'list', '--vault', CONTRACT['vault']], token)
    missing, invalid, ready = [], [], []
    for title, required in CONTRACT['prerequisites'].items():
        rows = [item for item in inventory if item.get('title') == title]
        if not rows:
            missing.append(title)
            continue
        if len(rows) != 1:
            invalid.append({'item': title, 'reason': 'duplicate title'})
            continue
        document = command(['item', 'get', rows[0]['id'], '--vault', CONTRACT['vault']], token)
        fields = document.get('fields', [])
        failed = [name for name in required if len([field for field in fields
                  if field.get('label') == name and isinstance(field.get('value'), str) and field['value']]) != 1
                  or len([field for field in fields if field.get('label') == name]) != 1]
        if failed:
            invalid.append({'item': title, 'fields': failed})
        else:
            ready.append(title)
    return {'missing': missing, 'invalid': invalid, 'ready': ready, 'production_mutations': 0,
            'scope_permissions_verified': False, 'ready_for_live_acceptance': False}


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--github-scopes', action='store_true')
    args = parser.parse_args(arguments)
    values = dotenv_values(Path('/workspace/.env'), interpolate=False)
    targets(values)
    # command() gives only its child the selected reader token; the writer is never loaded.
    result = inspect(values.get('OP_SERVICE_ACCOUNT_TOKEN'))
    if args.github_scopes and not result['missing'] and not result['invalid']:
        from playbooks.harbor.files.scopes import verify
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values['OP_SERVICE_ACCOUNT_TOKEN']
        result['github_apps'] = verify(values)
        result['github_scopes_verified'] = True
    print(json.dumps(result, sort_keys=True))
    return 1 if result['missing'] or result['invalid'] else 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception:
        raise SystemExit('Harbor prerequisite inspection failed; private details withheld and no changes made') from None
