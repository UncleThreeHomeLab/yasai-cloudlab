"""Portable independent monitoring; management credentials never enter the lab."""
import argparse
import json
import os
from pathlib import Path
import sys

from dotenv import dotenv_values

from automation.observability.uptimerobot import API, contact, reconcile, remove_fixture, owned, monitors, probe

ROOT = Path(__file__).resolve().parents[2]


def environment():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    if not values.get('OP_SERVICE_ACCOUNT_TOKEN'):
        raise ValueError('Missing .env input: OP_SERVICE_ACCOUNT_TOKEN')
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values['OP_SERVICE_ACCOUNT_TOKEN']
    from playbooks.secrets.files.vault import fields
    return API(fields('uptimerobot-management', ('API_KEY',))['API_KEY'])


def notes_origin():
    from automation.services.inputs import catalog
    value = catalog(required=True)
    entries = [row for row in value['catalog'] if row['definition']['name'] == 'notes' and
               row['approval'].get('chartPath') == 'apps/notes' and row['publication'] == 'published']
    if len(entries) != 1 or entries[0]['definition']['exposure']['class'] != 'public':
        raise RuntimeError('Independent monitoring requires the published approved notes application')
    return 'https://' + entries[0]['definition']['exposure']['hostname']


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('external-check', 'external-apply', 'fixture-ready', 'fixture-fail',
                                         'fixture-status', 'fixture-remove', 'charts', 'credentials', 'identity-prepare', 'baseline-prepare', 'baseline-cleanup'))
    args = parser.parse_args(arguments)
    from automation.observability.chart import check
    from automation.observability.credentials import provision
    from automation.observability.control import identity_prepare
    from automation.observability.baseline import prepare, cleanup
    local = {'charts': check, 'credentials': provision, 'identity-prepare': identity_prepare,
             'baseline-prepare': prepare, 'baseline-cleanup': cleanup}
    if args.action in local:
        print(json.dumps(local[args.action](), sort_keys=True))
        return
    api = environment()
    identifier = contact(api)
    origin = notes_origin()
    if args.action == 'fixture-status':
        row = owned(monitors(api), 'notification-proof')
        if not row:
            raise RuntimeError('Notification proof monitor absent')
        status = row.get('status')
        if status not in ('PAUSED', 'STARTED', 'UP', 'LOOKS_DOWN', 'DOWN'):
            raise RuntimeError('Unknown independent monitor status')
        result = {'provider_status': status, 'delivery_proven': False}
    elif args.action == 'fixture-remove':
        row = owned(monitors(api), 'notification-proof')
        allowed = [origin + '/monitoring-proof/' + state for state in ('ready', 'failed')]
        if row and row.get('url') not in allowed:
            raise RuntimeError('Fixture has an unexpected endpoint; removal refused')
        result = remove_fixture(api, row['url'] if row else allowed[0])
    else:
        fixture = args.action.startswith('fixture-')
        url = origin + ('/monitoring-proof/failed' if args.action == 'fixture-fail' else
                        '/monitoring-proof/ready' if fixture else '/health')
        probe(url, 503 if args.action == 'fixture-fail' else 200)
        if args.action == 'fixture-fail':
            row = owned(monitors(api), 'notification-proof')
            if row is None or (row.get('url') != url and row.get('status') != 'UP'):
                raise RuntimeError('Notification proof must first observe its disposable ready endpoint UP')
        result = reconcile(api, 'notification-proof' if fixture else 'notes-health', url, identifier,
                           apply=args.action != 'external-check', allow_fixture_change=fixture)
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Independent monitoring failed; private values withheld', file=sys.stderr)
        raise SystemExit(1) from None
