"""Portable, bounded service validation, rendering and lifecycle operations."""
import argparse
import json
import os
from pathlib import Path
import sys

import yaml

from automation.services.contract import validate, render, ROOT
from automation.services.gitops import resources
from automation.services.lifecycle import ready, publish, retire


def read(path):
    target = Path(path).resolve()
    if target.stat().st_size > 1024 * 1024:
        raise ValueError('Service input exceeds its bounded size')
    value = yaml.safe_load(target.read_text())
    if not isinstance(value, dict): raise ValueError('Service input must be an object')
    return value


def main(arguments=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('check', 'validate', 'render', 'catalog', 'ready', 'publish', 'retire',
                                         'catalog-propose', 'identity-provision', 'identity-retire', 'identity-remove', 'identity-rotate'))
    parser.add_argument('input', nargs='?')
    args = parser.parse_args(arguments)
    if args.action == 'check':
        from automation.services.check import run
        print(json.dumps(run(), sort_keys=True))
        return
    if not args.input: raise ValueError('Service command requires an explicit input file')
    value = read(args.input)
    if args.action == 'catalog-propose':
        from automation.services.inputs import validate_catalog
        from automation.services.source import publish
        print(json.dumps(publish(validate_catalog(value)), sort_keys=True))
        return
    if args.action.startswith('identity-'):
        from automation.identity.service_client import prepare
        if args.action == 'identity-rotate':
            from automation.identity.rotation import local
            definition = validate(value['definition'])
            oidc = definition['oidc']
            if not oidc['enabled'] or oidc['public']:
                raise ValueError('Only an approved confidential client can rotate a secret')
            result = local({'action': 'rotate', 'realm': oidc['realm'], 'client_id': oidc['client']})
        else:
            result = prepare(value['definition'], {'identity-provision': 'provision-client',
                             'identity-retire': 'retire-client', 'identity-remove': 'remove-client'}[args.action])
        print(json.dumps(result, sort_keys=True))
        return
    if args.action == 'validate':
        validate(value)
        print(json.dumps({'valid': True}))
        return
    if args.action == 'render':
        objects = render(validate(value))
    elif args.action == 'catalog':
        if value['approval'].get('chartPath') == 'apps/notes':
            raise ValueError('Notes catalog values must be compiled through lab apply with its private catalog')
        objects = resources(value['definition'], value['approval'], value['platformRepository'], value['platformRevision'])
    else:
        from automation.services.owners import Owners
        owners = Owners(value)
        {'ready': ready, 'publish': publish, 'retire': retire}[args.action](value['definition'], owners)
        print(json.dumps({'operation': args.action, 'verified': True}))
        return
    target = Path('/recovery/service-' + args.action + '.yaml')
    target.write_text(yaml.safe_dump_all(objects, sort_keys=False))
    target.chmod(0o600)
    print(json.dumps({'rendered': True, 'private_output': str(target)}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(str(error) if isinstance(error, (ValueError, RuntimeError)) else
              'Service operation failed; private inputs and data retained', file=sys.stderr)
        raise SystemExit(1) from None
