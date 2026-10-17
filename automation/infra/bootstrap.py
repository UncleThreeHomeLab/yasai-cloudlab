"""Create independent encryption keys; never store backend credentials in Git."""
import json
from pathlib import Path
import secrets

from dotenv import dotenv_values
from playbooks.secrets.files.provision import ensure_items


def main():
    inputs = dotenv_values(Path('/workspace/.env'), interpolate=False)
    definitions = {'opentofu-state-' + root: {
        'PASSPHRASE': ('CONCEALED', lambda: secrets.token_urlsafe(64))}
        for root in ('cloudflare', 'github')}
    result = ensure_items(inputs.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), definitions)
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError):
        raise SystemExit('Independent encryption key bootstrap incomplete; existing items remain unchanged') from None
