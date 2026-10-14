"""Create missing telemetry secrets locally; preserve every existing value."""
import fcntl
import json
import os
from pathlib import Path
import secrets

from dotenv import dotenv_values
from automation.credentials.provision import ensure_items

ROOT = Path(__file__).resolve().parents[2]


def definitions():
    return {'grafana-emergency': {'username': ('STRING', lambda: 'cloudlab-emergency'),
                                 'password': ('CONCEALED', lambda: secrets.token_urlsafe(48)),
                                 'secret_key': ('CONCEALED', lambda: secrets.token_urlsafe(48))},
            'kiali-signing-key': {'key': ('CONCEALED', lambda: secrets.token_urlsafe(24))}}


def provision():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.umask(0o077)
    with Path('/state/observability-provision.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return ensure_items(values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN'), definitions())


if __name__ == '__main__':
    try: print(json.dumps(provision(), sort_keys=True))
    except Exception:
        raise SystemExit('Telemetry credential prerequisites incomplete; values withheld') from None
