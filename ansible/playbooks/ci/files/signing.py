"""Create retained private CI signing material locally before any publisher consumes it."""
import fcntl
import argparse
import json
from pathlib import Path
from dotenv import dotenv_values

from playbooks.harbor.files.signatures import private_key, public_key, durable
from playbooks.secrets.files.provision import ensure_items
from playbooks.infrastructure.files.harbor import WORK

SIGNER = 'ci-private-signer'
VERIFIER = 'ci-private-verifier'
ROOT = Path(__file__).resolve().parents[4]


def provision(token):
    result = ensure_items(token, {SIGNER: {'private_key': ('CONCEALED', private_key)}})
    # Read the durable original before deriving or creating its separate public verifier.
    public = public_key(durable(token, SIGNER, 'private_key', 'CONCEALED'))
    verifier = ensure_items(token, {VERIFIER: {'public_key': ('STRING', lambda: public)}})
    if durable(token, VERIFIER, 'public_key', 'STRING') != public:
        raise ValueError('CI verifier differs from its retained signer; no rotation permitted')
    return {'created_items': len(result['created']) + len(verifier['created']),
            'preserved_items': len(result['preserved']) + len(verifier['preserved']), 'private_key_delivered': False}


def main():
    argparse.ArgumentParser(description='Create missing private CI signing items locally; preserve existing keys.').parse_args()
    values = dotenv_values(ROOT / '.env', interpolate=False)
    token = values.get('OP_PROVISION_SERVICE_ACCOUNT_TOKEN')
    if not token:
        raise ValueError('Local signing custody requires the separate vault provisioning account')
    WORK.mkdir(mode=0o700, parents=True, exist_ok=True)
    with (WORK / 'client.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(provision(token), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('CI signing custody incomplete; existing vault items and recovery keys preserved') from None
