"""Launch the maintenance compose profile with the vault-held writer token.

Reads the service-account token from .env, fetches RENOVATE_TOKEN from the
renovate-maintenance vault item, validates it, and execs docker compose with
the maintenance profile. The token travels in the child environment only.
"""
# Custom launcher, not `op run --env-file`: the native form would inject every
# .env entry into the compose child's environment, while this script reads only
# OP_SERVICE_ACCOUNT_TOKEN for its own op authentication, validates the vault
# field, and adds just RENOVATE_TOKEN to the child.
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = next((parent for parent in HERE.parents
             if (parent / 'platform').is_dir() and (parent / 'ansible').is_dir()), None)
if ROOT is None:
    raise RuntimeError('Maintenance launcher requires the CloudLab checkout')
sys.path.insert(0, str(ROOT / 'ansible'))

from playbooks.secrets.files.vault import fields  # noqa: E402

ITEM = 'renovate-maintenance'
FIELD = 'RENOVATE_TOKEN'
SERVICE_KEY = 'OP_SERVICE_ACCOUNT_TOKEN'


def service_token(env_file):
    """Read only the service-account token from .env with the standard library."""
    try:
        lines = Path(env_file).read_text(encoding='utf-8').splitlines()
    except (OSError, UnicodeError):
        return None
    for line in lines:
        text = line.strip()
        if not text or text.startswith('#') or '=' not in text:
            continue
        key, _, value = text.partition('=')
        if key.strip() != SERVICE_KEY:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in '\'"':
            value = value[1:-1]
        return value or None
    return None


def valid(token):
    return bool(token) and not any(char.isspace() for char in token)


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv) or ['up', '-d']
    if SERVICE_KEY not in os.environ:
        token = service_token(ROOT / '.env')
        if token:
            os.environ[SERVICE_KEY] = token
    try:
        secret = fields(ITEM, (FIELD,))[FIELD]
    except RuntimeError as error:
        # vault.fields failures name only the item and field, never values.
        print('maintenance launcher: ' + str(error), file=sys.stderr)
        return 1
    except Exception:
        print('maintenance launcher: cannot read required CloudLab item: ' + ITEM,
              file=sys.stderr)
        return 1
    if not valid(secret):
        print('maintenance launcher: writer token for ' + ITEM + '/' + FIELD +
              ' is missing or invalid; refusing to start', file=sys.stderr)
        return 1
    os.environ[FIELD] = secret
    print('maintenance launcher: starting profile maintenance (compose args: ' +
          ' '.join(args) + ')', flush=True)
    try:
        os.execvp('docker', ['docker', 'compose', '--profile', 'maintenance', *args])
    except OSError:
        print('maintenance launcher: docker compose is required on PATH',
              file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
