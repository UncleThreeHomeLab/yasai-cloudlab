"""Monthly cloud-write window shared with Longhorn."""
from datetime import datetime, timezone

try:
    from playbooks.longhorn.files.monthly_window import seconds_remaining
except ModuleNotFoundError:
    from monthly_window import seconds_remaining  # Installed beside independent recovery tooling.


def require_window(reserve=0, now=None):
    now = now or datetime.now(timezone.utc)
    remaining = seconds_remaining(now)
    if remaining <= reserve:
        raise RuntimeError('K3s writes require day 1 UTC.')
    return remaining
