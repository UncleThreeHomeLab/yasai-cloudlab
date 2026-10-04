"""Single UTC window contract for cloud writes, including disposable fixtures."""

from datetime import datetime, timezone, timedelta


def seconds_remaining(now=None):
    now = now or datetime.now(timezone.utc)
    if now.day != 1:
        return 0
    return ((now.replace(hour=0, minute=0, second=0, microsecond=0)
             + timedelta(days=1)) - now).total_seconds()


def require_window(reserve=0):
    remaining = seconds_remaining()
    if remaining <= reserve:
        raise RuntimeError('B2 writes require day 1 UTC; no initial or test exception.')
    return remaining
