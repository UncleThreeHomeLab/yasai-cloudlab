"""Monthly writes plus the operator's dated, initial K3s-only exception."""
from datetime import datetime, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'longhorn'))
from monthly_window import seconds_remaining

_initial = False
_replacement = False
REPLACEMENT_TAG = "retention-proof-2026-10-04"
REPLACEMENT_START = datetime(2026, 10, 3, 23, tzinfo=timezone.utc)
REPLACEMENT_END = datetime(2026, 10, 4, 4, tzinfo=timezone.utc)
INITIAL_START = datetime(2026, 10, 3, tzinfo=timezone.utc)
INITIAL_END = datetime(2026, 10, 4, tzinfo=timezone.utc)


def authorize_initial():
    global _initial
    _initial = True
    require_window(reserve=3600)


def authorize_replacement():
    global _replacement
    _replacement = True
    require_window(reserve=3600)


def replacement_active():
    return _replacement


def require_window(reserve=0, now=None):
    now = now or datetime.now(timezone.utc)
    if _replacement:
        remaining = (REPLACEMENT_END - now).total_seconds() if REPLACEMENT_START <= now < REPLACEMENT_END else 0
    elif _initial:
        remaining = (INITIAL_END - now).total_seconds() if INITIAL_START <= now < INITIAL_END else 0
    else:
        remaining = seconds_remaining(now)
    if remaining <= reserve:
        raise RuntimeError('K3s writes require day 1 UTC or an unexpired explicit recovery exception.')
    return remaining


def initial_active():
    return _initial
