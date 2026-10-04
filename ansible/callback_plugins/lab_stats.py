"""Expose non-secret recap counters for the repeat-apply proof."""

import json
from pathlib import Path

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = 'aggregate'
    CALLBACK_NAME = 'lab_stats'
    CALLBACK_NEEDS_ENABLED = True

    def v2_playbook_on_stats(self, stats):
        summary = {host: stats.summarize(host) for host in stats.processed}
        Path('/tmp/lab-stats.json').write_text(json.dumps(summary))
