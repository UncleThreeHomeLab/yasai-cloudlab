"""Reviewed profiles cannot add blocked syscalls, architectures or policy authority."""
import json
import unittest

from playbooks.dependencies.files import profiles
from playbooks.dependencies.files.inventory import ROOT


class ProfileTests(unittest.TestCase):
    def test_existing_profile_and_comment_only_apparmor_review_preserve_guards(self):
        directory = ROOT / profiles.BASE
        seccomp = (directory / 'buildkit-seccomp.json').read_bytes()
        profiles.seccomp(seccomp, seccomp)
        apparmor = (directory / 'cloudlab-buildkit').read_bytes()
        profiles.apparmor(apparmor, b'# Reviewed source update\n' + apparmor)
        with self.assertRaises(ValueError):
            profiles.apparmor(apparmor, apparmor + b'  /etc/** w,\n')
        with self.assertRaises(ValueError):
            profiles.apparmor(apparmor, apparmor.replace(b'#include <abstractions/base>', b'#include <abstractions/all>'))
        original = json.loads(seccomp)
        for name in ('bpf', 'new_unreviewed_syscall'):
            changed = json.loads(seccomp)
            changed['syscalls'].append({'names': [name], 'action': 'SCMP_ACT_ALLOW'})
            with self.assertRaises(ValueError):
                profiles.seccomp(seccomp, json.dumps(changed).encode())
        original['architectures'].append('SCMP_ARCH_AARCH64')
        with self.assertRaises(ValueError):
            profiles.seccomp(seccomp, json.dumps(original).encode())
        for mutate in (lambda value: value.update(defaultAction='SCMP_ACT_ALLOW'),
                       lambda value: next(row for row in value['syscalls'] if row.get('args')).pop('args')):
            changed = json.loads(seccomp)
            mutate(changed)
            with self.assertRaises(ValueError):
                profiles.seccomp(seccomp, json.dumps(changed).encode())
