"""Local control-plane inputs; writer credentials never enter lab workloads."""
import os


def identity_prepare():
    from playbooks.observability.files.payload import metadata
    from playbooks.observability.files.identity import provision
    from playbooks.argocd.files.github_setup import inputs
    values, api = inputs()
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        if not values.get(key): raise ValueError('Missing VM input: ' + key)
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    return provision(metadata(), values, api)
