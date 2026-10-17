"""Native maintenance execution with protected diagnostics and bounded duration."""
import json
import subprocess


def native(directory, env, *arguments, input_data=None):
    prefix = 2 if arguments[0] == 'state' else 1
    result = subprocess.run(['tofu', *arguments[:prefix], '-no-color', *arguments[prefix:]],
                            cwd=directory, env=env, input=input_data, capture_output=True, timeout=180)
    with (directory / 'diagnostics.txt').open('ab') as stream:
        stream.write(result.stderr if arguments[0] == 'show' or arguments[:2] == ('state', 'pull')
                     else result.stdout + result.stderr)
    return result


def require(result, allowed=(0,)):
    if result.returncode not in allowed:
        raise RuntimeError('Native infrastructure operation failed; protected diagnostics retained')
    return result


def document_plan(directory, env, filename):
    result = require(native(directory, env, 'plan', '-input=false', '-detailed-exitcode',
                            '-lock-timeout=0s', '-var-file=desired.tfvars.json', '-out=' + filename), (0, 2))
    document = json.loads(require(native(directory, env, 'show', '-json', filename)).stdout)
    return result.returncode, document


def review_import(document, identities, policy_ids=None):
    resources = {resource['address']: resource for resource in document.get('resource_changes', [])}
    if set(resources) != set(identities):
        raise ValueError('Fixture import scope differs from recorded identities')
    for name, resource in resources.items():
        change = resource['change']
        if change['actions'] != ['no-op'] or change.get('after', {}).get('id') != identities[name]:
            raise ValueError('Fixture import proposed an unintended remote change')
        if resource.get('type') == 'cloudflare_zero_trust_access_application' and policy_ids is not None:
            policies = change['after'].get('policies') or []
            if {policy['id'] for policy in policies} != set(policy_ids) or any(
                    policy.get('reusable') is not False for policy in policies):
                raise ValueError('Fixture import changed legacy policy ownership')
