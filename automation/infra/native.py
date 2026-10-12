"""Native maintenance execution with protected diagnostics and bounded duration."""
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
