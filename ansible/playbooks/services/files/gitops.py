"""Administrator-owned namespace budgets and fixed ApplicationSet destinations."""
import re
import os
import selectors
import signal
import subprocess
import time

from playbooks.services.files.contract import validate, artifact_approval

MAX_RENDER_OUTPUT = 8 * 1024 * 1024
MAX_RENDER_ERROR = 1024 * 1024


def _render(arguments, payload, *, timeout=90):
    """Bound native Helm streams while running, including blocked input writes."""
    environment = {key: os.environ[key] for key in
                   ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'TMPDIR', 'LANG', 'LC_ALL') if key in os.environ}
    process = None
    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(arguments, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=environment, bufsize=0, start_new_session=True)
        pending = memoryview(payload.encode())
        output = bytearray()
        counts = {'stdout': 0, 'stderr': 0}
        with selectors.DefaultSelector() as selector:
            for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr'), (process.stdin, 'stdin')):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_WRITE if name == 'stdin' else selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Administrator service catalog render exceeded its deadline')
                for key, _ in selector.select(remaining):
                    if key.data == 'stdin':
                        if pending:
                            pending = pending[os.write(key.fd, pending[:65536]):]
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    limit = MAX_RENDER_OUTPUT if key.data == 'stdout' else MAX_RENDER_ERROR
                    chunk = os.read(key.fd, min(65536, limit + 1 - counts[key.data]))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.data] += len(chunk)
                    if counts[key.data] > limit:
                        raise ValueError('Administrator service catalog render exceeded its output bound')
                    if key.data == 'stdout':
                        output.extend(chunk)
            if process.wait(timeout=max(.001, deadline - time.monotonic())):
                raise ValueError('Administrator service catalog failed validation')
        return output.decode('utf-8')
    except subprocess.TimeoutExpired:
        raise ValueError('Administrator service catalog render exceeded its deadline') from None
    except (OSError, UnicodeError):
        raise ValueError('Administrator service catalog render failed; diagnostics withheld') from None
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()


def resources(definition, approval, platform_repository, platform_revision, *, chart_root=None, public=None):
    """Render an explicit owner chart; the default is for local package checks."""
    if public is not None:
        from playbooks.services.files.owner import chart, configuration
        selected = configuration(public)
        if (platform_repository, platform_revision) != (selected['repository'], selected['revision']):
            raise ValueError('Service rendering differs from its declared public owner')
        if chart_root is None:
            with chart(public) as selected_chart:
                return resources(definition, approval, platform_repository, platform_revision, chart_root=selected_chart)
    definition = validate(definition)
    required = {'name', 'repository', 'revision', 'valuesPath', 'namespace', 'secretReferences', 'configMaps'}
    # Native selected schema owns optional/required approval fields. Keep the
    # shared source and namespace envelope independent of owner versions.
    if not isinstance(approval, dict) or not required <= set(approval) or approval.get('visibility', 'public') not in ('public', 'private'):
        raise ValueError('Administrator approval requires an exact source and namespace')
    if approval.get('chartPath', 'charts/service') not in ('charts/service', 'apps/notes'):
        raise ValueError('Service chart source is not approved')
    artifact_approval(approval)
    from playbooks.services.files.compositions import validate as composition
    composed = composition(approval)
    if composed:
        exposures = [row for row in [definition['exposure']] + definition.get('additionalExposures', []) if row['class'] != 'none']
        if (definition['rollouts']['enabled'] or set(composed['backends']) != {row['hostname'] for row in exposures} or
                any(composed['backends'][row['hostname']]['port'] != row['port'] for row in exposures)):
            raise ValueError('Composition routes require exact exposure host and real backend ports; canaries are unsupported')
        for exposure in exposures:
            selected = composed['backends'][exposure['hostname']]
            prefix = exposure['path'].rstrip('/')
            if 'readiness' in selected and not (selected['readiness']['path'] == prefix or
                    selected['readiness']['path'].startswith(prefix + '/')):
                raise ValueError('Composition listener readiness must remain under its approved exposure path')
    name, namespace = approval['name'], approval['namespace']
    if (not re.fullmatch(r'[a-z][a-z0-9-]{0,30}', name) or
            namespace != 'cloudlab-app-' + name or
            not re.fullmatch(r'https://github[.]com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+[.]git', approval['repository']) or
            not re.fullmatch(r'[a-f0-9]{40}', approval['revision']) or
            not re.fullmatch(r'[a-f0-9]{40}', platform_revision) or
            not re.fullmatch(r'apps/[a-z0-9/-]+[.]yaml', approval['valuesPath']) or
            '..' in approval['valuesPath']):
        raise ValueError('Unapproved service source or destination')
    if set(s['name'] for s in definition['secrets']) - set(approval['secretReferences']):
        raise ValueError('Service cannot select unapproved or privileged credentials')
    if set(s['name'] for s in definition['configMaps']) - set(approval['configMaps']):
        raise ValueError('Service cannot select unapproved configuration')
    for request in definition['data'].values():
        if request['credentialReference'] not in approval['secretReferences']:
            raise ValueError('Data requests require approved scoped credentials')
    import json
    import yaml
    from playbooks.services.files.contract import ROOT
    output = _render(['helm', 'template', 'services', str(chart_root or ROOT / 'platform/delivery/services'),
                             '-n', 'argocd', '-f', '-'], json.dumps({
                                 'repository': platform_repository, 'revision': platform_revision,
                                 'catalog': [{'definition': definition, 'approval': approval}],
                                 'dataApprovals': {r['credentialReference']: {'service': name, 'kind': kind, 'name': r['name'],
                                     'item': ('cnpg' if kind == 'database' else 's3') + '-' + name + '-production'}
                                     for kind, r in definition['data'].items()}}))
    return [obj for obj in yaml.safe_load_all(output) if obj]
