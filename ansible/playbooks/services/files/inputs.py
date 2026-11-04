"""Load the complete private catalog before mutation; public base remains optional."""
from pathlib import Path
import yaml

from dotenv import dotenv_values

from playbooks.services.files.contract import ROOT, validate
from playbooks.services.files.gitops import resources


def catalog(required=False, *, coordinates=False):
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    if required:
        if not environment.get('PRIVATE_CONFIG_REPOSITORY') or not environment.get('OP_SERVICE_ACCOUNT_TOKEN'):
            raise ValueError('Enabled services require the designated private configuration source and its existing reader')
        import os
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        from playbooks.services.files.source import read
        value = read(environment, include_revision=coordinates)
        public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
        return (validate_catalog(value[0], public=public), value[1]) if coordinates else validate_catalog(value, public=public)
    filename = environment.get('SERVICE_CATALOG_FILE')
    if not filename:
        if required: raise ValueError('Missing .env input: SERVICE_CATALOG_FILE')
        return None
    path = Path(filename)
    if path.is_absolute() or '..' in path.parts or not path.as_posix().startswith('docs/local/'):
        raise ValueError('Service catalog must be an ignored file under docs/local')
    target = (ROOT / path).resolve()
    if ROOT / 'docs/local' not in target.parents or not target.is_file() or target.stat().st_size > 1024 * 1024:
        raise ValueError('Private service catalog unavailable; refused before planning or mutation')
    value = yaml.safe_load(target.read_text())
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    return validate_catalog(value, public=public)


def validate_catalog(value, *, public=None, chart_root=None):
    """Production readers supply public owner coordinates; no source fallback."""
    if (not isinstance(value, dict) or set(value) != {'catalog', 'dataApprovals'} or
            not isinstance(value['catalog'], list) or len(value['catalog']) > 20 or
            not isinstance(value['dataApprovals'], dict) or len(value['dataApprovals']) > 40):
        raise ValueError('Private service catalog requires complete catalog and data approvals')
    if public is not None and chart_root is None:
        from playbooks.services.files.owner import chart
        with chart(public) as selected:
            return validate_catalog(value, public=public, chart_root=selected)
    names = set()
    platform = public if public is not None else yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    platform_repository = platform['repository']
    revision = platform.get('services', {}).get('revision') if public is not None else 'a' * 40
    from playbooks.data.files.requests import request
    for entry in value['catalog']:
        if set(entry) != {'definition', 'approval', 'publication'} or entry['publication'] not in ('ready', 'published', 'retired'):
            raise ValueError('Service catalog entries require explicit ready, published or retired intent')
        definition = validate(entry['definition'])
        name = entry['approval']['name']
        if name in names: raise ValueError('Duplicate service catalog namespace')
        names.add(name)
        request(name, definition['data'], value['dataApprovals'])
        resources(definition, entry['approval'], platform_repository, revision, chart_root=chart_root)
    return value


def private_dns_names():
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    value = catalog(required=public.get('services', {}).get('enabled', False))
    if value is None: return []
    names = []
    for entry in value['catalog']:
        for exposure in [entry['definition']['exposure']] + entry['definition'].get('additionalExposures', []):
            if exposure['class'] == 'private' and entry['publication'] == 'published':
                names.append(exposure['hostname'].split('.', 1)[0])
    return sorted(set(names))
