"""Guard the existing net8 native locks; locked restore verifies graph resolution."""
import base64
import json
import re

PROJECTS = frozenset(name.lower() for name in (
    'Sdk', 'Runner.Common', 'Runner.Sdk', 'Runner.Listener', 'Runner.Worker',
    'Runner.PluginHost', 'Runner.Plugins', 'Test'))
FRAMEWORKS = frozenset(('net8.0', 'net8.0/linux-x64'))
IDENTIFIER = re.compile(r'[A-Za-z0-9_]+(?:[.-][A-Za-z0-9_]+)*')
NUMBER = r'(?:0|[1-9][0-9]*)'
SUFFIX = r'(?:-[A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)*)?(?:[+][A-Za-z0-9-]+(?:[.][A-Za-z0-9-]+)*)?'
VERSION = re.compile(NUMBER + r'(?:[.]' + NUMBER + r'){0,3}' + SUFFIX)
RESOLVED = re.compile(NUMBER + r'[.]' + NUMBER + r'[.]' + NUMBER + r'(?:[.]' + NUMBER + r')?' + SUFFIX)


def identifier(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not IDENTIFIER.fullmatch(value):
        raise ValueError('NuGet lock contains an unsafe package identifier')


def constraint(value):
    if (not isinstance(value, str) or not 1 <= len(value) <= 256 or
            any(ord(char) < 32 or ord(char) > 126 for char in value)):
        raise ValueError('NuGet lock requires an explicit version constraint')
    if VERSION.fullmatch(value):
        return
    if value.startswith('[') and value.endswith(']') and VERSION.fullmatch(value[1:-1]):
        return
    if len(value) < 3 or value[0] not in '[(' or value[-1] not in '])' or value.count(',') != 1:
        raise ValueError('NuGet lock version range grammar differs')
    lower, upper = (bound.strip(' ') for bound in value[1:-1].split(','))
    if (not lower and not upper or
            lower and not VERSION.fullmatch(lower) or upper and not VERSION.fullmatch(upper) or
            not lower and value[0] != '(' or not upper and value[-1] != ')'):
        raise ValueError('NuGet lock version range bounds differ')


def content_hash(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9+/]{86}==', value):
        raise ValueError('NuGet lock requires a canonical SHA512 content hash')
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 64 or base64.b64encode(raw).decode() != value:
        raise ValueError('NuGet lock requires a canonical SHA512 content hash')


def unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('NuGet lock contains duplicate JSON fields')
        result[name] = value
    return result


def packages(graph):
    if not isinstance(graph, dict):
        raise ValueError('NuGet lock requires a package map')
    seen = set()
    for name, entry in graph.items():
        identifier(name)
        if name.lower() in seen:
            raise ValueError('NuGet lock contains ambiguous package identities')
        seen.add(name.lower())
        if not isinstance(entry, dict):
            raise ValueError('NuGet lock package must be an object')
        kind = entry.get('type')
        if kind == 'Project':
            if name.lower() not in PROJECTS or set(entry) - {'type', 'dependencies'}:
                raise ValueError('NuGet lock references an unreviewed project')
        else:
            fields = {'type', 'resolved', 'contentHash'}
            if kind == 'Direct':
                fields.add('requested')
                constraint(entry.get('requested'))
            elif kind != 'Transitive':
                raise ValueError('Unsupported NuGet dependency type')
            if not fields <= set(entry) or set(entry) - fields - {'dependencies'}:
                raise ValueError('NuGet lock package fields differ')
            resolved = entry.get('resolved')
            if not isinstance(resolved, str) or len(resolved) > 64 or not RESOLVED.fullmatch(resolved):
                raise ValueError('NuGet lock requires an exact resolved package version')
            content_hash(entry.get('contentHash'))
        dependencies = entry.get('dependencies', {})
        if not isinstance(dependencies, dict):
            raise ValueError('NuGet lock requires an explicit dependency map')
        related = set()
        for dependency, requested in dependencies.items():
            identifier(dependency)
            if dependency.lower() in related:
                raise ValueError('NuGet lock contains ambiguous dependency identities')
            related.add(dependency.lower())
            constraint(requested)


def document(raw):
    if not isinstance(raw, (bytes, str)) or len(raw) > 4 * 1024 * 1024:
        raise ValueError('NuGet lock input exceeds its supported size or type')
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise ValueError('Malformed NuGet lock document') from None
    if (not isinstance(value, dict) or set(value) != {'version', 'dependencies'} or
            type(value['version']) is not int or value['version'] != 1 or
            not isinstance(value['dependencies'], dict) or not value['dependencies'] or
            set(value['dependencies']) - FRAMEWORKS):
        raise ValueError('NuGet lock requires its existing version-one net8 schema')
    for graph in value['dependencies'].values():
        packages(graph)
    return value


def validate_lock(old, new):
    before, after = document(old), document(new)
    if set(before['dependencies']) != set(after['dependencies']):
        raise ValueError('NuGet lock cannot change its reviewed target frameworks')
