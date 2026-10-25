"""Explicit, isolated API-server qualification of the production preview policies."""
import argparse
import copy
import json
import os
import re
from pathlib import Path
import secrets
import shlex

from dotenv import dotenv_values
from playbooks.previews.files.check import example, render
from playbooks.previews.files.contract import canonical, catalog, digest, names, GENERATED_CONFIGMAPS
from playbooks.previews.files.resources import resources


def fixture(nonce):
    settings = example()
    row = settings['approvals'][0]
    row['instance'] = nonce
    namespace = names(row)['namespace']
    settings['ownership'] = {namespace: nonce + ':' + digest(canonical(row))}
    for number in range(256):
        instance = format(number, '032x')
        if instance != nonce and len(settings['ownership']) < 256:
            settings['ownership']['cloudlab-preview-' + instance] = instance + ':' + 'd' * 64
    catalog(settings)
    control = 'cloudlab-preview-proof-' + nonce[:16]
    username = 'system:serviceaccount:' + control + ':proof'
    selector = {'matchLabels': {'cloudlab.io/admission-proof': nonce}}
    objects = render({'enabled': True, 'permissionsEnabled': False, 'catalog': settings,
                      'platformRepository': 'https://github.com/example/platform.git'})
    selected = []
    for value in objects:
        if value['kind'] in ('ValidatingAdmissionPolicy', 'ValidatingAdmissionPolicyBinding'):
            value['metadata']['name'] = value['metadata']['name'].replace('cloudlab-preview', control, 1)
            if value['kind'] == 'ValidatingAdmissionPolicy':
                value['spec']['matchConstraints']['objectSelector'] = copy.deepcopy(selector)
                for condition in value['spec']['matchConditions']:
                    condition['expression'] = condition['expression'].replace('system:serviceaccount:argocd:cloudlab-previews', username)
            else:
                value['spec']['policyName'] = value['metadata']['name']
                value['spec']['matchResources'] = {'objectSelector': copy.deepcopy(selector)}
        else:
            continue
        selected.append(value)
    definitions = resources(row, settings, 'https://github.com/example/platform.git', 'native-proof')
    return {'nonce': nonce, 'control': control, 'username': username, 'namespace': definitions[0],
            'binding': definitions[1], 'objects': selected,
            'project': next(obj for obj in definitions if obj['kind'] == 'AppProject'),
            'appset': next(obj for obj in definitions if obj['kind'] == 'ApplicationSet'),
            'generatedConfigMaps': list(GENERATED_CONFIGMAPS), 'authorization': settings['ownership']}


REMOTE = r'''
import copy,json,subprocess,sys,time
sys.path.insert(0,'/opt/cloudlab')
from playbooks.istio.files.kube import get,kube,wait
p=json.load(sys.stdin)
created=[]
marker='cloudlab.io/admission-proof'
prefix=p['control']
assert prefix=='cloudlab-preview-proof-'+p['nonce'][:16]
assert p['namespace']['metadata']['name']=='cloudlab-preview-'+p['nonce']
assert p['username']=='system:serviceaccount:'+prefix+':proof'
paths={'Namespace':('/api/v1/namespaces/','namespace'),
       'ConfigMap':('/api/v1/namespaces/'+prefix+'/configmaps/','configmap'),
       'ValidatingAdmissionPolicy':('/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicies/','validatingadmissionpolicy'),
       'ValidatingAdmissionPolicyBinding':('/apis/admissionregistration.k8s.io/v1/validatingadmissionpolicybindings/','validatingadmissionpolicybinding')}
def observed(obj):
    return get(paths[obj['kind']][1],obj['metadata']['name'],obj['metadata'].get('namespace'))
def create(obj):
    obj=copy.deepcopy(obj)
    meta=obj['metadata']
    assert obj['kind'] in paths
    assert meta['name'].startswith(prefix) or (obj['kind']=='ConfigMap' and meta['name']=='authorization' and meta['namespace']==prefix) or meta['name']=='cloudlab-preview-'+p['nonce']
    if observed(obj):raise RuntimeError('Native fixture collision; adoption refused')
    meta.setdefault('annotations',{})[marker]=p['nonce']
    meta.setdefault('labels',{})[marker]=p['nonce']
    # Record before POST so interrupted creates can be conservatively recovered.
    receipt={'object':obj,'uid':None}
    created.append(receipt)
    value=json.loads(kube('create','-f','-','-o','json',document=obj))
    receipt['uid']=value['metadata']['uid']
    return value
def probe(obj=None,*,delete=None,denied=None,uid=None,uid_denied=False,denial_timeout=0):
    arguments=['/usr/local/bin/k3s','kubectl','--request-timeout=20s','--as='+p['username'],'--as-group=system:masters']
    body=copy.deepcopy(obj)
    if body is not None:body['metadata'].setdefault('labels',{})[marker]=p['nonce']
    if delete:
        body={'apiVersion':'v1','kind':'DeleteOptions','dryRun':['All']}
        if uid:body['preconditions']={'uid':uid}
        arguments+=['delete','--raw=/api/v1/namespaces/'+delete+'?dryRun=All','-f','-']
    else:arguments+=['create','--dry-run=server','-f','-']
    started=time.monotonic()
    attempts=0
    while True:
        attempts+=1
        timeout=min(30,max(0.1,denial_timeout-(time.monotonic()-started))) if denial_timeout else 30
        result=subprocess.run(arguments,input=json.dumps(body),capture_output=True,text=True,timeout=timeout)
        remaining=denial_timeout-(time.monotonic()-started)
        if not (denied and result.returncode==0 and denial_timeout and remaining>0):break
        time.sleep(min(1,remaining))
    if uid_denied:
        if not result.returncode or not any(word in result.stderr.lower() for word in ('uid','precondition')):
            print('Native UID probe return code:',result.returncode,'stderr:',result.stderr,file=sys.stderr,flush=True)
            raise RuntimeError('Native fixture did not establish UID precondition denial')
    elif denied:
        if not result.returncode or prefix+'-'+denied not in result.stderr:
            print('Native denial probe return code:',result.returncode,'stderr:',result.stderr,file=sys.stderr,flush=True)
            raise RuntimeError('Native fixture did not establish named admission denial')
    elif result.returncode:
        print(result.stderr,file=sys.stderr,flush=True)
        raise RuntimeError('Native fixture positive admission failed')
    return {'attempts':attempts,'elapsed_seconds':round(time.monotonic()-started,3)}
def inventory(namespace):
    versions=[('v1',json.loads(kube('get','--raw=/api/v1'))['resources'])]
    groups=json.loads(kube('get','--raw=/apis'))['groups']
    if len(groups)>100:raise RuntimeError('Native fixture API inventory exceeds bound')
    discovered=set()
    for group in groups:
        for served in group['versions']:
            version=served['groupVersion']
            if version in discovered:continue
            discovered.add(version)
            if len(discovered)>200:raise RuntimeError('Native fixture API inventory exceeds bound')
            versions.append((version,json.loads(kube('get','--raw=/apis/'+version))['resources']))
    known={row['uid'] for row in created if row['uid']}
    collections=set()
    for version,definitions in versions:
        if len(definitions)>1000:raise RuntimeError('Native fixture API inventory exceeds bound')
        for resource in definitions:
            if not resource.get('namespaced') or '/' in resource['name'] or 'list' not in resource.get('verbs',[]):continue
            collection=(version.split('/')[0] if '/' in version else '',resource['name'])
            if collection in collections:continue
            collections.add(collection)
            if len(collections)>1000:raise RuntimeError('Native fixture API inventory exceeds bound')
            route=('/api/v1' if version=='v1' else '/apis/'+version)+'/namespaces/'+namespace+'/'+resource['name']
            listing=json.loads(kube('get','--raw='+route))
            if listing.get('metadata',{}).get('continue') or len(listing.get('items',[]))>500:
                raise RuntimeError('Incomplete native fixture cleanup inventory')
            for obj in listing.get('items',[]):
                meta=obj['metadata']
                automatic=(resource['kind']=='ServiceAccount' and meta['name']=='default') or (resource['kind']=='ConfigMap' and meta['name'] in p['generatedConfigMaps']) or resource['kind']=='Event'
                if meta.get('annotations',{}).get('cloudlab.io/retention') or meta.get('annotations',{}).get('helm.sh/resource-policy')=='keep' or meta.get('finalizers') not in (None,[],['foregroundDeletion']):
                    raise RuntimeError('Retained resource blocks native fixture cleanup')
                if meta['uid'] not in known and not automatic:
                    raise RuntimeError('Foreign resource blocks native fixture namespace cleanup')
def cleanup():
    failures=[]
    for receipt in reversed(created):
        obj=receipt['object']
        try:
            current=observed(obj)
            if not current:continue
            if current['metadata'].get('annotations',{}).get(marker)!=p['nonce'] or current['metadata']['uid']!=receipt['uid']:
                raise RuntimeError('Native fixture cleanup ownership changed')
            if obj['kind']=='Namespace':inventory(obj['metadata']['name'])
            route=paths[obj['kind']][0]+obj['metadata']['name']
            kube('delete','--raw='+route,'-f','-',document={'apiVersion':'v1','kind':'DeleteOptions',
                'preconditions':{'uid':receipt['uid'],'resourceVersion':current['metadata']['resourceVersion']}})
            wait(lambda:not observed(obj),'owned native fixture removal',timeout=60)
        except Exception:failures.append(obj['kind']+'/'+obj['metadata']['name'])
    if failures:raise RuntimeError('Native fixture cleanup retained: '+','.join(failures))
if p.get('cleanupNamespace'):
    name=p['cleanupNamespace']
    if name not in (prefix,'cloudlab-preview-'+p['nonce']):raise RuntimeError('Cleanup target is outside exact fixture scope')
    current=get('namespace',name)
    if current:
        if current['metadata']['uid']!=p['cleanupUID'] or current['metadata'].get('annotations',{}).get(marker)!=p['nonce']:
            raise RuntimeError('Retained fixture namespace identity changed')
        created.append({'object':{'kind':'Namespace','metadata':{'name':name}},'uid':p['cleanupUID']})
        cleanup()
    print(json.dumps({'owned_fixture_cleanup':True,'namespace_removed':current is not None,'production_mutations':0}))
    sys.exit(0)
baseline={name:get('namespace',name)['metadata']['uid'] for name in ('argocd','cloudlab-identity','cloudlab-app-notes')}
try:
    create({'apiVersion':'v1','kind':'Namespace','metadata':{'name':prefix,'labels':{'cloudlab.io/owner':'cloudlab-preview-admission-proof'}}})
    for kind in ('ValidatingAdmissionPolicy','ValidatingAdmissionPolicyBinding'):
        for obj in p['objects']:
            if obj['kind']==kind:create(obj)
    for obj in p['objects']:
        if obj['kind']!='ValidatingAdmissionPolicy':continue
        def compiled():
            actual=observed(obj)
            if 'paramKind' in actual['spec']:raise RuntimeError('Native fixture cannot depend on parameters')
            authorization=[row['expression'] for row in actual['spec']['variables'] if row['name']=='authorization']
            if len(authorization)!=1 or json.loads(authorization[0])!=p['authorization']:
                raise RuntimeError('Native fixture authorization differs')
            status=actual.get('status',{})
            if status.get('typeChecking',{}).get('expressionWarnings'):
                raise RuntimeError('Native fixture policy type checking failed')
            return status.get('observedGeneration')==actual['metadata']['generation']
        wait(compiled,'native fixture policy compilation',timeout=60)
    for obj in p['objects']:
        if obj['kind']=='ValidatingAdmissionPolicyBinding' and 'paramRef' in observed(obj)['spec']:
            raise RuntimeError('Native fixture binding cannot depend on parameters')
    ns=p['namespace']
    probe(ns)
    bad=copy.deepcopy(ns);bad['metadata']['labels']['pod-security.kubernetes.io/enforce']='privileged'
    probe(bad,denied='namespaces')
    probe({'apiVersion':'v1','kind':'Namespace','metadata':{'name':'cloudlab-app-native-proof'}},denied='namespaces')
    probe(delete=prefix,uid=get('namespace',prefix)['metadata']['uid'],denied='namespaces')
    live=create(ns)
    probe(p['binding'])
    probe(p['project'])
    probe(p['appset'])
    wrong=copy.deepcopy(p['project']);wrong['spec']['destinations'][0]['namespace']='cloudlab-app-notes'
    probe(wrong,denied='objects')
    wrong=copy.deepcopy(p['appset']);wrong['spec']['template']['spec']['project']='default'
    probe(wrong,denied='objects')
    wrong=copy.deepcopy(p['appset']);wrong['spec']['template']['spec']['source']['path']='unapproved/chart'
    probe(wrong,denied='objects')
    wrong=copy.deepcopy(p['binding']);wrong['roleRef']['name']='cluster-admin'
    probe(wrong,denied='rolebindings')
    foreign=copy.deepcopy(live);foreign['metadata']['labels']['cloudlab.io/owner']='foreign-proof-owner'
    kube('replace','-f','-',document=foreign)
    probe(p['binding'],denied='rolebindings')
    live=get('namespace',ns['metadata']['name']);live['metadata']['labels']['cloudlab.io/owner']='cloudlab-previews'
    kube('replace','-f','-',document=live)
    # Namespace REST defaults omitted UID before admission; runtime still supplies its recorded UID.
    probe(delete=ns['metadata']['name'])
    unchanged=get('namespace',ns['metadata']['name'])
    if unchanged['metadata']['uid']!=live['metadata']['uid'] or unchanged['metadata'].get('deletionTimestamp'):
        raise RuntimeError('Server-defaulted UID dry-run unexpectedly changed namespace')
    probe(delete=ns['metadata']['name'],uid='00000000-0000-0000-0000-000000000000',uid_denied=True)
    probe(delete=ns['metadata']['name'],uid=live['metadata']['uid'])
    after=get('namespace',ns['metadata']['name'])
    if after['metadata']['uid']!=live['metadata']['uid'] or after['metadata'].get('deletionTimestamp'):
        raise RuntimeError('Native fixture dry-run unexpectedly changed namespace')
    bad={'apiVersion':'v1','kind':'ConfigMap','metadata':{'name':'proof','namespace':'argocd'}}
    probe(bad,denied='objects')
    # Replace only isolated fixture literals; all valid resource authority must disappear.
    for obj in p['objects']:
        if obj['kind']!='ValidatingAdmissionPolicy':continue
        current=observed(obj)
        for variable in current['spec']['variables']:
            if variable['name']=='authorization':variable['expression']='{}'
        kube('replace','-f','-',document=current)
        def empty_compiled():
            actual=observed(obj)
            if actual.get('status',{}).get('typeChecking',{}).get('expressionWarnings'):
                raise RuntimeError('Empty authorization policy type checking failed')
            return actual.get('status',{}).get('observedGeneration')==actual['metadata']['generation']
        wait(empty_compiled,'empty authorization compilation',timeout=60)
    transition=probe(p['project'],denied='objects',denial_timeout=30)
    result={'native_policies':3,'authorization_capacity':len(p['authorization']),'empty_map_denials':1,'positive_dry_runs':6,'server_defaulted_uid_dry_runs':1,'named_policy_denials':10,'uid_precondition_denials':1,'controller_grants_created':0,'production_mutations':0}
    result['empty_map_readiness']=transition
finally:cleanup()
if any(get('namespace',name)['metadata']['uid']!=uid for name,uid in baseline.items()):
    raise RuntimeError('Persistent namespace identity changed during native fixture')
result['owned_fixture_cleanup']=True
print(json.dumps(result,sort_keys=True))
'''


def run(cleanup_namespace=None, cleanup_uid=None, cleanup_marker=None):
    from playbooks.access.files.preflight import ssh
    root = Path(__file__).resolve().parents[4]
    values = dotenv_values(root / '.env', interpolate=False)
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD'):
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'
    if any((cleanup_namespace, cleanup_uid, cleanup_marker)):
        if (not all((cleanup_namespace, cleanup_uid, cleanup_marker)) or
                not re.fullmatch('[a-f0-9]{32}', cleanup_marker) or
                not re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', cleanup_uid) or
                cleanup_namespace not in ('cloudlab-preview-proof-' + cleanup_marker[:16], 'cloudlab-preview-' + cleanup_marker)):
            raise ValueError('Retained fixture cleanup requires its exact namespace, UID and marker')
        payload = fixture(cleanup_marker)
        payload.update(cleanupNamespace=cleanup_namespace, cleanupUID=cleanup_uid)
    else:
        payload = fixture(secrets.token_hex(16))
    diagnostics = '/recovery/preview-native-admission-' + payload['nonce'] + '.log'
    try:
        return json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(REMOTE),
            input=json.dumps(payload), timeout=900, diagnostics=diagnostics))
    except Exception:
        raise RuntimeError('Native preview fixture failed; private diagnostics: ' + diagnostics +
                           '; owned fixture prefix: ' + payload['control']) from None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--live', action='store_true', required=True)
    parser.add_argument('--cleanup-namespace')
    parser.add_argument('--cleanup-uid')
    parser.add_argument('--cleanup-marker')
    args = parser.parse_args()
    print(json.dumps(run(args.cleanup_namespace, args.cleanup_uid, args.cleanup_marker), sort_keys=True))
