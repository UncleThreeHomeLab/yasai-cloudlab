// Offline native-browser regression. Synthetic CA exists only inside isolated tmpfs HOME.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdtempSync, readFileSync, mkdirSync, rmSync} from 'node:fs';
import {execFileSync, spawn} from 'node:child_process';
import net from 'node:net';
import {EventEmitter} from 'node:events';
import {createServer} from 'node:https';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {authorize, origins, callback, corsEvidence, finish} from './browser-live.mjs';
import {enrollViewer} from '/proof/disposable.mjs';
const {chromium}=createRequire('/proof/package.json')('playwright');
const directory=mkdtempSync(join(tmpdir(),'preview-live-check-'));
const login='login.example.invalid', a='preview-'+ 'a'.repeat(32)+'.internal.example.invalid';
const b='preview-'+ 'b'.repeat(32)+'.internal.example.invalid', foreign='foreign.example.invalid';
const issuer='https://'+login+'/realms/applications';
const redirect='https://'+a+'/previews/'+ 'a'.repeat(32)+'/callback';
const other='https://'+b+'/previews/'+ 'b'.repeat(32)+'/callback';
let browser,server,mode='valid', requests=[], stage='certificate', credentialCreated=false, profileCompleted=false;
const openssl=args=>execFileSync('openssl',args,{cwd:directory,stdio:'ignore'});
const launch=()=>chromium.launch({headless:true,env:{...process.env,HOME:directory},args:[
  '--host-resolver-rules='+[login,a,b,foreign].map(host=>'MAP '+host+' 127.0.0.1').join(',')
]});
try {
  openssl(['req','-x509','-newkey','rsa:2048','-nodes','-keyout','ca.key','-out','ca.pem','-days','1',
    '-subj','/CN=Ephemeral Preview Fixture CA','-addext','basicConstraints=critical,CA:TRUE']);
  openssl(['req','-newkey','rsa:2048','-nodes','-keyout','server.key','-out','server.csr','-subj','/CN='+login]);
  const {writeFileSync}=await import('node:fs');
  writeFileSync(join(directory,'extensions'),'subjectAltName='+[login,a,b,foreign].map(host=>'DNS:'+host).join(',')+'\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n');
  openssl(['x509','-req','-in','server.csr','-CA','ca.pem','-CAkey','ca.key','-CAcreateserial','-out','server.pem','-days','1','-extfile','extensions']);
  server=createServer({key:readFileSync(join(directory,'server.key')),cert:readFileSync(join(directory,'server.pem'))},(request,response)=>{
    requests.push({host:request.headers.host,path:request.url});
    if(requests.length>200) { response.writeHead(500); response.end(); return; }
    if(request.headers.host===login) {
      if(mode==='enrollment') {
        response.setHeader('Content-Type','text/html');
        if(request.url=== '/realms/applications/account/') {
          response.end('<form action="/enroll/password" method="post"><label>Username<input name="username"></label><label>Password<input name="password" type="password"></label><button>Sign In</button></form>'); return;
        }
        if(request.url==='/enroll/password' && request.method==='POST') {
          response.end(`<button onclick="register()">Register</button><script>async function register() {
            const credential=await navigator.credentials.create({publicKey:{challenge:new Uint8Array(32),
              rp:{name:'Synthetic enrollment'},user:{id:new Uint8Array([1]),name:'fixture',displayName:'Fixture'},
              pubKeyCredParams:[{type:'public-key',alg:-7}],timeout:3000,attestation:'none'}});
            if(credential) { await fetch('/enroll/credential',{method:'POST'}); location.href='/enroll/profile'; }
          }</script>`); return;
        }
        if(request.url==='/enroll/credential' && request.method==='POST') {
          credentialCreated=true; response.end(''); return;
        }
        if(request.url==='/enroll/profile') {
          response.end('<form action="/enroll/complete" method="post"><label>First name<input name="first"></label><label>Last name<input name="last"></label><button>Submit</button></form>'); return;
        }
        if(request.url==='/enroll/complete' && request.method==='POST') {
          let body=''; request.on('data',chunk=>{body+=chunk;if(body.length>256)request.destroy();});
          request.on('end',()=>{profileCompleted=body==='first=Fixture&last=Viewer';response.end('<h1>Personal info</h1>');}); return;
        }
        response.writeHead(404); response.end(''); return;
      }
      if(request.url.startsWith('/realms/applications/protocol/openid-connect/auth')) {
        if(mode==='reject') { response.writeHead(400); response.end('Invalid parameter: redirect_uri'); return; }
        response.writeHead(302,{Location:issuer+'/login-actions/authenticate'}); response.end(); return;
      }
      let target=redirect+'?code=synthetic-code&state=synthetic-state';
      if(mode==='path') target=redirect+'/changed?code=synthetic-code&state=synthetic-state';
      if(mode==='empty-path') target=redirect+'/changed';
      if(mode==='origin') target='https://'+foreign+'/changed?code=synthetic-code&state=synthetic-state';
      if(mode==='fragment') target+='#private-fragment';
      if(mode==='duplicate') target+='&code=duplicate';
      if(mode==='unknown') target+='&unknown=private-value';
      if(mode==='popup') { response.end('<script>open("https://'+foreign+'/popup?code=private-code&state=private-state")</script>'); return; }
      response.writeHead(302,{Location:target}); response.end(); return;
    }
    if(mode==='hang' && request.headers['sec-fetch-dest']==='iframe') return;
    response.writeHead(200,{'Content-Type':'application/json','Cache-Control':'no-store'});
    response.end('{"callback":true}');
  });
  await new Promise(resolve=>server.listen(443,'127.0.0.1',resolve));
  stage='untrusted'; browser=await launch();
  let context=await browser.newContext(), page=await context.newPage();
  await assert.rejects(page.goto(redirect,{timeout:10000}),/ERR_CERT_AUTHORITY_INVALID/);
  await browser.close(); browser=undefined;
  // NSS is already supplied by the pinned browser. No downloaded trust tool or TLS bypass.
  stage='trust-import'; mkdirSync(join(directory,'.pki','nssdb'),{recursive:true});
  openssl(['x509','-in','ca.pem','-outform','DER','-out','ca.der']);
  try { execFileSync('python3',['-c',String.raw`
import ctypes as c, pathlib, sys
n=c.CDLL('libnss3.so'); p=c.c_void_p
def bind(name,args,result):
 f=getattr(n,name); f.argtypes=args; f.restype=result; return f
assert bind('NSS_InitReadWrite',[c.c_char_p],c.c_int)(('sql:'+sys.argv[1]+'/.pki/nssdb').encode())==0
raw=pathlib.Path(sys.argv[1]+'/ca.der').read_bytes()
class Item(c.Structure): _fields_=[('type',c.c_uint),('data',p),('len',c.c_uint)]
buffer=c.create_string_buffer(raw); item=Item(0,c.cast(buffer,p),len(raw))
db=bind('CERT_GetDefaultCertDB',[],p)()
cert=bind('CERT_NewTempCertificate',[p,c.POINTER(Item),c.c_char_p,c.c_int,c.c_int],p)(db,c.byref(item),None,0,1); assert cert
slot=bind('PK11_GetInternalKeySlot',[],p)(); assert slot
if bind('PK11_NeedUserInit',[p],c.c_int)(slot):
 assert bind('PK11_InitPin',[p,c.c_char_p,c.c_char_p],c.c_int)(slot,None,b'')==0
assert bind('PK11_ImportCert',[p,p,c.c_ulong,c.c_char_p,c.c_int],c.c_int)(slot,cert,0,b'ephemeral-preview-ca',0)==0
class Trust(c.Structure): _fields_=[('sslFlags',c.c_uint),('emailFlags',c.c_uint),('objectSigningFlags',c.c_uint)]
trust=Trust(0x18,0,0); db=bind('CERT_GetDefaultCertDB',[],p)()
assert bind('CERT_ChangeCertTrust',[p,p,c.POINTER(Trust)],c.c_int)(db,cert,c.byref(trust))==0
bind('CERT_DestroyCertificate',[p],None)(cert)
bind('PK11_FreeSlot',[p],None)(slot)
assert bind('NSS_Shutdown',[],c.c_int)()==0
`,directory],{stdio:'pipe'}); } catch(error) {
    const line=/line (\d+)/.exec(error.stderr?.toString()||'');
    if(line) console.error(JSON.stringify({trust_step:Number(line[1])}));
    throw new Error('Synthetic trust import failed');
  }
  stage='trusted'; browser=await launch(); context=await browser.newContext({serviceWorkers:'block'}); page=await context.newPage();
  page.setDefaultTimeout(8000); page.setDefaultNavigationTimeout(8000);
  stage='enrollment'; mode='enrollment'; const enrollmentStages=[];
  await enrollViewer(page,context,{username:'fixture',password:'synthetic-password'},issuer,value=>enrollmentStages.push(value));
  assert.equal(credentialCreated,true); assert.equal(profileCompleted,true);
  assert.deepEqual(enrollmentStages,['account enrollment','account password','WebAuthn registration','account session']);
  mode='valid';
  const input={issuer,redirect,state:'synthetic-state',authorization:issuer+'/protocol/openid-connect/auth?state=initial'};
  stage='redirect'; requests=[];
  assert.equal((await authorize(page,context,input)).callback,redirect+'?code=synthetic-code&state=synthetic-state');
  assert.equal(requests.filter(request=>request.host!==login).length,0);
  for(const variant of ['path','empty-path','origin','fragment','duplicate','unknown','popup']) {
    stage=variant;
    mode=variant; requests=[];
    await assert.rejects(authorize(page,context,input));
    assert.equal(requests.filter(request=>request.host!==login).length,0);
  }
  stage='issuer-rejection'; mode='reject'; assert.deepEqual(await authorize(page,context,input,true),{rejected:true});
  mode='origin'; await assert.rejects(authorize(page,context,input,true));
  // Interception was removed: this is a real trusted HTTPS response at the callback.
  stage='release'; mode='valid'; requests=[];
  assert.equal((await page.goto(redirect)).status(),200);
  assert.equal(requests.length,1);
  stage='origins'; assert.deepEqual(await origins(context,[redirect,other]),{origins:true,storage:true,dom:true,cors:true});
  stage='bounded-iframe'; mode='hang';
  const started=Date.now(); await assert.rejects(origins(context,[redirect,other]));
  assert.ok(Date.now()-started<10000); mode='valid';
  assert.equal(corsEvidence(new Map([['one',{status:200}],['two',{error:'MissingAllowOriginHeader'}]])),false);
  assert.equal(corsEvidence(new Map([['one',{error:'MissingAllowOriginHeader'}]])),false);
  assert.equal(corsEvidence(new Map([['one',{status:200,error:'InsecurePrivateNetwork'}]])),false);
  for(const suffix of ['#fragment','&code=duplicate','&unknown=private','&error=denied']) {
    assert.throws(()=>callback(redirect+'?code=secret&state=synthetic-state'+suffix,redirect,'synthetic-state',issuer));
  }
  stage='protocol-redaction';
  const delayed=new EventEmitter();
  let drained=false, release;
  delayed.end=()=>{ release=()=>delayed.emit('close'); };
  const drain=finish(delayed,{failed:true}).then(()=>{drained=true;});
  await Promise.resolve(); assert.equal(drained,false); setImmediate(release);
  await drain; assert.equal(drained,true);
  const child=spawn(process.execPath,['--input-type=module','-e',
    "setTimeout(()=>import('/fixture/browser-live.mjs').then(module=>module.serve()),1200)"],{stdio:['ignore','pipe','pipe']});
  const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  let logs='', socket;
  child.stdout.on('data',chunk=>{ logs+=chunk; if(logs.length>4096) child.kill(); });
  child.stderr.on('data',chunk=>{ logs+=chunk; if(logs.length>4096) child.kill(); });
  const childDeadline=setTimeout(()=>child.kill(),8000);
  try {
    const started=performance.now(), readyDeadline=started+5000;
    while(performance.now()<readyDeadline) {
      try {
        socket=await new Promise((resolve,reject)=>{
          const candidate=net.createConnection(5056,'127.0.0.1');
          candidate.once('connect',()=>resolve(candidate)); candidate.once('error',reject);
        }); break;
      } catch(error) {
        if(error.code!=='ECONNREFUSED') throw new Error('Synthetic readiness failed');
        await new Promise(resolve=>setTimeout(resolve,50));
      }
    }
    assert.ok(socket); assert.ok(performance.now()-started>=1200);
    let raw=''; socket.on('data',chunk=>{raw+=chunk;});
    socket.write('{"action":"authorize","private":"https://private-repository.invalid/?credential=private-password"}\n');
    assert.deepEqual(await exited,{code:0,signal:null});
    assert.equal(raw,'{"failed":true}\n');
    assert.equal(logs,'');
  } finally { clearTimeout(childDeadline); socket?.destroy(); child.kill(); }
  stage='terminal-enrollment';
  for(const fault of ['launch','context','account-enrollment','account-password','webauthn-registration','account-session','post-ready']) {
    // Replace Playwright only inside this synthetic child; execute the actual serve catch and shared helper.
    const source=`
      import {createRequire} from 'node:module';
      const {chromium}=createRequire('/proof/package.json')('playwright');
      const fault=${JSON.stringify(fault)}, refuse=()=>{throw new Error('private-sentinel-never-log');};
      const page={setDefaultTimeout(){},setDefaultNavigationTimeout(){},
        async goto(){if(fault==='account-enrollment')refuse();},
        getByLabel(){return {async fill(){if(fault==='account-password')refuse();},async waitFor(){},async isVisible(){return false;}};},
        async waitForLoadState(){if(fault==='webauthn-registration')refuse();},
        getByRole(role){if(fault==='account-session'&&role==='heading')refuse();return {async click(){},async waitFor(){},async count(){return 0;}};}};
      const context={async newPage(){return page;},async newCDPSession(){return {async send(){}};},async close(){}};
      chromium.launch=async()=>{if(fault==='launch')refuse();return {async newContext(){if(fault==='context')refuse();return context;},async close(){}};};
      await (await import('/fixture/browser-live.mjs')).serve();`;
    const process=spawn(globalThis.process.execPath,['--input-type=module','-e',source],{stdio:['ignore','pipe','pipe']});
    const exited=new Promise(resolve=>process.once('exit',(code,signal)=>resolve({code,signal})));
    let socket, logs='', raw='', sent=false;
    const bounded=chunk=>{logs+=chunk;if(logs.length>4096)process.kill();};
    process.stdout.on('data',bounded);process.stderr.on('data',bounded);
    const deadline=setTimeout(()=>process.kill(),8000);
    try {
      const readyDeadline=performance.now()+5000;
      while(performance.now()<readyDeadline) {
        try {
          socket=await new Promise((resolve,reject)=>{
            const candidate=net.createConnection(5056,'127.0.0.1');
            candidate.once('connect',()=>resolve(candidate));candidate.once('error',reject);
          });break;
        } catch(error) {if(error.code!=='ECONNREFUSED')throw error;await new Promise(resolve=>setTimeout(resolve,20));}
      }
      assert.ok(socket);
      socket.on('data',chunk=>{
        raw+=chunk;if(raw.length>32768)socket.destroy();
        if(fault==='post-ready' && raw.includes('\n') && !sent) {sent=true;socket.write('{"action":"invalid"}\n');}
      });
      socket.write(JSON.stringify({action:'enroll',issuer,gateway:'100.64.0.1',hosts:[a,b],
        viewer:{username:'fixture',email:'fixture@example.invalid',password:'synthetic-password'}})+'\n');
      assert.deepEqual(await exited,{code:0,signal:null});
      assert.equal(raw,fault==='post-ready' ? '{"ready":true}\n{"failed":true}\n' :
        JSON.stringify({failed:true,enrollmentStage:fault})+'\n');
      assert.equal(logs,'');
    } finally {clearTimeout(deadline);socket?.destroy();process.kill();}
  }
  console.log('{"enrollment":true,"terminal_enrollment":true,"trusted_tls":true,"redirect_guard":true,"no_callback_dispatch":true,"guard_removed":true,"native_cors":true}');
} catch {
  console.error(JSON.stringify({failed_stage:stage})); process.exitCode=1;
} finally {
  if(browser) await browser.close();
  if(server) { server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)); }
  rmSync(directory,{recursive:true,force:true});
}
