// Private ephemeral browser proof. Never log protocol frames, URLs or browser events.
import {createRequire} from 'node:module';
import net from 'node:net';
import {pathToFileURL} from 'node:url';
import {enrollViewer} from '/proof/disposable.mjs';
const {chromium} = createRequire('/proof/package.json')('playwright');
const LIMIT = 32768;
const fail = () => { throw new Error('Preview browser refused'); };
const bounded = value => typeof value === 'string' && value.length > 0 && value.length <= 8192;

export function callback(value, expected, state, issuer) {
  if (!bounded(value) || value.includes('#') || /[\x00-\x20\x7f]/.test(value)) fail();
  const url = new URL(value);
  if (url.origin + url.pathname !== expected || url.username || url.password || url.port || url.hash) fail();
  const keys = [...url.searchParams.keys()];
  if (new Set(keys).size !== keys.length || keys.some(key => !['code','state','iss','session_state'].includes(key))) fail();
  if (!bounded(url.searchParams.get('code')) || url.searchParams.get('state') !== state ||
      (url.searchParams.has('iss') && url.searchParams.get('iss') !== issuer) ||
      (url.searchParams.has('session_state') && !bounded(url.searchParams.get('session_state')))) fail();
  return value;
}

export async function guard(page, context, {authorization, redirect, state, issuer}) {
  const initial = new URL(authorization), accepted = new URL(issuer);
  if (initial.origin !== accepted.origin || initial.username || initial.password || initial.hash || initial.port) fail();
  const cdp = await context.newCDPSession(page);
  let captured, refused = false, pending = 0;
  let location;
  const response = event => {
    if (event.type !== 'Document' || !event.redirectResponse) return;
    try {
      const headers = event.redirectResponse.headers || {};
      const value = Object.entries(headers).find(([key]) => key.toLowerCase() === 'location')?.[1];
      if (typeof value === 'string' && value.length <= 16384) location = new URL(value, event.redirectResponse.url).href;
      else refused = true;
    } catch { refused=true; }
  };
  const otherPages = async route => {
    pending++;
    try {
      let controlled=false;
      try { controlled=route.request().frame().page() === page; } catch { /* Initial popup has no frame yet. */ }
      if (!controlled) { refused = true; await route.abort(); }
      else await route.continue();
    } catch { refused=true; }
    finally { pending--; }
  };
  await context.route('**/*', otherPages);
  cdp.on('Network.requestWillBeSent', response);
  await cdp.send('Network.enable');
  const paused = async event => {
    pending++;
    let proceed = false;
    try {
      const raw = event.request.url;
      const url = new URL(raw);
      const actual = location && location.split('#')[0] === raw.split('#')[0] ? location : raw;
      location = undefined;
      if (url.origin + url.pathname === redirect) {
        // Capture only after native interception has stopped the exact callback hop.
        const valid = callback(actual, redirect, state, issuer);
        if (captured) fail();
        captured = valid;
      } else {
        const secret = raw !== authorization && [...url.searchParams.keys()].some(key => ['code','state','error','error_description','error_uri','session_state'].includes(key));
        const canonical = url.protocol === 'https:' && !url.port && !url.username && !url.password && !url.hash;
        const authentication = url.origin === accepted.origin &&
          (url.pathname.startsWith('/realms/applications/login-actions/') ||
           url.pathname === '/realms/applications/protocol/openid-connect/auth');
        if (!canonical || secret || !(raw === authorization || authentication) || actual.includes('#')) fail();
        proceed = true;
      }
    } catch { refused = true; }
    try { await cdp.send(proceed ? 'Fetch.continueRequest' : 'Fetch.failRequest',
      proceed ? {requestId:event.requestId} : {requestId:event.requestId,errorReason:'Aborted'}); }
    catch { refused = true; }
    finally { pending--; }
  };
  cdp.on('Fetch.requestPaused', paused);
  await cdp.send('Fetch.enable', {patterns:[{urlPattern:'*',resourceType:'Document',requestStage:'Request'}]});
  return {
    result() { if (refused) fail(); return captured; },
    async close() {
      const end = Date.now()+2000;
      while (pending && Date.now()<end) await new Promise(resolve => setTimeout(resolve,10));
      if (pending) fail();
      await cdp.send('Fetch.disable');
      cdp.off('Fetch.requestPaused',paused);
      cdp.off('Network.requestWillBeSent',response);
      await context.unroute('**/*',otherPages);
      await cdp.detach();
      if(refused) fail();
    }
  };
}

export async function authorize(page, context, input, rejected=false) {
  const active = await guard(page,context,input);
  try {
    let response;
    try { response = await page.goto(input.authorization,{waitUntil:'domcontentloaded'}); }
    catch { if (!active.result()) fail(); }
    const captured = active.result();
    if (rejected) {
      if (captured || !response || response.status() !== 400 ||
          new URL(page.url()).origin !== new URL(input.issuer).origin) fail();
      // Keycloak's real invalid redirect response, not an arbitrary 400/login failure.
      if (!/Invalid parameter: redirect_uri/.test(await page.locator('body').innerText({timeout:5000}))) fail();
      return {rejected:true};
    }
    if (!captured) fail();
    return {callback:captured};
  } finally { await active.close(); }
}

export function corsEvidence(rows) {
  return [...rows.values()].some(row => row.status === 200 && row.error === 'MissingAllowOriginHeader');
}

export async function origins(context, callbacks) {
  const [a,b] = await Promise.all(callbacks.map(() => context.newPage()));
  try {
    for (const [index,page] of [a,b].entries()) {
      const url = callbacks[index], response = await page.goto(url);
      if (!response || response.status() !== 200 || page.url() !== url ||
          JSON.stringify(await response.json()) !== '{"callback":true}') fail();
      await page.evaluate(index => {
        localStorage.setItem('preview-proof',String(index));
        document.cookie='__Host-preview-proof='+index+'; Secure; Path=/; SameSite=Strict';
      },index);
    }
    for (const [index,page] of [a,b].entries()) {
      if (!await page.evaluate(index => localStorage.getItem('preview-proof') === String(index) &&
          document.cookie === '__Host-preview-proof='+index,index)) fail();
      if (!await page.evaluate(async url => {
        const response = await fetch(url,{cache:'no-store'});
        return response.status === 200 && (await response.json()).callback === true;
      },callbacks[index])) fail();
    }
    if (new URL(a.url()).origin === new URL(b.url()).origin) fail();
    if (!await a.evaluate(async url => {
      const frame=document.createElement('iframe'); frame.src=url;
      await new Promise((resolve,reject) => {
        const timeout=setTimeout(reject,5000);
        frame.onload=()=>{ clearTimeout(timeout); resolve(); };
        frame.onerror=()=>{ clearTimeout(timeout); reject(); };
        document.body.append(frame);
      });
      try { void frame.contentWindow.document.body; return false; }
      catch(error) { return error.name === 'SecurityError'; }
      finally { frame.remove(); }
    },callbacks[1])) fail();
    const cdp=await context.newCDPSession(a), rows=new Map(), waiting=new Map();
    const request=event => {
      if (event.request.url === callbacks[1] && event.request.method === 'GET' && event.type === 'Fetch') {
        if (rows.size >= 4) return;
        rows.set(event.requestId,waiting.get(event.requestId)||{});
      }
    };
    const extra=event => {
      if (waiting.size >= 16 && !waiting.has(event.requestId)) return;
      const row=rows.get(event.requestId)||waiting.get(event.requestId)||{};
      row.status=event.statusCode; waiting.set(event.requestId,row);
    };
    const failed=event => { if (rows.has(event.requestId)) rows.get(event.requestId).error=event.corsErrorStatus?.corsError; };
    cdp.on('Network.requestWillBeSent',request);
    cdp.on('Network.responseReceivedExtraInfo',extra);
    cdp.on('Network.loadingFailed',failed);
    try {
      await cdp.send('Network.enable');
      await cdp.send('Network.setCacheDisabled',{cacheDisabled:true});
      const unreadable=await a.evaluate(async url => {
        try { await fetch(url,{cache:'no-store'}); return false; } catch { return true; }
      },callbacks[1]);
      const end=Date.now()+3000;
      while (!corsEvidence(rows) && Date.now()<end) await new Promise(resolve=>setTimeout(resolve,20));
      if (!unreadable || !corsEvidence(rows)) fail();
    } finally { await cdp.detach(); rows.clear(); waiting.clear(); }
    return {origins:true,storage:true,dom:true,cors:true};
  } finally { await a.close(); await b.close(); }
}

export function channel(socket) {
  let buffer=Buffer.alloc(0), received=[], waiter, failed=false;
  socket.setTimeout(30000,()=>socket.destroy());
  socket.on('data',chunk=>{
    buffer=Buffer.concat([buffer,chunk]);
    if (buffer.length>LIMIT) { failed=true; socket.destroy(); return; }
    let end;
    while ((end=buffer.indexOf(10))>=0) {
      try { received.push(JSON.parse(buffer.subarray(0,end).toString('utf8'))); }
      catch { failed=true; socket.destroy(); }
      buffer=buffer.subarray(end+1);
      if (received.length>1) { failed=true; socket.destroy(); }
      if (waiter) { const resolve=waiter; waiter=undefined; resolve(); }
    }
  });
  socket.on('error',()=>{ failed=true; if(waiter) waiter(); });
  socket.on('close',()=>{ failed=true; if(waiter) waiter(); });
  return {
    async read(action,keys) {
      if (!received.length && !failed) await new Promise(resolve=>{ waiter=resolve; });
      const value=received.shift();
      if(failed || !value || Array.isArray(value) || value.action!==action ||
          Object.keys(value).sort().join()!==['action',...keys].sort().join()) fail();
      return value;
    },
    send(value) { const raw=JSON.stringify(value); if(raw.length>LIMIT || failed) fail(); socket.write(raw+'\n'); }
  };
}

export async function finish(socket, value) {
  if(socket.destroyed) return;
  await new Promise(resolve=>{
    let settled=false;
    const done=()=>{
      if(settled) return; settled=true;
      clearTimeout(deadline); socket.off('error',done); socket.off('close',done); resolve();
    };
    const deadline=setTimeout(done,2000);
    socket.once('error',done); socket.once('close',done);
    try { socket.end(JSON.stringify(value)+'\n'); } catch { done(); }
  });
}

export async function serve() {
  let accepted=false, browser;
  const server=net.createServer(async socket=>{
    if(accepted) { socket.destroy(); return; } accepted=true; server.close();
    const budget=setTimeout(()=>{ socket.destroy(); if(browser) browser.close().catch(()=>{}); },240000);
    try {
      const wire=channel(socket), input=await wire.read('enroll',['issuer','gateway','hosts','viewer']);
      const issuer=new URL(input.issuer);
      if(issuer.protocol!=='https:' || issuer.pathname!=='/realms/applications' || issuer.port || issuer.username || issuer.password ||
          issuer.search || issuer.hash || !/^login\.[a-z0-9.-]+$/.test(issuer.hostname) ||
          !/^100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$/.test(input.gateway) ||
          !Array.isArray(input.hosts) || input.hosts.length!==2 || new Set(input.hosts).size!==2 ||
          input.hosts.some(host=>!new RegExp('^[a-z0-9-]+-[a-f0-9]{32}\\.internal\\.'+issuer.hostname.slice(6).replaceAll('.','\\.')+'$').test(host)) ||
          Object.keys(input.viewer).sort().join()!=='email,password,username' ||
          Object.values(input.viewer).some(value=>!bounded(value))) fail();
      browser=await chromium.launch({headless:true,args:['--host-resolver-rules='+[issuer.hostname,...input.hosts].map(host=>'MAP '+host+' '+input.gateway).join(',') ]});
      const context=await browser.newContext({serviceWorkers:'block'}), page=await context.newPage();
      page.setDefaultTimeout(20000); page.setDefaultNavigationTimeout(25000);
      await enrollViewer(page,context,input.viewer,input.issuer,()=>{});
      wire.send({ready:true});
      for(let index=0;index<2;index++) {
        const command=await wire.read('authorize',['authorization','redirect','state','issuer']);
        if(command.issuer!==input.issuer || new URL(command.redirect).hostname!==input.hosts[index]) fail();
        wire.send(await authorize(page,context,command));
      }
      for(let index=0;index<2;index++) {
        const command=await wire.read('reject',['authorization','redirect','state','issuer']);
        if(command.issuer!==input.issuer) fail();
        wire.send(await authorize(page,context,command,true));
      }
      const command=await wire.read('origins',['callbacks']);
      if(!Array.isArray(command.callbacks) || command.callbacks.length!==2 || command.callbacks.some((url,index)=>new URL(url).hostname!==input.hosts[index])) fail();
      await finish(socket,await origins(context,command.callbacks));
      await context.close();
    } catch { await finish(socket,{failed:true}); }
    finally { clearTimeout(budget); if(browser) await browser.close(); socket.destroy(); }
  });
  const deadline=setTimeout(()=>server.close(),600000);
  server.on('close',()=>clearTimeout(deadline));
  server.listen(5056,'0.0.0.0');
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  serve().catch(()=>process.exitCode=1);
}
