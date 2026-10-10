// Live disposable viewer only. Credentials and sessions stay in process memory.
import {chromium} from 'playwright';
import readline from 'node:readline';
import net from 'node:net';

// Only the controller joins this internal Compose network; no host port is published.
const listener = net.createServer();
listener.listen(5055, '0.0.0.0');
const connection = await new Promise((resolve, reject) => {
  const timer = setTimeout(()=>reject(new Error('Controller connection timed out')),120000);
  listener.once('connection', socket => {clearTimeout(timer); listener.close(); resolve(socket);});
  listener.once('error', reject);
});
const lines = readline.createInterface({input:connection, terminal:false})[Symbol.asyncIterator]();
let browser, stage = 'input';
const report = value => connection.write(JSON.stringify(value)+'\n');
try {
  const input = JSON.parse((await lines.next()).value);
  if (Object.keys(input).sort().join(',') !== 'access_url,email,gateway_address,nonce,password,username,zone' ||
      !/^[a-f0-9]{32}$/.test(input.nonce) || input.username !== 'proof-'+input.nonce ||
      typeof input.password !== 'string' || input.password.length < 32 ||
      typeof input.email !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email) ||
      typeof input.zone !== 'string' || input.zone.length > 253 ||
      !input.zone.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      net.isIP(input.gateway_address) !== 4 || Number(input.gateway_address.split('.')[0]) !== 100 ||
      Number(input.gateway_address.split('.')[1]) < 64 || Number(input.gateway_address.split('.')[1]) > 127)
    throw new Error('Invalid disposable viewer input');
  const access = new URL(input.access_url);
  if (access.protocol !== 'https:' || !access.hostname.endsWith('.'+input.zone) ||
      access.pathname !== '/__cloudlab_identity_access_canary' || access.search || access.hash ||
      access.username || access.password || access.port)
    throw new Error('Invalid owned disposable Access route');
  const issuer = 'https://login.'+input.zone+'/realms/platform';
  const argo = 'https://cd.internal.'+input.zone;
  browser = await chromium.launch({headless:true,args:[
    '--host-resolver-rules=MAP cd.internal.'+input.zone+' '+input.gateway_address]});
  const context = await browser.newContext();
  context.setDefaultTimeout(60000);
  const page = await context.newPage();
  page.on('dialog', dialog => dialog.accept('disposable-session-proof'));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {options:{protocol:'ctap2',transport:'internal',
    hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  let refresh;
  page.on('response', async response => {
    if (response.url() === issuer+'/protocol/openid-connect/token' && response.status() === 200) {
      try {refresh = (await response.json()).refresh_token;} catch {}
    }
  });
  stage = 'account enrollment';
  await page.goto(issuer+'/account/');
  await page.getByLabel('Username', {exact:false}).fill(input.username);
  await page.getByLabel('Password', {exact:true}).fill(input.password);
  await page.getByRole('button', {name:'Sign In',exact:true}).click();
  await page.getByRole('button', {name:/Register/}).click();
  const label = page.getByLabel(/Authenticator Label/);
  if (await label.count()) {
    await label.fill('disposable-session-proof');
    await page.getByRole('button', {name:/Register/}).click();
  }
  stage = 'account session';
  await page.getByRole('heading', {name:'Personal info',exact:true}).waitFor();
  const profilePromise = page.waitForResponse(r => r.url().startsWith(issuer+'/account/?') && r.status()===200);
  await page.reload();
  const profile = await profilePromise;
  if ((await profile.json()).username !== input.username) throw new Error('Unexpected account identity');
  const authorization = (await profile.request().allHeaders()).authorization;
  if (!authorization?.startsWith('Bearer ') || !refresh) throw new Error('Missing real account session');
  const claims = JSON.parse(Buffer.from(authorization.split('.')[1], 'base64url'));
  if (claims.iss !== issuer || !claims.exp || claims.exp-claims.iat > 300)
    throw new Error('Unexpected issuer or token lifetime');
  stage = 'native Argo SSO';
  await page.goto(argo+'/auth/login?return_url='+encodeURIComponent(argo));
  await page.waitForURL(url => url.origin===argo && !url.pathname.startsWith('/auth/'));
  const argoCookie = (await context.cookies(argo)).find(c => c.name==='argocd.token');
  if (!argoCookie) throw new Error('Missing native Argo session');
  const argoHeaders = {Cookie:'argocd.token='+argoCookie.value};
  const read = await context.request.get(argo+'/api/v1/applications?projects=cloudlab-public', {headers:argoHeaders});
  if (read.status()!==200) throw new Error('Viewer read denied');
  if ((await context.request.get(argo+'/api/v1/clusters',{headers:argoHeaders})).status()!==403)
    throw new Error('Viewer administrative role allowed');
  stage = 'Access SSO';
  await page.goto(input.access_url);
  await page.getByText('mesh-ok',{exact:true}).waitFor();
  const accessCookie = (await context.cookies(input.access_url)).find(c => c.name==='CF_Authorization');
  if (!accessCookie) throw new Error('Missing real Access session');
  const accessHeaders = {Cookie:'CF_Authorization='+accessCookie.value};
  if (claims.exp <= Date.now()/1000) throw new Error('Initial access token expired before baseline');
  report({ready:true,synthetic_webauthn_on_disposable_user:true,native_argo_sso:true,
    viewer_read_allowed:true,viewer_administration_denied:true,access_sso:true,sessions_persisted:false});
  const command = JSON.parse((await lines.next()).value);
  if (JSON.stringify(command)!=='{"action":"observe-offboarding"}') throw new Error('Invalid observation command');
  const started = Date.now(), measured = {};
  while (Date.now()-started < 660000) {
    stage = 'offboarding observation';
    const elapsed = () => Math.round((Date.now()-started)/100)/10;
    if (measured.keycloak_refresh_denied_seconds === undefined) {
      const result = await context.request.post(issuer+'/protocol/openid-connect/token', {
        form:{grant_type:'refresh_token',client_id:'account-console',refresh_token:refresh}});
      if (result.status()===400 && (await result.json()).error==='invalid_grant')
        measured.keycloak_refresh_denied_seconds=elapsed();
      else if (result.status()===200) {
        const renewed = await result.json();
        if (!renewed.refresh_token) throw new Error('Missing renewed refresh session');
        refresh = renewed.refresh_token;
      } else throw new Error('Unexpected refresh response');
    }
    if (measured.argo_session_denied_seconds === undefined) {
      const result = await context.request.get(argo+'/api/v1/applications?projects=cloudlab-public', {headers:argoHeaders});
      if ([401,403].includes(result.status())) measured.argo_session_denied_seconds=elapsed();
      else if (result.status()!==200) throw new Error('Unexpected Argo response');
    }
    if (measured.access_session_denied_seconds === undefined) {
      const result = await context.request.get(input.access_url,{headers:accessHeaders,maxRedirects:0});
      if ([302,401,403].includes(result.status())) measured.access_session_denied_seconds=elapsed();
      else if (result.status()!==200 || (await result.text()).trim()!=='mesh-ok')
        throw new Error('Unexpected Access response');
    }
    if (Date.now()/1000 >= claims.exp) measured.original_access_jwt_expired_seconds=elapsed();
    if (Object.keys(measured).length===4) {
      if (measured.keycloak_refresh_denied_seconds>300 || measured.argo_session_denied_seconds>600 ||
          measured.access_session_denied_seconds>600) throw new Error('Coordinated offboarding deadline exceeded');
      report({...measured,logout_is_not_instant_jwt_revocation:true,sessions_persisted:false});
      break;
    }
    await new Promise(resolve=>setTimeout(resolve,2000));
  }
  if (Object.keys(measured).length!==4) throw new Error('Offboarding observation timed out');
} catch (error) {
  console.error('Disposable session proof failed at '+stage+': '+error.name);
  process.exitCode=1;
} finally {
  lines.return?.();
  if (browser) await browser.close();
  connection.end();
}
