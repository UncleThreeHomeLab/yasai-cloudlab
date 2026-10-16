// Live disposable viewer only. Never persist or log credentials, CLI secrets or cookies.
import {chromium} from 'playwright';
import {enrollViewer} from '/proof/disposable.mjs';
import net from 'node:net';
import readline from 'node:readline';

const listener = net.createServer();
listener.listen(5055, '0.0.0.0');
const connection = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('Controller unavailable')), 120000);
  listener.once('connection', socket => {clearTimeout(timer); listener.close(); resolve(socket);});
  listener.once('error', reject);
});
const lines = readline.createInterface({input: connection, terminal: false})[Symbol.asyncIterator]();
const report = value => connection.write(JSON.stringify(value) + '\n');
let browser, stage = 'input';
try {
  const input = JSON.parse((await lines.next()).value);
  if (Object.keys(input).sort().join(',') !== 'digest,gateway_address,issuer,nonce,origin,password,subject,username' ||
      !/^[a-f0-9]{32}$/.test(input.nonce) || input.username !== 'proof-' + input.nonce ||
      !/^[a-f0-9-]{36}$/.test(input.subject) || !/^sha256:[a-f0-9]{64}$/.test(input.digest) ||
      typeof input.password !== 'string' || input.password.length < 48 ||
      !/^https:\/\/harbor\.internal\.[a-z0-9.-]+$/.test(input.origin) ||
      input.issuer !== 'https://login.' + new URL(input.origin).hostname.slice(16) + '/realms/platform' ||
      net.isIP(input.gateway_address) !== 4 || !/^100\./.test(input.gateway_address) ||
      Number(input.gateway_address.split('.')[1]) < 64 || Number(input.gateway_address.split('.')[1]) > 127)
    throw new Error('Invalid disposable scope');
  browser = await chromium.launch({args: ['--host-resolver-rules=MAP ' +
    new URL(input.origin).hostname + ' ' + input.gateway_address]});
  const context = await browser.newContext();
  context.setDefaultTimeout(60000);
  const page = await context.newPage();
  page.on('dialog', dialog => dialog.accept('disposable-harbor-viewer'));
  await enrollViewer(page, context, input, input.issuer, value => {stage = value;});
  stage = 'native Harbor OIDC';
  await page.goto(input.origin + '/c/oidc/login');
  await page.waitForURL(url => url.origin === input.origin && url.pathname.startsWith('/harbor/'));
  const read = path => page.evaluate(async path => {
    const response = await fetch(path, {redirect: 'manual'});
    return {status: response.status, document: response.status === 200 ? await response.json() : null};
  }, path);
  const current = await read('/api/v2.0/users/current');
  if (current.status !== 200 || current.document.sysadmin_flag !== false ||
      current.document.username !== input.subject || !current.document.oidc_user_meta?.secret)
    throw new Error('Native Harbor viewer identity rejected');
  const publicProject = await read('/api/v2.0/projects/cloudlab-public');
  if (publicProject.status !== 200 || publicProject.document.name !== 'cloudlab-public' ||
      ![403, 404].includes((await read('/api/v2.0/projects/cloudlab-private')).status) ||
      (await read('/api/v2.0/configurations')).status !== 403)
    throw new Error('Explicit Harbor viewer roles rejected');
  const harborUser = current.document;
  const basic = 'Basic ' + Buffer.from(harborUser.username + ':' + harborUser.oidc_user_meta.secret).toString('base64');
  const tokenPath = input.origin + '/service/token?service=harbor-registry&scope=' +
    encodeURIComponent('repository:cloudlab-public/bootstrap:pull');
  const issue = async () => {
    const response = await context.request.get(tokenPath, {headers: {Authorization: basic}, maxRedirects: 0});
    if ([401, 403].includes(response.status())) return null;
    if (response.status() !== 200) throw new Error('Unexpected registry authentication response');
    const value = await response.json();
    if (typeof value.token !== 'string') throw new Error('Registry token absent');
    const claims = JSON.parse(Buffer.from(value.token.split('.')[1], 'base64url'));
    if (!Array.isArray(claims.access) || claims.access.some(access => access.actions?.includes('push')) ||
        claims.exp - claims.iat > 305) throw new Error('Unexpected registry token scope');
    if (!claims.access.some(access => access.name === 'cloudlab-public/bootstrap' && access.actions?.includes('pull')))
      return null;
    return value.token;
  };
  const pull = async token => {
    const response = await context.request.get(input.origin + '/v2/cloudlab-public/bootstrap/manifests/' + input.digest,
      {headers: {Authorization: 'Bearer ' + token, Accept: 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'}, maxRedirects: 0});
    if ([401, 403].includes(response.status())) return false;
    if (response.status() !== 200 || response.headers()['docker-content-digest'] !== input.digest)
      throw new Error('Unexpected registry digest response');
    return true;
  };
  let lastToken = await issue();
  if (!lastToken || !(await pull(lastToken))) throw new Error('Native OIDC CLI digest pull unavailable');
  const cookies = await context.cookies(input.origin);
  const gate = cookies.find(cookie => cookie.name === '__Host-harbor_oidc');
  if (!gate || gate.expires * 1000 > Date.now() + 245000) throw new Error('Browser session bound rejected');
  const replay = cookies.map(cookie => cookie.name + '=' + cookie.value).join('; ');
  report({ready: true, native_harbor_oidc: true, viewer_public_project_allowed: true,
    viewer_private_project_denied: true, viewer_admin_denied: true, native_oidc_cli_pull: true});
  if (JSON.stringify(JSON.parse((await lines.next()).value)) !== '{"action":"observe-offboarding"}')
    throw new Error('Invalid offboarding command');
  const started = Date.now(), measured = {};
  while (Date.now() - started < 1560000) {
    stage = 'Harbor offboarding observation';
    if (measured.browser_cookie_denied_seconds === undefined) {
      const response = await context.request.get(input.origin + '/api/v2.0/users/current', {
        headers: {Cookie: replay}, maxRedirects: 0});
      if ([302, 401, 403].includes(response.status()))
        measured.browser_cookie_denied_seconds = Math.round((Date.now() - started) / 100) / 10;
      else if (response.status() !== 200) throw new Error('Unexpected browser replay response');
    }
    if (measured.oidc_cli_denied_seconds === undefined) {
      const issued = await issue();
      if (issued) lastToken = issued;
      else measured.oidc_cli_denied_seconds = Math.round((Date.now() - started) / 100) / 10;
    }
    if (measured.last_registry_token_denied_seconds === undefined && !(await pull(lastToken)))
      measured.last_registry_token_denied_seconds = Math.round((Date.now() - started) / 100) / 10;
    if (Object.keys(measured).length === 3) break;
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  if (Object.keys(measured).length !== 3 || measured.browser_cookie_denied_seconds > 245 ||
      measured.oidc_cli_denied_seconds > 1500 || measured.last_registry_token_denied_seconds > 1500)
    throw new Error('Harbor session termination bound exceeded');
  stage = 'offboarded new Harbor login';
  const fresh = await browser.newContext();
  fresh.setDefaultTimeout(60000);
  const login = await fresh.newPage();
  await login.goto(input.origin + '/c/oidc/login');
  await login.getByLabel('Username', {exact: false}).fill(input.username);
  await login.getByLabel('Password', {exact: true}).fill(input.password);
  await login.getByRole('button', {name: 'Sign In', exact: true}).click();
  await login.getByText(/^(Invalid username or password\.|Account is disabled, contact your administrator\.)$/).waitFor();
  if ((await fresh.cookies(input.origin)).some(cookie => cookie.name === '__Host-harbor_oidc'))
    throw new Error('Offboarded viewer received a new Harbor gate session');
  await fresh.close();
  report({...measured, offboarded_new_login_denied: true, sessions_persisted: false});
} catch {
  report({failed: true, stage});
  process.exitCode = 1;
} finally {
  lines.return?.();
  if (browser) await browser.close();
  connection.end();
}
