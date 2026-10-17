import fs from 'node:fs';
import { chromium, request } from 'playwright';

const input = JSON.parse(fs.readFileSync('/fixture/grafana-browser.json', 'utf8'));
const origin = 'https://localhost:3443';
let stage = 'server readiness';
const browser = await chromium.launch({args: [`--ignore-certificate-errors-spki-list=${input.spki}`]});
const api = await request.newContext();
const deadline = Date.now() + 120000;
while (Date.now() < deadline) {
  try { if ((await api.get(origin + '/api/health')).status() === 200) break; } catch {}
  await new Promise(resolve => setTimeout(resolve, 1000));
}
let viewer;
async function login(context, user) {
  const page = await context.newPage();
  page.on('dialog', dialog => dialog.accept('disposable-grafana'));
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options: {protocol: 'ctap2', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true}});
  await page.goto(origin + '/login/generic_oauth');
  await page.getByLabel('Username', {exact: false}).fill(user.username);
  await page.getByLabel('Password', {exact: true}).fill(user.password);
  await page.getByRole('button', {name: 'Sign In', exact: true}).click();
  const register = page.getByRole('button', {name: /Register/});
  await register.waitFor({timeout: 30000});
  await register.click();
  await page.waitForURL(url => url.origin === origin && !url.pathname.includes('generic_oauth'), {timeout: 60000});
  return {page, cdp, authenticatorId};
}
try {
  const users = [...input.users.filter(user => user.role !== 'Viewer'), input.users.find(user => user.role === 'Viewer')];
  for (const user of users) {
    stage = 'role mapping ' + user.role;
    const context = await browser.newContext();
    const flow = await login(context, user);
    const response = await context.request.get(origin + '/api/user/orgs');
    if (user.role === 'Unmapped') {
      if (response.status() !== 401) throw new Error('Unmapped user admitted');
    } else {
      if (response.status() !== 200 || !(await response.json()).some(row => row.role === user.role)) throw new Error('Mapped role differs');
      if ((await (await context.request.get(origin + '/api/user')).json()).isGrafanaAdmin) throw new Error('SSO granted server administrator');
    }
    if (user.role === 'Viewer') viewer = {context, ...flow, user};
    else await context.close();
  }
  stage = 'logout';
  await viewer.page.goto(origin + '/logout');
  await viewer.page.waitForURL(origin + '/login', {timeout: 30000});
  if ((await viewer.context.request.get(origin + '/api/user/orgs')).status() !== 401) throw new Error('Logout retained Grafana session');
  await viewer.page.goto(origin + '/login/generic_oauth');
  await viewer.page.getByLabel('Username', {exact: false}).waitFor();
  stage = 'viewer credential retention';
  const credentials = (await viewer.cdp.send('WebAuthn.getCredentials', {authenticatorId: viewer.authenticatorId})).credentials;
  if (!credentials.length) throw new Error('Disposable authenticator lost its credential');
  stage = 'viewer authenticator activation';
  await viewer.cdp.send('WebAuthn.enable');
  await viewer.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {authenticatorId: viewer.authenticatorId, enabled: true});
  stage = 'viewer password submission';
  await viewer.page.getByLabel('Username', {exact: false}).fill(viewer.user.username);
  await viewer.page.getByLabel('Password', {exact: true}).fill(viewer.user.password);
  await viewer.page.getByRole('button', {name: 'Sign In', exact: true}).click();
  stage = 'viewer passkey authentication';
  await viewer.page.locator('#authenticateWebAuthnButton').click();
  stage = 'viewer callback';
  await viewer.page.waitForURL(url => url.origin === origin && !url.pathname.includes('generic_oauth'), {timeout: 60000});
  stage = 'viewer renewed session';
  if ((await viewer.context.request.get(origin + '/api/user/orgs')).status() !== 200) throw new Error('Viewer reauthentication denied');
  stage = 'administrative offboarding';
  const token = await api.post('https://localhost:8443/realms/master/protocol/openid-connect/token', {
    form: {grant_type: 'password', client_id: 'admin-cli', username: 'fixture-admin', password: 'fixture-only-isolated-admin'}});
  const headers = {Authorization: `Bearer ${(await token.json()).access_token}`};
  const root = 'https://localhost:8443/admin/realms/platform';
  const started = Date.now();
  if ((await api.put(`${root}/users/${viewer.user.uid}`, {headers, data: {enabled: false}})).status() !== 204) throw new Error('Offboarding refused');
  if ((await api.post(`${root}/users/${viewer.user.uid}/logout`, {headers})).status() !== 204) throw new Error('Revocation refused');
  let denied = false;
  stage = 'offboarding deadline';
  while (Date.now() - started < 360000) {
    if ((await viewer.context.request.get(origin + '/api/user/orgs')).status() === 401) { denied = true; break; }
    await new Promise(resolve => setTimeout(resolve, 2000));
  }
  if (!denied) throw new Error('Offboarding exceeded bound');
  const offboardingSeconds = (Date.now() - started) / 1000;
  stage = 'fresh offboarded login';
  await viewer.page.goto(origin + '/login/generic_oauth');
  await viewer.page.getByLabel('Username', {exact: false}).fill(viewer.user.username);
  await viewer.page.getByLabel('Password', {exact: true}).fill(viewer.user.password);
  await viewer.page.getByRole('button', {name: 'Sign In', exact: true}).click();
  await viewer.page.getByText(/Invalid username or password|Account is disabled|Account disabled/).waitFor();
  stage = 'independent emergency access';
  const renewed = await api.post('https://localhost:8443/realms/master/protocol/openid-connect/token', {
    form: {grant_type: 'password', client_id: 'admin-cli', username: 'fixture-admin', password: 'fixture-only-isolated-admin'}});
  headers.Authorization = `Bearer ${(await renewed.json()).access_token}`;
  if ((await api.put(root, {headers, data: {enabled: false}})).status() !== 204) throw new Error('Disposable IdP disable refused');
  const emergency = await request.newContext({extraHTTPHeaders: {
    Authorization: 'Basic ' + Buffer.from('fixture-emergency:' + input.emergency).toString('base64')}});
  if ((await emergency.get(origin + '/api/user')).status() !== 200) throw new Error('Emergency access depends on IdP');
  if ((await api.put(root, {headers, data: {enabled: true}})).status() !== 204) throw new Error('Disposable IdP restore refused');
  console.log(JSON.stringify({grafana_oss_roles: true, unmapped_denied: true, server_admin_denied: true,
    logout: true, offboarding_seconds: offboardingSeconds, fresh_offboarded_login_denied: true, independent_emergency_access: true}));
  await emergency.dispose();
  await viewer.context.close();
} catch (error) {
  console.error(`Isolated Grafana SSO proof failed: ${stage}; private diagnostics withheld`);
  if (viewer) console.error(JSON.stringify({error_type: error.name,
    identity_page: new URL(viewer.page.url()).origin === 'https://localhost:8443',
    username_form: await viewer.page.getByLabel('Username', {exact: false}).count(),
    authenticate_button: await viewer.page.getByRole('button', {name: /Authenticate/}).count()}));
  process.exitCode = 1;
} finally { await api.dispose(); await browser.close(); }
