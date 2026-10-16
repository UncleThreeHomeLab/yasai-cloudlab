// Enroll only a fresh disposable viewer. Callers retain credentials and browser sessions in memory.
export async function enrollViewer(page, context, input, issuer, setStage) {
  setStage('account enrollment');
  await page.goto(issuer+'/account/', {waitUntil:'domcontentloaded'});
  setStage('account password');
  await page.getByLabel('Username', {exact:false}).fill(input.username);
  await page.getByLabel('Password', {exact:true}).fill(input.password);
  await page.getByRole('button', {name:'Sign In',exact:true}).click();
  setStage('WebAuthn registration');
  await page.waitForLoadState('domcontentloaded');
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {options:{protocol:'ctap2',transport:'internal',
    hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await page.getByRole('button', {name:/Register/}).click();
  setStage('account session');
  const personal = page.getByRole('heading', {name:'Personal info',exact:true});
  const firstName = page.getByLabel('First name',{exact:false});
  await Promise.race([personal.waitFor(),firstName.waitFor()]);
  const profileSubmit = page.getByRole('button',{name:/^Submit$/i});
  if (await firstName.isVisible() && await profileSubmit.count()) {
    await firstName.fill('Fixture');
    await page.getByLabel('Last name',{exact:false}).fill('Viewer');
    await profileSubmit.click();
  }
  await personal.waitFor();
}
