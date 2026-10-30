const fs = require('node:fs');
const {spawnSync} = require('node:child_process');
const {applyPackageRules} = require('/usr/local/renovate/dist/util/package-rules/index.js');
const versioning = require('/usr/local/renovate/dist/modules/versioning/index.js');
(async () => {
  const deadline = Date.now() + 120000;
  for (const base of ['main', 'cloudlab-maintenance-fixture/native-validation']) {
    const request = {repository: 'example/platform', base,
      ownerPaths: ['ansible/runner/tools.lock.json'], dependencies: ['opentofu/opentofu']};
    fs.writeFileSync('/tmp/operation.json', JSON.stringify(request), {mode: 0o600});
    const result = spawnSync('/usr/local/renovate/node', ['/usr/local/renovate/dist/config-validator.js', '--strict', '/trusted/renovate.cjs'], {
      encoding: 'utf8', timeout: Math.max(1, deadline - Date.now()), maxBuffer: 1024 * 1024
    });
    if (result.status !== 0) throw Error('Invalid native configuration');
    delete require.cache[require.resolve('/trusted/renovate.cjs')];
    const config = require('/trusted/renovate.cjs');
    const dependency = {manager: 'custom.regex', datasource: 'github-releases', versioning: 'semver',
      currentValue: '1.13.0', packageFile: 'ansible/runner/tools.lock.json'};
    const selected = await applyPackageRules({...config.force, ...dependency,
      depName: 'opentofu/opentofu', packageName: 'opentofu/opentofu'});
    const unselected = await applyPackageRules({...config.force, ...dependency,
      depName: 'helm/helm', packageName: 'helm/helm'});
    const matcher = versioning.get(selected.versioning);
    if (selected.enabled !== true || unselected.enabled !== false ||
        !matcher.matches('1.13.1', selected.allowedVersions) ||
        matcher.matches('1.13.2', selected.allowedVersions) !== (base === 'main') ||
        matcher.matches('1.14.0', selected.allowedVersions)) {
      throw Error('Native fixture target or owner selection changed');
    }
  }
  process.stdout.write(JSON.stringify({passed: true, configuration: 'trusted admin and exact owner selection', fixtureTarget: true}) + '\n');
})().catch(() => {
  process.stderr.write('Trusted native maintenance configuration validation failed\n');
  process.exitCode = 1;
}).finally(() => fs.rmSync('/tmp/operation.json', {force: true}));
