// Extraction must retain trusted managers despite the hostile repository config.
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const {applyPackageRules} = require('/usr/local/renovate/dist/util/package-rules/index.js');
const result = spawnSync('/usr/local/renovate/node', ['/usr/local/renovate/dist/renovate.js', '--platform=local', '--dry-run=extract'], {
  env: {PATH: process.env.PATH, HOME: '/tmp/home', RENOVATE_BASE_DIR: '/tmp/renovate', RENOVATE_CONFIG_FILE: '/trusted/renovate.json', RENOVATE_USE_CLOUD_METADATA_SERVICES: 'false', LOG_FORMAT: 'json', LOG_LEVEL: 'trace'},
  cwd: '/fixture', encoding: 'utf8', timeout: 120000, maxBuffer: 64 * 1024 * 1024
});
const records = result.stdout.split('\n').flatMap(line => {try { return [JSON.parse(line)]; } catch { return []; }});
const extraction = records.find(row => row.msg === 'Dependency extraction complete');
const managers = extraction?.stats?.managers;
const packageFiles = records.find(row => row.msg === 'packageFiles')?.config || {};
const dependencies = Object.entries(packageFiles).flatMap(([manager, files]) => files.flatMap(file =>
  (file.deps || []).map(dep => ({manager, dependency: dep.depName, package: dep.packageName || dep.depName,
    datasource: dep.datasource || file.datasource, skipped: dep.skipReason || null, currentValue: dep.currentValue,
    packageFile: file.packageFile}))));
if (result.status !== 0 || managers?.dockerfile?.depCount !== 1 || managers?.terraform?.depCount < 1 || managers?.regex?.depCount < 19 || managers?.helmv3?.depCount < 3 || managers?.npm?.depCount < 1 || managers?.['pip_requirements']?.depCount < 1) {
  process.stderr.write(JSON.stringify({passed: false, managers: managers || null,
    exitCode: result.status, errorCode: result.error?.code || null, outputBytes: result.stdout.length,
    errors: records.filter(row => row.level >= 40).map(row => row.msg).slice(0, 3)}) + '\n');
  process.exitCode = 1;
} else {
  (async () => {
    const force = JSON.parse(fs.readFileSync('/trusted/renovate.json', 'utf8')).force;
    const groups = await Promise.all(dependencies.map(async dep => {
      const selected = await applyPackageRules({...force, depName: dep.dependency, packageName: dep.package,
        datasource: dep.datasource, currentValue: dep.currentValue, packageFile: dep.packageFile,
        manager: dep.manager === 'regex' ? 'custom.regex' : dep.manager});
      return {dependency: dep.package, enabled: selected.enabled !== false,
        group: selected.groupName || null, versions: selected.allowedVersions || null};
    }));
    const required = [['argo-cd', 'argocd'], ['playwright', 'identity-browser'],
      ['ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set-controller', 'CI execution'],
      ['ghcr.io/cloudnative-pg/postgresql', 'data images'], ['cert-manager/cmctl', 'certificate renewal tool'],
      ['quay.io/jetstack/cert-manager-controller', 'certificates'], ['keycloak/keycloak', 'identity Keycloak'],
      ['kubernetes-sigs/gateway-api', 'Gateway API'], ['coredns/coredns', 'private DNS'],
      ['argoproj-labs/rollouts-plugin-trafficrouter-gatewayapi', 'rollouts Gateway API plugin'],
      ['ruamel-yaml', 'Python wheel requirements']];
    if (required.some(([name, group]) => !groups.some(row => row.dependency === name && row.enabled && row.group === group))) {
      throw new Error('Required native compatible group did not match its pinned manager rules');
    }
    process.stdout.write(JSON.stringify({passed: true, managers, groups}) + '\n');
  })().catch(() => {process.stderr.write('Pinned native compatible-group qualification failed\n'); process.exitCode = 1;});
}
