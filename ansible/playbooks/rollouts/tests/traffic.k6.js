import http from 'k6/http';
import exec from 'k6/execution';
import { Counter } from 'k6/metrics';

const stable = new Counter('stable_samples');
const canary = new Counter('canary_samples');
const unknown = new Counter('unknown_revision');
const failed = new Counter('failed_samples');
const policy = JSON.parse(open('../../../../charts/service/release-policy.json'));
const origin = __ENV.RELEASE_ORIGIN;
if (!/^https:\/\/[a-z0-9.-]+:8443$/.test(origin || '')) throw new Error('Canonical fixture HTTPS origin required');
export const options = {
  // Six total RPS gives each half enough samples for the accepted per-revision gate.
  scenarios: { release: { executor: 'constant-arrival-rate', rate: 6, timeUnit: '1s',
    duration: `${policy.duration_seconds + 70}s`, preAllocatedVUs: 2, maxVUs: 4 } },
  hosts: { [origin.substring(8)]: '127.0.0.1:8443' },
  discardResponseBodies: true,
  maxRedirects: 0,
  userAgent: 'CloudLab-Release-Proof/1.0',
  thresholds: { dropped_iterations: ['count==0'], unknown_revision: ['count==0'],
    http_req_duration: [`p(95)<${policy.p95_seconds * 1000}`, `max<${policy.maximum_seconds * 1000}`] },
  systemTags: ['status', 'method', 'name', 'scenario', 'error_code'],
};
export default function () {
  const response = http.get(origin + '/canary-proof', { timeout: '2s', tags: {name: 'disposable-release'} });
  unknown.add(response.headers['X-Cloudlab-Revision'] !== __ENV.STABLE_REVISION &&
    response.headers['X-Cloudlab-Revision'] !== __ENV.CANARY_REVISION ? 1 : 0);
  if (exec.instance.currentTestRunDuration < policy.duration_seconds * 1000) {
    stable.add(response.headers['X-Cloudlab-Revision'] === __ENV.STABLE_REVISION ? 1 : 0);
    canary.add(response.headers['X-Cloudlab-Revision'] === __ENV.CANARY_REVISION ? 1 : 0);
  }
  failed.add(response.status !== 200 ? 1 : 0);
}
export function handleSummary(data) {
  const count = name => data.metrics[name]?.values.count || 0;
  return {stdout: JSON.stringify({stable_samples: count('stable_samples'), canary_samples: count('canary_samples'),
    unknown_revision: count('unknown_revision'), dropped_iterations: count('dropped_iterations'),
    failed_samples: count('failed_samples'), requests: data.metrics.http_reqs.values.count,
    p95_ms: data.metrics.http_req_duration.values['p(95)'], maximum_ms: data.metrics.http_req_duration.values.max}) + '\n'};
}
