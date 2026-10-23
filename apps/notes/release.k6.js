import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

const policy = { ...JSON.parse(open('./slo.json')).release,
  ...JSON.parse(open('../../charts/service/release-policy.json')) };
const origin = __ENV.RELEASE_ORIGIN;
const token = __ENV.RELEASE_TOKEN;
if (!/^https:\/\/[a-z0-9.-]+$/.test(origin || '') || !token || token.length > 16384) {
  throw new Error('Release proof requires canonical HTTPS origin and scoped transient access token');
}
const samples = new Counter('release_samples');
export const options = {
  scenarios: { release: { executor: 'constant-arrival-rate', rate: policy.rate_per_second,
    timeUnit: '1s', duration: `${policy.duration_seconds}s`, preAllocatedVUs: 2, maxVUs: policy.maximum_vus } },
  thresholds: { http_req_failed: [`rate<${policy.failure_rate}`],
    http_req_duration: [`p(95)<${policy.p95_seconds * 1000}`, `max<${policy.maximum_seconds * 1000}`],
    release_samples: [`count>=${policy.minimum_samples}`], checks: ['rate==1'], dropped_iterations: ['count==0'] },
  discardResponseBodies: false, maxRedirects: 0, userAgent: 'CloudLab-Release-Proof/1.0',
  systemTags: ['status', 'method', 'name', 'scenario', 'check', 'error_code'],
};

export default function () {
  const response = http.get(origin + policy.route, {
    headers: { Authorization: `Bearer ${token}` }, timeout: '5s', tags: { name: 'notes-release-read' },
  });
  samples.add(1);
  check(response, { 'authorized bounded read': r => r.status === 200 && r.body.length <= 131072 });
}

// Never emit raw URLs, credentials, response bodies or transport diagnostics.
export function handleSummary(data) {
  const duration = data.metrics.http_req_duration.values;
  const passed = Object.values(data.metrics).every(metric =>
    Object.values(metric.thresholds || {}).every(threshold => threshold.ok));
  return { stdout: JSON.stringify({ scenario: 'notes-release-read', passed,
    samples: data.metrics.release_samples.values.count,
    p95_ms: duration['p(95)'], maximum_ms: duration.max,
    failure_rate: data.metrics.http_req_failed.values.rate,
    evaluation_seconds: policy.duration_seconds }) + '\n' };
}
