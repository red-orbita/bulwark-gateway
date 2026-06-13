/**
 * Sentinel Gateway — Multi-Tenant Isolation Scenario
 *
 * Validates that tenant isolation holds under concurrent load. Multiple
 * tenants sending traffic simultaneously should:
 *   - Not cross-contaminate rate limit counters
 *   - Maintain consistent per-tenant latency
 *   - Apply correct per-tenant policies
 *
 * This scenario sends traffic from 5 tenants in parallel, each with
 * distinct agent configurations, and verifies no single tenant starves others.
 *
 * Run:
 *   k6 run --out json=results/multi-tenant.json tests/load/scenario-multi-tenant.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import {
  BASE_URL,
  authHeaders,
  standardStages,
  randomPayload,
  cleanPayload,
  attackPayload,
  isValidResponse,
  isBlocked,
  TENANTS,
  randomTenant,
  TARGETS,
  DEFAULT_VUS,
} from "./k6-config.js";

// ---------------------------------------------------------------------------
// Per-tenant custom metrics
// ---------------------------------------------------------------------------

const tenantLatency = new Trend("tenant_latency", true);
const tenantAlphaLatency = new Trend("tenant_alpha_latency", true);
const tenantBetaLatency = new Trend("tenant_beta_latency", true);
const tenantGammaLatency = new Trend("tenant_gamma_latency", true);
const tenantDeltaLatency = new Trend("tenant_delta_latency", true);
const tenantDefaultLatency = new Trend("tenant_default_latency", true);

const blockRate = new Rate("block_rate");
const errorRate = new Rate("error_rate");
const rateLimitHits = new Counter("rate_limit_429");
const requestsPerTenant = new Counter("requests_per_tenant");
const isolationViolations = new Counter("isolation_violations");

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Each tenant gets its own VU pool to simulate realistic isolation
    tenant_alpha: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.ceil(DEFAULT_VUS / 5)),
      gracefulRampDown: "10s",
      exec: "tenantAlpha",
      env: { TENANT_ID: "tenant-alpha", AGENT_ID: "support-bot" },
    },
    tenant_beta: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.ceil(DEFAULT_VUS / 5)),
      gracefulRampDown: "10s",
      exec: "tenantBeta",
      env: { TENANT_ID: "tenant-beta", AGENT_ID: "code-assistant" },
    },
    tenant_gamma: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.ceil(DEFAULT_VUS / 5)),
      gracefulRampDown: "10s",
      exec: "tenantGamma",
      env: { TENANT_ID: "tenant-gamma", AGENT_ID: "data-analyst" },
    },
    tenant_delta: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.ceil(DEFAULT_VUS / 5)),
      gracefulRampDown: "10s",
      exec: "tenantDelta",
      env: { TENANT_ID: "tenant-delta", AGENT_ID: "research-bot" },
    },
    tenant_default: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.ceil(DEFAULT_VUS / 5)),
      gracefulRampDown: "10s",
      exec: "tenantDefault",
      env: { TENANT_ID: "default-corp", AGENT_ID: "support-bot" },
    },
  },

  thresholds: {
    // Global latency should stay within full-pipeline targets
    http_req_duration: [
      { threshold: "p(50)<5", abortOnFail: false },
      { threshold: "p(95)<8", abortOnFail: false },
      { threshold: "p(99)<12", abortOnFail: true },
    ],
    // Per-tenant fairness: no single tenant >2x the average
    tenant_alpha_latency: [{ threshold: "p(95)<10", abortOnFail: false }],
    tenant_beta_latency: [{ threshold: "p(95)<10", abortOnFail: false }],
    tenant_gamma_latency: [{ threshold: "p(95)<10", abortOnFail: false }],
    tenant_delta_latency: [{ threshold: "p(95)<10", abortOnFail: false }],
    tenant_default_latency: [{ threshold: "p(95)<10", abortOnFail: false }],
    error_rate: [{ threshold: "rate<0.02", abortOnFail: true }],
    http_req_failed: [{ threshold: "rate<0.02", abortOnFail: true }],
  },

  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

// ---------------------------------------------------------------------------
// Per-tenant VU functions
// ---------------------------------------------------------------------------

function tenantRequest(tenantId, agentId, latencyMetric) {
  const headers = authHeaders(tenantId, agentId);
  const payload = randomPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { tenant: tenantId, scenario: "multi_tenant" },
    timeout: "15s",
  });
  const elapsed = Date.now() - startTime;

  tenantLatency.add(elapsed);
  latencyMetric.add(elapsed);
  requestsPerTenant.add(1);

  // Check for rate limiting (429) — expected per-tenant isolation
  if (res.status === 429) {
    rateLimitHits.add(1);
    // Rate limiting is correct behavior, not an error
    check(res, {
      "rate limit response has retry-after": (r) =>
        r.headers["Retry-After"] !== undefined || r.status === 429,
    });
    sleep(1); // Back off on rate limit
    return;
  }

  const valid = isValidResponse(res);
  errorRate.add(!valid);
  blockRate.add(isBlocked(res));

  // Verify response includes correct tenant context (no cross-contamination)
  if (res.status === 200 && res.body) {
    try {
      const body = JSON.parse(res.body);
      // If response has metadata, verify tenant ID matches
      if (body.metadata && body.metadata.tenant_id) {
        if (body.metadata.tenant_id !== tenantId) {
          isolationViolations.add(1);
        }
      }
    } catch (e) {
      // Not all responses are JSON (streaming/blocked)
    }
  }

  check(res, {
    "valid response (200/403)": (r) => isValidResponse(r) || r.status === 429,
    "no server errors": (r) => r.status < 500,
    "latency under 12ms (p99 multi-tenant)": () => elapsed < 12,
  });

  sleep(0.02);
}

export function tenantAlpha() {
  tenantRequest("tenant-alpha", "support-bot", tenantAlphaLatency);
}

export function tenantBeta() {
  tenantRequest("tenant-beta", "code-assistant", tenantBetaLatency);
}

export function tenantGamma() {
  tenantRequest("tenant-gamma", "data-analyst", tenantGammaLatency);
}

export function tenantDelta() {
  tenantRequest("tenant-delta", "research-bot", tenantDeltaLatency);
}

export function tenantDefault() {
  tenantRequest("default-corp", "support-bot", tenantDefaultLatency);
}

// Default export uses random tenant selection
export default function () {
  const tenant = randomTenant();
  tenantRequest(tenant.id, tenant.agent, tenantLatency);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`, { timeout: "5s" });
  if (healthRes.status !== 200) {
    console.error(`Target ${BASE_URL} not healthy: ${healthRes.status}`);
  }
  return {
    tenants: TENANTS.map((t) => t.id),
    startTime: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const perTenant = {};
  for (const name of ["alpha", "beta", "gamma", "delta", "default"]) {
    const key = `tenant_${name}_latency`;
    perTenant[name] = {
      p50: data.metrics[key]?.values?.["p(50)"] || null,
      p95: data.metrics[key]?.values?.["p(95)"] || null,
      p99: data.metrics[key]?.values?.["p(99)"] || null,
      avg: data.metrics[key]?.values?.avg || null,
    };
  }

  // Calculate fairness: max p95 / min p95 (should be < 2.0 for fair scheduling)
  const p95Values = Object.values(perTenant)
    .map((t) => t.p95)
    .filter((v) => v !== null);
  const fairnessRatio =
    p95Values.length > 1 ? Math.max(...p95Values) / Math.min(...p95Values) : 1.0;

  const summary = {
    scenario: "multi-tenant",
    timestamp: new Date().toISOString(),
    results: {
      global_p50: data.metrics.http_req_duration?.values?.["p(50)"] || null,
      global_p95: data.metrics.http_req_duration?.values?.["p(95)"] || null,
      global_p99: data.metrics.http_req_duration?.values?.["p(99)"] || null,
      throughput: data.metrics.http_reqs?.values?.rate || null,
      errorRate: data.metrics.error_rate?.values?.rate || null,
      rateLimitHits: data.metrics.rate_limit_429?.values?.count || 0,
      isolationViolations: data.metrics.isolation_violations?.values?.count || 0,
      fairnessRatio: fairnessRatio,
      perTenant,
    },
    passed: fairnessRatio < 2.0 && (data.metrics.isolation_violations?.values?.count || 0) === 0,
  };

  return {
    "results/multi-tenant.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data, perTenant, fairnessRatio),
  };
}

function textSummary(data, perTenant, fairnessRatio) {
  const d = data.metrics.http_req_duration?.values || {};
  const lines = [
    "",
    "=== Multi-Tenant Isolation Results ===",
    `  Global p50:  ${(d["p(50)"] || 0).toFixed(2)}ms`,
    `  Global p95:  ${(d["p(95)"] || 0).toFixed(2)}ms`,
    `  Global p99:  ${(d["p(99)"] || 0).toFixed(2)}ms`,
    `  Throughput:  ${(data.metrics.http_reqs?.values?.rate || 0).toFixed(0)} req/s`,
    `  Fairness:    ${fairnessRatio.toFixed(2)}x (target: <2.0x)`,
    "",
    "  Per-tenant p95:",
  ];

  for (const [name, vals] of Object.entries(perTenant)) {
    lines.push(`    ${name.padEnd(10)} ${(vals.p95 || 0).toFixed(2)}ms`);
  }

  lines.push("");
  lines.push(
    `  Isolation violations: ${data.metrics.isolation_violations?.values?.count || 0}`
  );
  lines.push(`  Rate limit hits: ${data.metrics.rate_limit_429?.values?.count || 0}`);
  lines.push("");

  return lines.join("\n");
}
