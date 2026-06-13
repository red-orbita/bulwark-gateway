/**
 * Sentinel Gateway — Spike/Burst Traffic Scenario
 *
 * Simulates sudden traffic spikes (10x normal load) to validate:
 *   - Rate limiter handles bursts without cascading failures
 *   - Latency degrades gracefully under overload
 *   - System recovers quickly after spike subsides
 *   - No request loss during transitions
 *
 * Pattern: baseline -> 10x spike -> hold -> drop -> recovery -> verify
 *
 * Run:
 *   k6 run --out json=results/spike.json tests/load/scenario-spike.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import {
  BASE_URL,
  authHeaders,
  spikeStages,
  randomPayload,
  isValidResponse,
  isBlocked,
  TARGETS,
  DEFAULT_VUS,
} from "./k6-config.js";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const spikeLatency = new Trend("spike_latency", true);
const baselineLatency = new Trend("baseline_latency", true);
const recoveryLatency = new Trend("recovery_latency", true);
const blockRate = new Rate("block_rate");
const errorRate = new Rate("error_rate");
const rateLimited = new Counter("rate_limited_429");
const requestsTotal = new Counter("requests_total");
const timeoutCount = new Counter("timeout_count");

// Track phases for per-phase analysis
let testStartTime = 0;

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    spike_test: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: spikeStages(DEFAULT_VUS),
      gracefulRampDown: "15s",
    },
  },

  thresholds: {
    // During spike, latency may increase — but p99 should not exceed 50ms
    http_req_duration: [
      { threshold: "p(50)<10", abortOnFail: false },
      { threshold: "p(95)<25", abortOnFail: false },
      { threshold: "p(99)<50", abortOnFail: true },
    ],
    // Baseline (pre-spike) should meet normal targets
    baseline_latency: [
      { threshold: "p(95)<5", abortOnFail: false },
      { threshold: "p(99)<8", abortOnFail: false },
    ],
    // Recovery should return to near-baseline within reasonable time
    recovery_latency: [
      { threshold: "p(95)<8", abortOnFail: false },
      { threshold: "p(99)<12", abortOnFail: false },
    ],
    // Error rate during spike: accept up to 5% (rate limiting is expected)
    error_rate: [{ threshold: "rate<0.05", abortOnFail: true }],
    // Hard errors (5xx) should still be rare
    http_req_failed: [{ threshold: "rate<0.02", abortOnFail: true }],
  },

  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`, { timeout: "5s" });
  if (healthRes.status !== 200) {
    console.error(`Target ${BASE_URL} not healthy: ${healthRes.status}`);
  }

  return {
    startTime: Date.now(),
    baseUrl: BASE_URL,
    vus: DEFAULT_VUS,
  };
}

// ---------------------------------------------------------------------------
// Main VU function
// ---------------------------------------------------------------------------

export default function (data) {
  const headers = authHeaders();
  const payload = randomPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  requestsTotal.add(1);

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "spike" },
    timeout: "15s",
  });
  const elapsed = Date.now() - startTime;

  spikeLatency.add(elapsed);

  // Determine current phase based on elapsed time from test start
  const testElapsed = (Date.now() - data.startTime) / 1000; // seconds
  if (testElapsed < 90) {
    // Warm-up + initial baseline (0-90s)
    baselineLatency.add(elapsed);
  } else if (testElapsed > 180) {
    // Recovery phase (after spike, 180s+)
    recoveryLatency.add(elapsed);
  }
  // 90-180s is the spike window — captured only in spikeLatency

  // Handle timeout
  if (res.status === 0) {
    timeoutCount.add(1);
    errorRate.add(true);
    return;
  }

  // Rate limiting is expected during spikes
  if (res.status === 429) {
    rateLimited.add(1);
    blockRate.add(false);
    errorRate.add(false); // 429 is correct behavior during spike
    check(res, {
      "rate limit has retry-after or valid body": (r) => r.body && r.body.length > 0,
    });
    sleep(0.5); // Back off
    return;
  }

  // Normal response handling
  const valid = isValidResponse(res);
  errorRate.add(!valid && res.status !== 429);
  blockRate.add(isBlocked(res));

  check(res, {
    "response valid (200/403/429)": (r) => r.status === 200 || r.status === 403 || r.status === 429,
    "no server crash (5xx)": (r) => r.status < 500,
    "response body present": (r) => r.body && r.body.length > 0,
  });

  // Minimal sleep — let k6 manage concurrency pressure
  sleep(0.005);
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const overall = data.metrics.http_req_duration?.values || {};
  const baseline = data.metrics.baseline_latency?.values || {};
  const recovery = data.metrics.recovery_latency?.values || {};

  const summary = {
    scenario: "spike",
    timestamp: new Date().toISOString(),
    results: {
      overall: {
        p50: overall["p(50)"] || null,
        p95: overall["p(95)"] || null,
        p99: overall["p(99)"] || null,
        avg: overall.avg || null,
        max: overall.max || null,
      },
      baseline: {
        p50: baseline["p(50)"] || null,
        p95: baseline["p(95)"] || null,
        p99: baseline["p(99)"] || null,
      },
      recovery: {
        p50: recovery["p(50)"] || null,
        p95: recovery["p(95)"] || null,
        p99: recovery["p(99)"] || null,
      },
      throughput: data.metrics.http_reqs?.values?.rate || null,
      totalRequests: data.metrics.requests_total?.values?.count || 0,
      rateLimited: data.metrics.rate_limited_429?.values?.count || 0,
      timeouts: data.metrics.timeout_count?.values?.count || 0,
      errorRate: data.metrics.error_rate?.values?.rate || null,
    },
    // Passed if recovery latency returns close to baseline
    passed:
      (recovery["p(95)"] || 0) < (baseline["p(95)"] || 5) * 2 &&
      (data.metrics.timeout_count?.values?.count || 0) < 10,
  };

  return {
    "results/spike.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data, summary),
  };
}

function textSummary(data, summary) {
  const r = summary.results;
  return [
    "",
    "=== Spike/Burst Traffic Results ===",
    "",
    "  Phase          p50       p95       p99",
    "  -------------- --------- --------- ---------",
    `  Baseline       ${fmt(r.baseline.p50)}   ${fmt(r.baseline.p95)}   ${fmt(r.baseline.p99)}`,
    `  Overall        ${fmt(r.overall.p50)}   ${fmt(r.overall.p95)}   ${fmt(r.overall.p99)}`,
    `  Recovery       ${fmt(r.recovery.p50)}   ${fmt(r.recovery.p95)}   ${fmt(r.recovery.p99)}`,
    "",
    `  Throughput:    ${(r.throughput || 0).toFixed(0)} req/s`,
    `  Total reqs:    ${r.totalRequests}`,
    `  Rate limited:  ${r.rateLimited} (expected during spike)`,
    `  Timeouts:      ${r.timeouts}`,
    `  Error rate:    ${((r.errorRate || 0) * 100).toFixed(2)}%`,
    "",
    `  Recovery ratio: ${r.recovery.p95 && r.baseline.p95 ? (r.recovery.p95 / r.baseline.p95).toFixed(2) : "N/A"}x baseline (target: <2.0x)`,
    "",
  ].join("\n");
}

function fmt(val) {
  return val !== null ? `${val.toFixed(2)}ms` : "   N/A  ";
}
