/**
 * Sentinel Gateway — Full Pipeline Scenario
 *
 * Measures end-to-end latency through the complete request pipeline:
 *   Auth -> Rate Limit -> Input Guardrail -> IOC Check -> Forward -> Tool Policy -> Output Filter
 *
 * This exercises the entire proxy path without ML scanners.
 *
 * Target: p50 <3ms, p95 <5ms, p99 <8ms, >8,000 RPS
 *
 * Run:
 *   k6 run --out json=results/full-pipeline.json tests/load/scenario-full-pipeline.js
 */

import http from "k6/http";
import { check, sleep, group } from "k6";
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
  isAllowed,
  TARGETS,
  DEFAULT_VUS,
} from "./k6-config.js";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const pipelineLatency = new Trend("pipeline_latency", true);
const inputGuardrailTime = new Trend("input_guardrail_time", true);
const blockRate = new Rate("block_rate");
const errorRate = new Rate("error_rate");
const timeoutRate = new Rate("timeout_rate");
const requestsTotal = new Counter("requests_total");
const requestsAllowed = new Counter("requests_allowed");
const requestsBlocked = new Counter("requests_blocked");
const requestsErrored = new Counter("requests_errored");

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Main load: ramping VUs through the full pipeline
    full_pipeline: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(DEFAULT_VUS),
      gracefulRampDown: "10s",
      exec: "fullPipeline",
    },
    // Constant arrival rate for throughput measurement
    throughput_test: {
      executor: "constant-arrival-rate",
      rate: 1000,
      timeUnit: "1s",
      duration: "1m",
      preAllocatedVUs: 50,
      maxVUs: 200,
      startTime: "3m30s", // After ramping scenario
      exec: "fullPipeline",
    },
  },

  thresholds: {
    // Enterprise targets for full pipeline (no ML)
    http_req_duration: [
      { threshold: "p(50)<3", abortOnFail: false },
      { threshold: "p(95)<5", abortOnFail: false },
      { threshold: "p(99)<8", abortOnFail: true },
    ],
    pipeline_latency: [
      { threshold: "p(50)<3", abortOnFail: false },
      { threshold: "p(95)<5", abortOnFail: false },
      { threshold: "p(99)<8", abortOnFail: true },
    ],
    error_rate: [{ threshold: "rate<0.01", abortOnFail: true }],
    timeout_rate: [{ threshold: "rate<0.005", abortOnFail: true }],
    http_req_failed: [{ threshold: "rate<0.01", abortOnFail: true }],
  },

  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

// ---------------------------------------------------------------------------
// Main scenario function
// ---------------------------------------------------------------------------

export function fullPipeline() {
  const headers = authHeaders();
  const payload = randomPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  requestsTotal.add(1);

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "full_pipeline" },
    timeout: "30s",
  });
  const elapsed = Date.now() - startTime;

  pipelineLatency.add(elapsed);

  // Classify response
  if (res.status === 0 || res.timings.duration > 29000) {
    timeoutRate.add(true);
    errorRate.add(true);
    requestsErrored.add(1);
    return;
  }
  timeoutRate.add(false);

  const valid = isValidResponse(res);
  errorRate.add(!valid);

  if (isBlocked(res)) {
    blockRate.add(true);
    requestsBlocked.add(1);
  } else if (isAllowed(res)) {
    blockRate.add(false);
    requestsAllowed.add(1);
  } else {
    requestsErrored.add(1);
    errorRate.add(true);
  }

  check(res, {
    "status is 200 or 403": (r) => isValidResponse(r),
    "response body present": (r) => r.body && r.body.length > 0,
    "no server errors (5xx)": (r) => r.status < 500,
    "latency under 8ms (p99 target)": () => elapsed < 8,
  });

  // Extract timing headers if available (custom Sentinel headers)
  const guardrailHeader = res.headers["X-Guardrail-Time"];
  if (guardrailHeader) {
    inputGuardrailTime.add(parseFloat(guardrailHeader));
  }

  sleep(0.01);
}

// Default export for k6
export default fullPipeline;

// ---------------------------------------------------------------------------
// Additional validation: health endpoint should always be fast
// ---------------------------------------------------------------------------

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`, {
    timeout: "5s",
  });

  const healthy = check(healthRes, {
    "health endpoint returns 200": (r) => r.status === 200,
    "health response is JSON": (r) => {
      try {
        JSON.parse(r.body);
        return true;
      } catch (e) {
        return false;
      }
    },
  });

  if (!healthy) {
    console.error(
      `Target ${BASE_URL} is not healthy. Status: ${healthRes.status}, Body: ${healthRes.body}`
    );
  }

  return { healthy };
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const summary = {
    scenario: "full-pipeline",
    timestamp: new Date().toISOString(),
    targets: TARGETS.fullPipeline,
    results: {
      p50: data.metrics.http_req_duration?.values?.["p(50)"] || null,
      p95: data.metrics.http_req_duration?.values?.["p(95)"] || null,
      p99: data.metrics.http_req_duration?.values?.["p(99)"] || null,
      avg: data.metrics.http_req_duration?.values?.avg || null,
      min: data.metrics.http_req_duration?.values?.min || null,
      max: data.metrics.http_req_duration?.values?.max || null,
      throughput: data.metrics.http_reqs?.values?.rate || null,
      errorRate: data.metrics.error_rate?.values?.rate || null,
      blockRate: data.metrics.block_rate?.values?.rate || null,
      timeoutRate: data.metrics.timeout_rate?.values?.rate || null,
    },
    passed: true,
  };

  // Check against targets
  if (summary.results.p50 > TARGETS.fullPipeline.p50) summary.passed = false;
  if (summary.results.p95 > TARGETS.fullPipeline.p95) summary.passed = false;
  if (summary.results.p99 > TARGETS.fullPipeline.p99) summary.passed = false;

  return {
    "results/full-pipeline.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data),
  };
}

function textSummary(data) {
  const d = data.metrics.http_req_duration?.values || {};
  const reqs = data.metrics.http_reqs?.values || {};
  return [
    "",
    "=== Full Pipeline Scenario Results ===",
    `  p50:      ${(d["p(50)"] || 0).toFixed(2)}ms (target: <${TARGETS.fullPipeline.p50}ms)`,
    `  p95:      ${(d["p(95)"] || 0).toFixed(2)}ms (target: <${TARGETS.fullPipeline.p95}ms)`,
    `  p99:      ${(d["p(99)"] || 0).toFixed(2)}ms (target: <${TARGETS.fullPipeline.p99}ms)`,
    `  avg:      ${(d.avg || 0).toFixed(2)}ms`,
    `  max:      ${(d.max || 0).toFixed(2)}ms`,
    `  rate:     ${(reqs.rate || 0).toFixed(0)} req/s (target: >${TARGETS.fullPipeline.minRPS})`,
    `  errors:   ${((data.metrics.error_rate?.values?.rate || 0) * 100).toFixed(2)}%`,
    `  blocked:  ${((data.metrics.block_rate?.values?.rate || 0) * 100).toFixed(1)}%`,
    "",
  ].join("\n");
}
