/**
 * Sentinel Gateway — Streaming (SSE) Scenario
 *
 * Measures Time-To-First-Byte (TTFB) and throughput for SSE streaming
 * responses. The gateway applies chunk-level output filtering with a
 * 256-char sliding window buffer.
 *
 * Target: p50 <5ms TTFB, p95 <10ms, p99 <15ms, >5,000 RPS
 *
 * Run:
 *   k6 run --out json=results/streaming.json tests/load/scenario-streaming.js
 */

import http from "k6/http";
import { check, sleep } from "k6";
import { Rate, Trend, Counter } from "k6/metrics";
import {
  BASE_URL,
  authHeaders,
  standardStages,
  streamingPayload,
  randomPayload,
  isValidResponse,
  isBlocked,
  TARGETS,
  DEFAULT_VUS,
} from "./k6-config.js";

// ---------------------------------------------------------------------------
// Custom metrics
// ---------------------------------------------------------------------------

const ttfb = new Trend("ttfb", true);
const streamDuration = new Trend("stream_total_duration", true);
const blockRate = new Rate("block_rate");
const errorRate = new Rate("error_rate");
const sseSuccess = new Rate("sse_success_rate");
const chunksReceived = new Counter("sse_chunks_received");
const requestsTotal = new Counter("requests_total");

// ---------------------------------------------------------------------------
// Test options
// ---------------------------------------------------------------------------

export const options = {
  scenarios: {
    // Streaming requests with ramping load
    streaming_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: standardStages(Math.floor(DEFAULT_VUS * 0.6)), // Fewer VUs for streaming (longer connections)
      gracefulRampDown: "15s",
      exec: "streamingRequest",
    },
    // Mixed: streaming + non-streaming (realistic)
    mixed_load: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "30s", target: Math.floor(DEFAULT_VUS * 0.4) },
        { duration: "2m", target: Math.floor(DEFAULT_VUS * 0.4) },
        { duration: "30s", target: 0 },
      ],
      gracefulRampDown: "10s",
      startTime: "0s",
      exec: "nonStreamingRequest",
    },
  },

  thresholds: {
    // Enterprise TTFB targets for streaming
    "http_req_waiting{scenario:streaming_load}": [
      { threshold: "p(50)<5", abortOnFail: false },
      { threshold: "p(95)<10", abortOnFail: false },
      { threshold: "p(99)<15", abortOnFail: true },
    ],
    ttfb: [
      { threshold: "p(50)<5", abortOnFail: false },
      { threshold: "p(95)<10", abortOnFail: false },
      { threshold: "p(99)<15", abortOnFail: true },
    ],
    error_rate: [{ threshold: "rate<0.02", abortOnFail: true }],
    http_req_failed: [{ threshold: "rate<0.02", abortOnFail: true }],
  },

  summaryTrendStats: ["avg", "min", "med", "max", "p(50)", "p(90)", "p(95)", "p(99)"],
};

// ---------------------------------------------------------------------------
// Streaming request function
// ---------------------------------------------------------------------------

export function streamingRequest() {
  const headers = authHeaders();
  const payload = streamingPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  requestsTotal.add(1);

  const startTime = Date.now();
  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "streaming" },
    timeout: "30s",
    // k6 will capture TTFB via res.timings.waiting
  });
  const totalTime = Date.now() - startTime;

  // Record TTFB (time to first byte from server)
  if (res.timings && res.timings.waiting) {
    ttfb.add(res.timings.waiting);
  }
  streamDuration.add(totalTime);

  // Check for blocked attacks (still fast even in streaming)
  if (isBlocked(res)) {
    blockRate.add(true);
    // Blocked responses should still have fast TTFB
    check(res, {
      "blocked response is fast": (r) => r.timings.waiting < 15,
    });
    return;
  }
  blockRate.add(false);

  // Validate streaming response format
  const isSSE =
    res.headers["Content-Type"] &&
    (res.headers["Content-Type"].includes("text/event-stream") ||
      res.headers["Content-Type"].includes("application/json"));

  if (res.status === 200) {
    sseSuccess.add(true);
    errorRate.add(false);

    // Count SSE chunks in response body
    if (res.body) {
      const chunks = res.body.split("\ndata: ").length - 1;
      if (chunks > 0) {
        chunksReceived.add(chunks);
      }
    }

    check(res, {
      "streaming response 200": (r) => r.status === 200,
      "has content-type header": (r) => r.headers["Content-Type"] !== undefined,
      "TTFB under 15ms (p99)": (r) => r.timings.waiting < 15,
    });
  } else if (res.status !== 403) {
    sseSuccess.add(false);
    errorRate.add(true);
  }

  sleep(0.05); // Slightly longer pause for streaming (connection overhead)
}

// ---------------------------------------------------------------------------
// Non-streaming companion (simulates real mixed traffic)
// ---------------------------------------------------------------------------

export function nonStreamingRequest() {
  const headers = authHeaders();
  const payload = randomPayload();
  const url = `${BASE_URL}/v1/chat/completions`;

  const res = http.post(url, payload, {
    headers,
    tags: { scenario: "non_streaming_companion" },
    timeout: "10s",
  });

  check(res, {
    "companion request valid": (r) => isValidResponse(r),
  });

  sleep(0.02);
}

// Default export
export default streamingRequest;

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export function setup() {
  const healthRes = http.get(`${BASE_URL}/health`, { timeout: "5s" });
  const healthy = healthRes.status === 200;

  if (!healthy) {
    console.error(`Target ${BASE_URL} not healthy: ${healthRes.status}`);
  }

  return { healthy, baseUrl: BASE_URL };
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

export function handleSummary(data) {
  const ttfbVals = data.metrics.ttfb?.values || {};
  const summary = {
    scenario: "streaming",
    timestamp: new Date().toISOString(),
    targets: TARGETS.streaming,
    results: {
      ttfb_p50: ttfbVals["p(50)"] || null,
      ttfb_p95: ttfbVals["p(95)"] || null,
      ttfb_p99: ttfbVals["p(99)"] || null,
      ttfb_avg: ttfbVals.avg || null,
      total_duration_avg: data.metrics.stream_total_duration?.values?.avg || null,
      throughput: data.metrics.http_reqs?.values?.rate || null,
      errorRate: data.metrics.error_rate?.values?.rate || null,
      blockRate: data.metrics.block_rate?.values?.rate || null,
      sseSuccessRate: data.metrics.sse_success_rate?.values?.rate || null,
    },
    passed: true,
  };

  if (summary.results.ttfb_p50 > TARGETS.streaming.p50) summary.passed = false;
  if (summary.results.ttfb_p95 > TARGETS.streaming.p95) summary.passed = false;
  if (summary.results.ttfb_p99 > TARGETS.streaming.p99) summary.passed = false;

  return {
    "results/streaming.json": JSON.stringify(summary, null, 2),
    stdout: textSummary(data),
  };
}

function textSummary(data) {
  const t = data.metrics.ttfb?.values || {};
  const reqs = data.metrics.http_reqs?.values || {};
  return [
    "",
    "=== Streaming (SSE) Scenario Results ===",
    `  TTFB p50:  ${(t["p(50)"] || 0).toFixed(2)}ms (target: <${TARGETS.streaming.p50}ms)`,
    `  TTFB p95:  ${(t["p(95)"] || 0).toFixed(2)}ms (target: <${TARGETS.streaming.p95}ms)`,
    `  TTFB p99:  ${(t["p(99)"] || 0).toFixed(2)}ms (target: <${TARGETS.streaming.p99}ms)`,
    `  TTFB avg:  ${(t.avg || 0).toFixed(2)}ms`,
    `  Rate:      ${(reqs.rate || 0).toFixed(0)} req/s (target: >${TARGETS.streaming.minRPS})`,
    `  Errors:    ${((data.metrics.error_rate?.values?.rate || 0) * 100).toFixed(2)}%`,
    `  Blocked:   ${((data.metrics.block_rate?.values?.rate || 0) * 100).toFixed(1)}%`,
    "",
  ].join("\n");
}
