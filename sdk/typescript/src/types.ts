/**
 * Type definitions for Sentinel Gateway SDK.
 */

// ─── Configuration ──────────────────────────────────────────────────────────

export interface SentinelClientConfig {
  /** Base URL of the Sentinel Gateway proxy (e.g., "http://localhost:8080") */
  baseUrl: string;

  /** API key or JWT token for authentication */
  apiKey?: string;

  /** JWT token (alternative to apiKey) */
  jwtToken?: string;

  /** Tenant identifier (sent as X-Tenant-ID header) */
  tenantId: string;

  /** Agent identifier (sent as X-Agent-ID header) */
  agentId: string;

  /** Request timeout in milliseconds (default: 120000) */
  timeout?: number;

  /** Maximum retry attempts on 5xx errors (default: 0 = no retry) */
  maxRetries?: number;

  /** Custom headers to include in every request */
  headers?: Record<string, string>;

  /** Custom fetch implementation (for testing or environments without global fetch) */
  fetch?: typeof globalThis.fetch;
}

// ─── Chat Completion Types ──────────────────────────────────────────────────

export interface Message {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  name?: string;
  tool_calls?: ToolCall[];
  tool_call_id?: string;
}

export interface ToolCall {
  id: string;
  type: "function";
  function: ToolFunction;
}

export interface ToolFunction {
  name: string;
  arguments: string;
}

export interface Tool {
  type: "function";
  function: ToolFunctionDef;
}

export interface ToolFunctionDef {
  name: string;
  description?: string;
  parameters?: Record<string, unknown>;
}

export interface ChatRequest {
  /** Model identifier */
  model: string;

  /** Conversation messages */
  messages: Message[];

  /** Temperature (0-2, lower = more deterministic) */
  temperature?: number;

  /** Maximum tokens in response */
  max_tokens?: number;

  /** Enable streaming response */
  stream?: boolean;

  /** Available tools for the model */
  tools?: Tool[];

  /** How the model should use tools */
  tool_choice?: "none" | "auto" | "required" | { type: "function"; function: { name: string } };

  /** Number of completions to generate */
  n?: number;

  /** Stop sequences */
  stop?: string | string[];

  /** Frequency penalty (-2.0 to 2.0) */
  frequency_penalty?: number;

  /** Presence penalty (-2.0 to 2.0) */
  presence_penalty?: number;

  /** Response format */
  response_format?: { type: "text" | "json_object" };
}

export interface Choice {
  index: number;
  message: Message;
  finish_reason: "stop" | "length" | "tool_calls" | "content_filter" | null;
}

export interface Usage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
}

export interface ChatResponse {
  id: string;
  object: "chat.completion";
  created: number;
  model: string;
  choices: Choice[];
  usage?: Usage;
}

// ─── Streaming Types ────────────────────────────────────────────────────────

export interface StreamDelta {
  role?: "assistant";
  content?: string | null;
  tool_calls?: Partial<ToolCall>[];
}

export interface StreamChoice {
  index: number;
  delta: StreamDelta;
  finish_reason: "stop" | "length" | "tool_calls" | "content_filter" | null;
}

export interface StreamChunk {
  id: string;
  object: "chat.completion.chunk";
  created: number;
  model: string;
  choices: StreamChoice[];
}

// ─── Health Types ───────────────────────────────────────────────────────────

export interface HealthResponse {
  status: "healthy" | "degraded" | "unhealthy";
  version: string;
  uptime_seconds: number;
}

export interface HealthStats {
  status: string;
  uptime_seconds: number;
  requests_total: number;
  requests_blocked: number;
  requests_allowed: number;
  requests_warned: number;
  block_rate: number;
  latency_p50_ms: number;
  latency_p95_ms: number;
  latency_p99_ms: number;
}

// ─── Error Types ────────────────────────────────────────────────────────────

export interface SentinelError {
  /** HTTP status code */
  status: number;

  /** Error message */
  message: string;

  /** Error code from Sentinel (e.g., "guardrail_blocked", "rate_limited") */
  code?: string;

  /** Threat category if blocked by guardrail */
  category?: string;

  /** Matched pattern description */
  matched_pattern?: string;
}

export interface GuardrailBlock {
  /** The guardrail that triggered the block */
  source: "input_guardrail" | "output_filter" | "tool_policy" | "ioc_scanner" | "rate_limit";

  /** Threat category */
  category: string;

  /** Severity level */
  severity: "low" | "medium" | "high" | "critical";

  /** Human-readable description */
  description: string;
}

// ─── Tool Validation (Sidecar Mode) ────────────────────────────────────────

export interface ValidateToolRequest {
  /** Tool name to validate */
  tool_name: string;

  /** Tool arguments */
  arguments: Record<string, unknown>;

  /** Agent making the call (optional, uses client default) */
  agent_id?: string;
}

export interface ValidateToolResponse {
  /** Whether the tool call is allowed */
  allowed: boolean;

  /** Reason if blocked */
  reason?: string;

  /** Violations found */
  violations?: string[];
}
