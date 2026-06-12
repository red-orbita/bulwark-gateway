/**
 * Sentinel Gateway TypeScript SDK
 *
 * Typed HTTP client for interacting with Sentinel Gateway proxy.
 * Compatible with Node.js 18+, Deno, and Bun.
 *
 * @example
 * ```ts
 * import { SentinelClient } from "@sentinel-gateway/sdk";
 *
 * const client = new SentinelClient({
 *   baseUrl: "http://localhost:8080",
 *   apiKey: "your-api-key",
 *   tenantId: "acme-corp",
 *   agentId: "support-bot",
 * });
 *
 * const response = await client.chat({
 *   model: "gpt-4",
 *   messages: [{ role: "user", content: "Hello!" }],
 * });
 * ```
 *
 * @packageDocumentation
 */

export { SentinelClient } from "./client";
export type {
  SentinelClientConfig,
  ChatRequest,
  ChatResponse,
  Message,
  Choice,
  Usage,
  ToolCall,
  ToolFunction,
  Tool,
  ToolFunctionDef,
  StreamChunk,
  HealthResponse,
  HealthStats,
  SentinelError,
  GuardrailBlock,
  ValidateToolRequest,
  ValidateToolResponse,
} from "./types";
