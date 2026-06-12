/**
 * Sentinel Gateway Client
 *
 * HTTP client with typed methods for all Sentinel Gateway endpoints.
 * Zero dependencies — uses native fetch (Node 18+, Deno, Bun).
 */

import type {
  SentinelClientConfig,
  ChatRequest,
  ChatResponse,
  StreamChunk,
  HealthResponse,
  HealthStats,
  SentinelError,
  ValidateToolRequest,
  ValidateToolResponse,
} from "./types";

export class SentinelClient {
  private readonly config: Required<
    Pick<SentinelClientConfig, "baseUrl" | "tenantId" | "agentId" | "timeout" | "maxRetries">
  > &
    SentinelClientConfig;

  private readonly fetchFn: typeof globalThis.fetch;

  constructor(config: SentinelClientConfig) {
    if (!config.baseUrl) throw new Error("baseUrl is required");
    if (!config.tenantId) throw new Error("tenantId is required");
    if (!config.agentId) throw new Error("agentId is required");
    if (!config.apiKey && !config.jwtToken) {
      throw new Error("Either apiKey or jwtToken is required");
    }

    this.config = {
      timeout: 120_000,
      maxRetries: 0,
      ...config,
    };

    this.fetchFn = config.fetch ?? globalThis.fetch;
  }

  // ─── Chat Completions ───────────────────────────────────────────────────

  /**
   * Send a chat completion request through Sentinel Gateway.
   *
   * The request is validated by input guardrails before forwarding to the
   * LLM backend. The response passes through output filters before returning.
   *
   * @throws {SentinelGuardrailError} If the request is blocked by a guardrail (403)
   * @throws {SentinelRateLimitError} If rate limit is exceeded (429)
   * @throws {SentinelError} On other errors
   */
  async chat(request: ChatRequest): Promise<ChatResponse> {
    const response = await this.request<ChatResponse>("POST", "/v1/chat/completions", {
      ...request,
      stream: false,
    });
    return response;
  }

  /**
   * Send a streaming chat completion request.
   *
   * Returns an async iterator of SSE chunks. Each chunk contains a delta
   * of the response content.
   *
   * @example
   * ```ts
   * for await (const chunk of client.chatStream({ model: "gpt-4", messages })) {
   *   const content = chunk.choices[0]?.delta?.content;
   *   if (content) process.stdout.write(content);
   * }
   * ```
   */
  async *chatStream(request: Omit<ChatRequest, "stream">): AsyncGenerator<StreamChunk> {
    const url = this.buildUrl("/v1/chat/completions");
    const body = JSON.stringify({ ...request, stream: true });

    const response = await this.rawFetch(url, {
      method: "POST",
      headers: this.buildHeaders(),
      body,
    });

    if (!response.ok) {
      await this.handleError(response);
    }

    if (!response.body) {
      throw new SentinelClientError(500, "No response body for streaming request");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed || !trimmed.startsWith("data: ")) continue;
          const data = trimmed.slice(6);
          if (data === "[DONE]") return;

          try {
            const chunk: StreamChunk = JSON.parse(data);
            yield chunk;
          } catch {
            // Skip malformed chunks
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  // ─── Tool Validation (Sidecar Mode) ────────────────────────────────────

  /**
   * Validate a tool call against the agent's policy BEFORE execution.
   *
   * Used in sidecar mode where the agent framework calls Sentinel
   * to check if a tool invocation is permitted.
   */
  async validateTool(request: ValidateToolRequest): Promise<ValidateToolResponse> {
    return this.request<ValidateToolResponse>("POST", "/v1/tool/validate", request);
  }

  // ─── Health Checks ─────────────────────────────────────────────────────

  /**
   * Check gateway health status.
   * Does NOT require authentication.
   */
  async health(): Promise<HealthResponse> {
    const url = this.buildUrl("/health");
    const response = await this.rawFetch(url, { method: "GET" });
    if (!response.ok) {
      throw new SentinelClientError(response.status, "Health check failed");
    }
    return response.json() as Promise<HealthResponse>;
  }

  /**
   * Get detailed health statistics.
   * Does NOT require authentication.
   */
  async healthStats(): Promise<HealthStats> {
    const url = this.buildUrl("/health/stats");
    const response = await this.rawFetch(url, { method: "GET" });
    if (!response.ok) {
      throw new SentinelClientError(response.status, "Health stats check failed");
    }
    return response.json() as Promise<HealthStats>;
  }

  // ─── Private Methods ───────────────────────────────────────────────────

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = this.buildUrl(path);
    let lastError: Error | null = null;
    const maxAttempts = 1 + this.config.maxRetries;

    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const response = await this.rawFetch(url, {
          method,
          headers: this.buildHeaders(),
          body: body ? JSON.stringify(body) : undefined,
        });

        if (!response.ok) {
          // Retry on 5xx
          if (response.status >= 500 && attempt < maxAttempts - 1) {
            lastError = new SentinelClientError(response.status, `Server error (attempt ${attempt + 1})`);
            await this.sleep(Math.min(1000 * 2 ** attempt, 10_000));
            continue;
          }
          await this.handleError(response);
        }

        return (await response.json()) as T;
      } catch (error) {
        if (error instanceof SentinelClientError) throw error;
        if (error instanceof SentinelGuardrailError) throw error;
        if (error instanceof SentinelRateLimitError) throw error;

        // Network error — retry if allowed
        lastError = error as Error;
        if (attempt < maxAttempts - 1) {
          await this.sleep(Math.min(1000 * 2 ** attempt, 10_000));
          continue;
        }
      }
    }

    throw lastError ?? new SentinelClientError(0, "Request failed after retries");
  }

  private buildUrl(path: string): string {
    const base = this.config.baseUrl.replace(/\/$/, "");
    return `${base}${path}`;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "X-Tenant-ID": this.config.tenantId,
      "X-Agent-ID": this.config.agentId,
      ...this.config.headers,
    };

    if (this.config.apiKey) {
      headers["Authorization"] = `Bearer ${this.config.apiKey}`;
    } else if (this.config.jwtToken) {
      headers["Authorization"] = `Bearer ${this.config.jwtToken}`;
    }

    return headers;
  }

  private async rawFetch(url: string, init: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      return await this.fetchFn(url, {
        ...init,
        signal: controller.signal,
      });
    } catch (error) {
      if ((error as Error).name === "AbortError") {
        throw new SentinelClientError(408, `Request timed out after ${this.config.timeout}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async handleError(response: Response): Promise<never> {
    let errorBody: Record<string, unknown> = {};
    try {
      errorBody = (await response.json()) as Record<string, unknown>;
    } catch {
      // Body might not be JSON
    }

    const message =
      (errorBody.detail as string) ??
      (errorBody.message as string) ??
      `HTTP ${response.status}`;

    if (response.status === 403) {
      throw new SentinelGuardrailError(
        message,
        (errorBody.category as string) ?? undefined,
        (errorBody.source as string) ?? undefined,
      );
    }

    if (response.status === 429) {
      const retryAfter = response.headers.get("Retry-After");
      throw new SentinelRateLimitError(
        message,
        retryAfter ? parseInt(retryAfter, 10) : undefined,
      );
    }

    throw new SentinelClientError(response.status, message);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

// ─── Error Classes ──────────────────────────────────────────────────────────

/**
 * Base error for Sentinel Gateway client errors.
 */
export class SentinelClientError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "SentinelClientError";
  }
}

/**
 * Thrown when a request is blocked by a guardrail (HTTP 403).
 */
export class SentinelGuardrailError extends SentinelClientError {
  constructor(
    message: string,
    public readonly category?: string,
    public readonly source?: string,
  ) {
    super(403, message);
    this.name = "SentinelGuardrailError";
  }
}

/**
 * Thrown when rate limit is exceeded (HTTP 429).
 */
export class SentinelRateLimitError extends SentinelClientError {
  constructor(
    message: string,
    public readonly retryAfterSeconds?: number,
  ) {
    super(429, message);
    this.name = "SentinelRateLimitError";
  }
}
