// Package sentinel provides a Go SDK for the Sentinel Gateway security proxy.
//
// Sentinel Gateway is a security guardrail proxy for AI agents. This SDK provides
// both remote scanning (via the gateway API) and local guard scanning (offline regex).
//
// Basic usage:
//
//	client, err := sentinel.NewClient(
//	    sentinel.WithBaseURL("https://sentinel.company.com"),
//	    sentinel.WithAPIKey("sk-..."),
//	    sentinel.WithTenant("acme-corp"),
//	    sentinel.WithAgent("support-bot"),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result, err := client.ScanInput(ctx, "user message")
//	if result.Verdict == sentinel.VerdictBlock {
//	    // content was blocked
//	}
package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Version is the SDK version string.
const Version = "0.1.0"

// Client is a thread-safe client for the Sentinel Gateway API.
// A single Client should be shared across goroutines.
type Client struct {
	cfg        *clientConfig
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewClient creates a new Sentinel Gateway client with the provided options.
// At minimum, an API key should be provided for authenticated environments.
//
// Returns ErrInvalidConfig if the configuration is invalid.
func NewClient(opts ...Option) (*Client, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Validate configuration
	if cfg.baseURL == "" {
		return nil, fmt.Errorf("%w: base URL cannot be empty", ErrInvalidConfig)
	}
	cfg.baseURL = strings.TrimRight(cfg.baseURL, "/")

	// Use provided HTTP client or create one with timeout
	httpClient := cfg.httpClient
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: cfg.timeout,
			// SECURITY (H-16 fix): Disable redirects to prevent Authorization
			// header from leaking to external hosts via redirect.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Client{
		cfg:        cfg,
		httpClient: httpClient,
	}, nil
}

// Health checks the gateway health status.
func (c *Client) Health(ctx context.Context) (*HealthStatus, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/health", nil)
	if err != nil {
		return nil, err
	}

	var status HealthStatus
	if err := c.do(req, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// ChatCompletion sends a chat completion request through the Sentinel Gateway proxy.
// The request is scanned by input guardrails, forwarded to the backend LLM, and the
// response is filtered by output guardrails before being returned.
func (c *Client) ChatCompletion(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal request: %w", err)
	}

	httpReq, err := c.newRequest(ctx, http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var resp ChatResponse
	if err := c.do(httpReq, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// newRequest creates an HTTP request with authentication and tenant headers.
func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	url := c.cfg.baseURL + path

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to create request: %w", err)
	}

	// Set content type for requests with bodies
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// Set authentication
	if c.cfg.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.apiKey)
	}

	// Set tenant and agent routing headers
	if c.cfg.tenant != "" {
		req.Header.Set("X-Tenant-ID", c.cfg.tenant)
	}
	if c.cfg.agent != "" {
		req.Header.Set("X-Agent-ID", c.cfg.agent)
	}

	// Set user agent
	req.Header.Set("User-Agent", c.cfg.userAgent)

	// Set custom headers
	for k, v := range c.cfg.headers {
		req.Header.Set(k, v)
	}

	return req, nil
}

// do executes the HTTP request with retries and decodes the response.
func (c *Client) do(req *http.Request, v any) error {
	var lastErr error

	attempts := c.cfg.retries + 1
	for i := 0; i < attempts; i++ {
		if i > 0 {
			// Exponential backoff
			wait := c.cfg.retryWait * time.Duration(1<<(i-1))
			select {
			case <-req.Context().Done():
				return fmt.Errorf("%w: %v", ErrTimeout, req.Context().Err())
			case <-time.After(wait):
			}

			// Clone the request for retry (body must be re-readable)
			// For simplicity, we only retry GET requests or requests where the body
			// was fully buffered. The scan methods handle this by using bytes.Reader.
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			if req.Context().Err() != nil {
				return fmt.Errorf("%w: %v", ErrTimeout, err)
			}
			lastErr = fmt.Errorf("sentinel: request failed: %w", err)
			if i < attempts-1 {
				continue
			}
			return lastErr
		}

		// SECURITY (H-14 fix): Close body immediately in this iteration,
		// not deferred to function return (would leak N bodies in retry loop).
		// SECURITY (H-15 fix): Limit response body to 10MB to prevent OOM
		// from a malicious/compromised gateway sending unbounded data.
		const maxResponseSize = 10 * 1024 * 1024 // 10MB
		limitedReader := io.LimitReader(resp.Body, maxResponseSize)
		respBody, err := io.ReadAll(limitedReader)
		resp.Body.Close() // Close immediately, not defer
		if err != nil {
			lastErr = fmt.Errorf("sentinel: failed to read response: %w", err)
			continue
		}

		// Handle error responses
		if resp.StatusCode >= 400 {
			apiErr := &APIError{
				StatusCode: resp.StatusCode,
				RequestID:  resp.Header.Get("X-Request-ID"),
			}

			// Try to parse structured error response
			_ = json.Unmarshal(respBody, apiErr)
			if apiErr.Code == "" {
				apiErr.Code = http.StatusText(resp.StatusCode)
			}
			if apiErr.Message == "" {
				apiErr.Message = string(respBody)
			}

			// Retry on retryable status codes
			if IsRetryable(apiErr) && i < attempts-1 {
				lastErr = apiErr
				continue
			}

			return apiErr
		}

		// Decode successful response
		if v != nil && len(respBody) > 0 {
			if err := json.Unmarshal(respBody, v); err != nil {
				return fmt.Errorf("sentinel: failed to decode response: %w", err)
			}
		}

		return nil
	}

	return lastErr
}

// Middleware returns an HTTP middleware that scans request bodies through
// the Sentinel Gateway before passing them to the next handler.
//
// If scanning returns VerdictBlock, a 403 response is sent and the next
// handler is not called. The scan result is stored in the request context
// and can be retrieved with ResultFromContext().
//
// Usage:
//
//	mux.Handle("/api/chat", sentinel.Middleware(client)(yourHandler))
func Middleware(client *Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only scan requests with bodies
			if r.Body == nil || r.ContentLength == 0 {
				next.ServeHTTP(w, r)
				return
			}

			// Read the body
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
				return
			}

			// Scan the content
			result, err := client.ScanInput(r.Context(), string(body))
			if err != nil {
				// Fail closed: block on scan errors
				http.Error(w, `{"error":"security scan failed"}`, http.StatusServiceUnavailable)
				return
			}

			// Store result in context for downstream handlers
			ctx := contextWithResult(r.Context(), result)
			r = r.WithContext(ctx)

			// Block if verdict is Block
			if result.Verdict == VerdictBlock {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Sentinel-Verdict", string(result.Verdict))
				w.Header().Set("X-Sentinel-Scan-ID", result.ScanID)
				w.WriteHeader(http.StatusForbidden)
				resp, _ := json.Marshal(map[string]any{
					"error":    "blocked by security guardrail",
					"verdict":  result.Verdict,
					"scan_id":  result.ScanID,
					"findings": result.Findings,
				})
				w.Write(resp)
				return
			}

			// Restore the body for downstream handlers
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Add verdict header for observability
			w.Header().Set("X-Sentinel-Verdict", string(result.Verdict))

			next.ServeHTTP(w, r)
		})
	}
}

// contextKey is an unexported type for context keys in this package.
type contextKey struct{}

// resultKey is the context key for storing ScanResult.
var resultKey = contextKey{}

// contextWithResult stores a ScanResult in the context.
func contextWithResult(ctx context.Context, result *ScanResult) context.Context {
	return context.WithValue(ctx, resultKey, result)
}

// ResultFromContext retrieves the ScanResult stored by the Middleware.
// Returns nil if no result is present (e.g., the middleware was not used).
func ResultFromContext(ctx context.Context) *ScanResult {
	result, _ := ctx.Value(resultKey).(*ScanResult)
	return result
}
