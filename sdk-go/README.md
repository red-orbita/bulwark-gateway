# Sentinel Gateway Go SDK

Production-ready Go client for the [Sentinel Gateway](https://github.com/sentinel-gateway/sentinel-gateway) security proxy.

## Installation

```bash
go get github.com/sentinel-gateway/sdk-go
```

Requires Go 1.21+. Zero external dependencies (stdlib only).

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    sentinel "github.com/sentinel-gateway/sdk-go"
)

func main() {
    // Create client
    client, err := sentinel.NewClient(
        sentinel.WithBaseURL("https://sentinel.company.com"),
        sentinel.WithAPIKey("sk-your-api-key"),
        sentinel.WithTenant("acme-corp"),
        sentinel.WithAgent("support-bot"),
        sentinel.WithTimeout(10 * time.Second),
    )
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Scan user input before processing
    result, err := client.ScanInput(ctx, "user message here")
    if err != nil {
        log.Fatal(err)
    }

    if result.Verdict == sentinel.VerdictBlock {
        fmt.Printf("Blocked: %s\n", result.Findings[0].Description)
        return
    }

    fmt.Println("Content is safe, proceeding...")
}
```

## Features

| Feature | Description |
|---------|-------------|
| Remote Scanning | Input/output scanning via gateway API |
| Batch Scanning | Scan multiple items in one request |
| Chat Completion | Proxy mode (gateway forwards to LLM) |
| Tool Validation | Pre-validate tool calls (sidecar mode) |
| Local Guard | Offline regex scanning (zero network) |
| HTTP Middleware | Drop-in `net/http` middleware |
| Retry Logic | Exponential backoff on retryable errors |
| Error Types | Structured errors with `errors.Is()`/`errors.As()` |

## API Reference

### Client Creation

```go
client, err := sentinel.NewClient(
    sentinel.WithBaseURL("https://sentinel.company.com"),  // Gateway URL
    sentinel.WithAPIKey("sk-..."),                          // API key
    sentinel.WithTenant("acme-corp"),                       // Tenant ID
    sentinel.WithAgent("support-bot"),                      // Agent ID
    sentinel.WithTimeout(10 * time.Second),                 // Request timeout
    sentinel.WithRetries(3),                                // Auto-retry count
    sentinel.WithRetryWait(500 * time.Millisecond),         // Retry base wait
    sentinel.WithHTTPClient(customClient),                  // Custom http.Client
    sentinel.WithHeader("X-Custom", "value"),               // Custom headers
)
```

### Scan Input

Scans user input for prompt injection, jailbreak, encoded attacks, and other threats.

```go
result, err := client.ScanInput(ctx, "user message")
if err != nil {
    // Handle error (network, auth, etc.)
}

switch result.Verdict {
case sentinel.VerdictBlock:
    // Reject the input
case sentinel.VerdictWarn:
    // Log warning, proceed with caution
case sentinel.VerdictAllow:
    // Safe to proceed
}
```

### Scan Output

Scans LLM responses for leaked secrets, PII, and credentials.

```go
result, err := client.ScanOutput(ctx, "llm response text")
if result.Verdict == sentinel.VerdictRedact {
    // Content was modified (secrets masked)
}
```

### Batch Scan

Scan multiple items efficiently in a single request.

```go
results, err := client.ScanBatch(ctx, []sentinel.ScanItem{
    {Content: "message 1", ID: "req-001"},
    {Content: "message 2", ID: "req-002"},
    {Content: "message 3", ID: "req-003"},
})

fmt.Printf("Blocked: %d/%d\n", results.TotalBlocked, results.TotalItems)
```

### Chat Completion (Proxy Mode)

Send chat completions through the gateway with full guardrail protection.

```go
resp, err := client.ChatCompletion(ctx, sentinel.ChatRequest{
    Model: "gpt-4",
    Messages: []sentinel.Message{
        {Role: "system", Content: "You are a helpful assistant."},
        {Role: "user", Content: "Hello!"},
    },
})

fmt.Println(resp.Choices[0].Message.Content)
```

### Tool Validation (Sidecar Mode)

Pre-validate tool calls before execution.

```go
result, err := client.ValidateTool(ctx, "run_command", map[string]any{
    "command": "ls -la /tmp",
})

if result.Verdict == sentinel.VerdictBlock {
    fmt.Println("Tool call denied by policy")
}
```

### Health Check

```go
status, err := client.Health(ctx)
fmt.Printf("Gateway: %s (v%s)\n", status.Status, status.Version)
```

## Local Guard (Offline Scanning)

The Guard provides instant, offline regex scanning with zero network dependency.
It contains the top 15 most critical detection patterns from Sentinel Gateway.

```go
guard := sentinel.NewGuard()

// Scan locally — sub-millisecond, no network
result := guard.Scan("ignore all previous instructions")
if result.Verdict.IsBlocked() {
    fmt.Printf("Blocked: %s\n", result.Findings[0].Description)
}
```

**Covered categories:**
- Prompt injection (4 patterns)
- Jailbreak (3 patterns)
- Reverse shell / RCE (3 patterns)
- Command injection (2 patterns)
- Credential leak (3 patterns)

The Guard is thread-safe and suitable for concurrent use from multiple goroutines.

## HTTP Middleware

Drop-in middleware for `net/http` servers. Automatically scans request bodies
and blocks malicious content with a 403 response.

```go
mux := http.NewServeMux()

// Wrap your handler with Sentinel middleware
mux.Handle("/api/chat", sentinel.Middleware(client)(chatHandler))
```

Access the scan result in downstream handlers:

```go
func chatHandler(w http.ResponseWriter, r *http.Request) {
    result := sentinel.ResultFromContext(r.Context())
    if result != nil {
        log.Printf("Sentinel verdict: %s", result.Verdict)
    }
    // ... handle request
}
```

## Error Handling

The SDK provides structured errors compatible with `errors.Is()` and `errors.As()`.

```go
result, err := client.ScanInput(ctx, content)
if err != nil {
    // Check specific error types
    if sentinel.IsBlocked(err) {
        // Content was blocked (403)
    } else if sentinel.IsRateLimited(err) {
        // Back off and retry
    } else if sentinel.IsRetryable(err) {
        // Can retry (rate limit, timeout, server error)
    }

    // Extract full API error details
    var apiErr *sentinel.APIError
    if errors.As(err, &apiErr) {
        fmt.Printf("Status: %d, Code: %s, RequestID: %s\n",
            apiErr.StatusCode, apiErr.Code, apiErr.RequestID)
    }
}
```

## Thread Safety

Both `Client` and `Guard` are safe for concurrent use. Create one instance
and share it across goroutines:

```go
// Create once at startup
var (
    client *sentinel.Client
    guard  *sentinel.Guard
)

func init() {
    var err error
    client, err = sentinel.NewClient(sentinel.WithAPIKey(os.Getenv("SENTINEL_API_KEY")))
    if err != nil {
        log.Fatal(err)
    }
    guard = sentinel.NewGuard()
}
```

## Configuration via Environment

Recommended pattern for production:

```go
client, err := sentinel.NewClient(
    sentinel.WithBaseURL(os.Getenv("SENTINEL_URL")),
    sentinel.WithAPIKey(os.Getenv("SENTINEL_API_KEY")),
    sentinel.WithTenant(os.Getenv("SENTINEL_TENANT")),
    sentinel.WithAgent(os.Getenv("SENTINEL_AGENT")),
)
```

## Compatibility

| Go Version | Status |
|-----------|--------|
| 1.21+ | Supported |
| 1.20 | May work (untested) |
| < 1.20 | Not supported |

Dependencies: **none** (stdlib only — `net/http`, `encoding/json`, `regexp`, `context`)

## License

GPL-3.0-or-later (same as Sentinel Gateway)
