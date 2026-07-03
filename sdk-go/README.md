# Bulwark Gateway Go SDK

Production-ready Go client for the [Bulwark Gateway](https://github.com/bulwark-gateway/bulwark-gateway) security proxy.

## Installation

```bash
go get github.com/bulwark-gateway/sdk-go
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

    bulwark "github.com/bulwark-gateway/sdk-go"
)

func main() {
    // Create client
    client, err := bulwark.NewClient(
        bulwark.WithBaseURL("https://bulwark.company.com"),
        bulwark.WithAPIKey("sk-your-api-key"),
        bulwark.WithTenant("acme-corp"),
        bulwark.WithAgent("support-bot"),
        bulwark.WithTimeout(10 * time.Second),
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

    if result.Verdict == bulwark.VerdictBlock {
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
client, err := bulwark.NewClient(
    bulwark.WithBaseURL("https://bulwark.company.com"),  // Gateway URL
    bulwark.WithAPIKey("sk-..."),                          // API key
    bulwark.WithTenant("acme-corp"),                       // Tenant ID
    bulwark.WithAgent("support-bot"),                      // Agent ID
    bulwark.WithTimeout(10 * time.Second),                 // Request timeout
    bulwark.WithRetries(3),                                // Auto-retry count
    bulwark.WithRetryWait(500 * time.Millisecond),         // Retry base wait
    bulwark.WithHTTPClient(customClient),                  // Custom http.Client
    bulwark.WithHeader("X-Custom", "value"),               // Custom headers
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
case bulwark.VerdictBlock:
    // Reject the input
case bulwark.VerdictWarn:
    // Log warning, proceed with caution
case bulwark.VerdictAllow:
    // Safe to proceed
}
```

### Scan Output

Scans LLM responses for leaked secrets, PII, and credentials.

```go
result, err := client.ScanOutput(ctx, "llm response text")
if result.Verdict == bulwark.VerdictRedact {
    // Content was modified (secrets masked)
}
```

### Batch Scan

Scan multiple items efficiently in a single request.

```go
results, err := client.ScanBatch(ctx, []bulwark.ScanItem{
    {Content: "message 1", ID: "req-001"},
    {Content: "message 2", ID: "req-002"},
    {Content: "message 3", ID: "req-003"},
})

fmt.Printf("Blocked: %d/%d\n", results.TotalBlocked, results.TotalItems)
```

### Chat Completion (Proxy Mode)

Send chat completions through the gateway with full guardrail protection.

```go
resp, err := client.ChatCompletion(ctx, bulwark.ChatRequest{
    Model: "gpt-4",
    Messages: []bulwark.Message{
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

if result.Verdict == bulwark.VerdictBlock {
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
It contains the top 15 most critical detection patterns from Bulwark Gateway.

```go
guard := bulwark.NewGuard()

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

// Wrap your handler with Bulwark middleware
mux.Handle("/api/chat", bulwark.Middleware(client)(chatHandler))
```

Access the scan result in downstream handlers:

```go
func chatHandler(w http.ResponseWriter, r *http.Request) {
    result := bulwark.ResultFromContext(r.Context())
    if result != nil {
        log.Printf("Bulwark verdict: %s", result.Verdict)
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
    if bulwark.IsBlocked(err) {
        // Content was blocked (403)
    } else if bulwark.IsRateLimited(err) {
        // Back off and retry
    } else if bulwark.IsRetryable(err) {
        // Can retry (rate limit, timeout, server error)
    }

    // Extract full API error details
    var apiErr *bulwark.APIError
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
    client *bulwark.Client
    guard  *bulwark.Guard
)

func init() {
    var err error
    client, err = bulwark.NewClient(bulwark.WithAPIKey(os.Getenv("BULWARK_API_KEY")))
    if err != nil {
        log.Fatal(err)
    }
    guard = bulwark.NewGuard()
}
```

## Configuration via Environment

Recommended pattern for production:

```go
client, err := bulwark.NewClient(
    bulwark.WithBaseURL(os.Getenv("BULWARK_URL")),
    bulwark.WithAPIKey(os.Getenv("BULWARK_API_KEY")),
    bulwark.WithTenant(os.Getenv("BULWARK_TENANT")),
    bulwark.WithAgent(os.Getenv("BULWARK_AGENT")),
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

GPL-3.0-or-later (same as Bulwark Gateway)
