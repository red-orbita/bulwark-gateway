package sentinel

import "time"

// Verdict represents the security decision made by the gateway.
type Verdict string

const (
	// VerdictAllow indicates the content is safe to proceed.
	VerdictAllow Verdict = "allow"

	// VerdictBlock indicates the content was blocked by a guardrail.
	VerdictBlock Verdict = "block"

	// VerdictWarn indicates suspicious content that was allowed with a warning.
	VerdictWarn Verdict = "warn"

	// VerdictRedact indicates sensitive content was masked before forwarding.
	VerdictRedact Verdict = "redact"
)

// IsBlocked returns true if the verdict is Block.
func (v Verdict) IsBlocked() bool {
	return v == VerdictBlock
}

// IsSafe returns true if the verdict is Allow.
func (v Verdict) IsSafe() bool {
	return v == VerdictAllow
}

// ScanResult is the response from a scan operation.
type ScanResult struct {
	// Verdict is the security decision.
	Verdict Verdict `json:"verdict"`

	// ScanID is the unique identifier for this scan.
	ScanID string `json:"scan_id"`

	// Findings contains detected security issues.
	Findings []Finding `json:"findings"`

	// Metadata contains additional scan information.
	Metadata Metadata `json:"metadata"`
}

// Finding represents a single detected security issue.
type Finding struct {
	// Category is the threat category (e.g., "prompt_injection", "jailbreak").
	Category string `json:"category"`

	// Severity is the finding severity: "low", "medium", "high", "critical".
	Severity string `json:"severity"`

	// Description is a human-readable explanation of the finding.
	Description string `json:"description"`

	// PatternID is the identifier of the matched detection pattern.
	PatternID string `json:"pattern_id"`

	// Confidence is the detection confidence score (0.0 to 1.0).
	Confidence float64 `json:"confidence"`
}

// Metadata contains supplementary information about a scan.
type Metadata struct {
	// Latency is the scan duration.
	Latency time.Duration `json:"latency_ms"`

	// PatternsChecked is the number of patterns evaluated.
	PatternsChecked int `json:"patterns_checked"`

	// Tenant is the tenant that owns this scan.
	Tenant string `json:"tenant,omitempty"`

	// Agent is the agent ID associated with this scan.
	Agent string `json:"agent,omitempty"`

	// RequestID is the gateway request correlation ID.
	RequestID string `json:"request_id,omitempty"`
}

// ScanItem represents a single item in a batch scan request.
type ScanItem struct {
	// Content is the text to scan.
	Content string `json:"content"`

	// ID is an optional client-provided correlation ID.
	ID string `json:"id,omitempty"`
}

// BatchResult wraps results for a batch scan operation.
type BatchResult struct {
	// Results maps item IDs to their scan results.
	Results []BatchResultItem `json:"results"`

	// TotalBlocked is the count of blocked items in this batch.
	TotalBlocked int `json:"total_blocked"`

	// TotalItems is the total number of items scanned.
	TotalItems int `json:"total_items"`
}

// BatchResultItem is a single result within a batch.
type BatchResultItem struct {
	// ID is the client-provided correlation ID.
	ID string `json:"id"`

	// Result is the scan result for this item.
	Result ScanResult `json:"result"`
}

// ChatRequest is an OpenAI-compatible chat completion request.
type ChatRequest struct {
	// Model is the LLM model to use.
	Model string `json:"model"`

	// Messages is the conversation history.
	Messages []Message `json:"messages"`

	// Tools is the list of available tools (optional).
	Tools []Tool `json:"tools,omitempty"`

	// ToolChoice controls tool selection behavior (optional).
	ToolChoice any `json:"tool_choice,omitempty"`

	// Temperature controls randomness (0.0-2.0).
	Temperature *float64 `json:"temperature,omitempty"`

	// MaxTokens limits the response length.
	MaxTokens *int `json:"max_tokens,omitempty"`

	// Stream enables server-sent events streaming.
	Stream bool `json:"stream,omitempty"`
}

// Message represents a single message in a chat conversation.
type Message struct {
	// Role is the message role: "system", "user", "assistant", "tool".
	Role string `json:"role"`

	// Content is the message text content.
	Content string `json:"content"`

	// Name is an optional participant name.
	Name string `json:"name,omitempty"`

	// ToolCalls contains tool invocations from the assistant (optional).
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`

	// ToolCallID is the ID of the tool call this message responds to.
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// Tool describes a callable tool.
type Tool struct {
	// Type is always "function".
	Type string `json:"type"`

	// Function describes the function.
	Function ToolFunction `json:"function"`
}

// ToolFunction describes a function tool.
type ToolFunction struct {
	// Name is the function identifier.
	Name string `json:"name"`

	// Description explains what the function does.
	Description string `json:"description,omitempty"`

	// Parameters is the JSON Schema for function parameters.
	Parameters any `json:"parameters,omitempty"`
}

// ToolCall represents a tool invocation by the model.
type ToolCall struct {
	// ID is the tool call identifier.
	ID string `json:"id"`

	// Type is always "function".
	Type string `json:"type"`

	// Function contains the function name and arguments.
	Function ToolCallFunction `json:"function"`
}

// ToolCallFunction contains the details of a function call.
type ToolCallFunction struct {
	// Name is the function to call.
	Name string `json:"name"`

	// Arguments is a JSON string of function arguments.
	Arguments string `json:"arguments"`
}

// ChatResponse is the response from a chat completion request.
type ChatResponse struct {
	// ID is the response identifier.
	ID string `json:"id"`

	// Object is the response type (e.g., "chat.completion").
	Object string `json:"object"`

	// Created is the creation timestamp.
	Created int64 `json:"created"`

	// Model is the model that generated the response.
	Model string `json:"model"`

	// Choices contains the generated completions.
	Choices []Choice `json:"choices"`

	// Usage contains token usage information.
	Usage *Usage `json:"usage,omitempty"`
}

// Choice represents a single completion choice.
type Choice struct {
	// Index is the choice index.
	Index int `json:"index"`

	// Message is the generated message.
	Message Message `json:"message"`

	// FinishReason indicates why generation stopped.
	FinishReason string `json:"finish_reason"`
}

// Usage contains token usage statistics.
type Usage struct {
	// PromptTokens is the number of input tokens.
	PromptTokens int `json:"prompt_tokens"`

	// CompletionTokens is the number of generated tokens.
	CompletionTokens int `json:"completion_tokens"`

	// TotalTokens is the sum of prompt and completion tokens.
	TotalTokens int `json:"total_tokens"`
}

// HealthStatus represents the gateway health check response.
type HealthStatus struct {
	// Status is "healthy" or "degraded".
	Status string `json:"status"`

	// Version is the gateway version.
	Version string `json:"version"`

	// Uptime is the gateway uptime in seconds.
	Uptime float64 `json:"uptime"`
}
