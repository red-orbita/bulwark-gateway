package sentinel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// scanRequest is the internal request body for scan API calls.
type scanRequest struct {
	Content  string `json:"content"`
	Type     string `json:"type"` // "input" or "output"
	Tenant   string `json:"tenant,omitempty"`
	Agent    string `json:"agent,omitempty"`
	Metadata any    `json:"metadata,omitempty"`
}

// batchScanRequest is the internal request body for batch scan API calls.
type batchScanRequest struct {
	Items  []ScanItem `json:"items"`
	Type   string     `json:"type"`
	Tenant string     `json:"tenant,omitempty"`
	Agent  string     `json:"agent,omitempty"`
}

// ScanInput scans user input content through the Sentinel Gateway's input guardrails.
// This checks for prompt injection, jailbreak attempts, encoded attacks, and other threats.
//
// Returns the scan result with verdict and any findings. If the content is blocked,
// the verdict will be VerdictBlock and findings will contain details.
func (c *Client) ScanInput(ctx context.Context, content string) (*ScanResult, error) {
	if content == "" {
		return nil, ErrNoContent
	}

	return c.scan(ctx, content, "input")
}

// ScanOutput scans LLM output content through the Sentinel Gateway's output filters.
// This checks for leaked secrets, PII, credentials, and other sensitive data.
//
// Returns the scan result with verdict. If sensitive content is found, the verdict
// may be VerdictRedact (content was masked) or VerdictBlock.
func (c *Client) ScanOutput(ctx context.Context, content string) (*ScanResult, error) {
	if content == "" {
		return nil, ErrNoContent
	}

	return c.scan(ctx, content, "output")
}

// scan is the internal implementation for both input and output scanning.
func (c *Client) scan(ctx context.Context, content, scanType string) (*ScanResult, error) {
	payload := scanRequest{
		Content: content,
		Type:    scanType,
		Tenant:  c.cfg.tenant,
		Agent:   c.cfg.agent,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal scan request: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/v2/scan", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var result ScanResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ScanBatch scans multiple content items in a single request.
// This is more efficient than individual scans for batch processing workloads.
//
// Each item must have Content set. The ID field is optional but recommended
// for correlating results with source items.
//
// Returns a BatchResult with individual results for each item.
func (c *Client) ScanBatch(ctx context.Context, items []ScanItem) (*BatchResult, error) {
	if len(items) == 0 {
		return nil, ErrNoContent
	}

	// Validate items
	for i, item := range items {
		if item.Content == "" {
			return nil, fmt.Errorf("%w: item at index %d has empty content", ErrNoContent, i)
		}
		// Assign default IDs if not provided
		if item.ID == "" {
			items[i].ID = fmt.Sprintf("item-%d", i)
		}
	}

	payload := batchScanRequest{
		Items:  items,
		Type:   "input",
		Tenant: c.cfg.tenant,
		Agent:  c.cfg.agent,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal batch request: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/v2/scan/batch", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var result BatchResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ValidateTool pre-validates a tool call before execution (sidecar mode).
// This checks the tool name, arguments, and calling patterns against the
// agent's RBAC policy without actually executing the tool.
//
// Returns the scan result. VerdictAllow means the tool call is permitted.
func (c *Client) ValidateTool(ctx context.Context, toolName string, arguments map[string]any) (*ScanResult, error) {
	if toolName == "" {
		return nil, fmt.Errorf("%w: tool name is required", ErrNoContent)
	}

	payload := map[string]any{
		"tool_name": toolName,
		"arguments": arguments,
		"tenant":    c.cfg.tenant,
		"agent":     c.cfg.agent,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("sentinel: failed to marshal tool validation request: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/v1/tool/validate", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	var result ScanResult
	if err := c.do(req, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
