package sentinel

import (
	"errors"
	"fmt"
)

// Sentinel error variables for use with errors.Is().
var (
	// ErrBlocked is returned when content is blocked by a guardrail.
	ErrBlocked = errors.New("sentinel: content blocked by guardrail")

	// ErrUnauthorized is returned when authentication fails.
	ErrUnauthorized = errors.New("sentinel: unauthorized (check API key)")

	// ErrRateLimited is returned when the rate limit is exceeded.
	ErrRateLimited = errors.New("sentinel: rate limit exceeded")

	// ErrTimeout is returned when a request times out.
	ErrTimeout = errors.New("sentinel: request timed out")

	// ErrServerError is returned for 5xx responses from the gateway.
	ErrServerError = errors.New("sentinel: server error")

	// ErrInvalidConfig is returned when the client configuration is invalid.
	ErrInvalidConfig = errors.New("sentinel: invalid configuration")

	// ErrNoContent is returned when scan input is empty.
	ErrNoContent = errors.New("sentinel: no content provided")
)

// APIError represents a structured error response from the Sentinel Gateway API.
// Use errors.As() to extract it from a returned error.
type APIError struct {
	// StatusCode is the HTTP status code returned by the gateway.
	StatusCode int `json:"status_code"`

	// Code is the machine-readable error code (e.g., "BLOCKED", "RATE_LIMITED").
	Code string `json:"code"`

	// Message is the human-readable error description.
	Message string `json:"message"`

	// RequestID is the request correlation ID from the gateway.
	RequestID string `json:"request_id,omitempty"`

	// RetryAfter indicates seconds until the next request is allowed (rate limiting).
	RetryAfter int `json:"retry_after,omitempty"`
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.RequestID != "" {
		return fmt.Sprintf("sentinel: API error %d (%s): %s [request_id=%s]",
			e.StatusCode, e.Code, e.Message, e.RequestID)
	}
	return fmt.Sprintf("sentinel: API error %d (%s): %s",
		e.StatusCode, e.Code, e.Message)
}

// Unwrap returns the underlying sentinel error for use with errors.Is().
func (e *APIError) Unwrap() error {
	switch {
	case e.StatusCode == 401:
		return ErrUnauthorized
	case e.StatusCode == 403:
		return ErrBlocked
	case e.StatusCode == 429:
		return ErrRateLimited
	case e.StatusCode >= 500:
		return ErrServerError
	default:
		return nil
	}
}

// IsBlocked returns true if the error represents blocked content.
func IsBlocked(err error) bool {
	return errors.Is(err, ErrBlocked)
}

// IsRateLimited returns true if the error represents a rate limit.
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// IsRetryable returns true if the request can be retried.
func IsRetryable(err error) bool {
	if errors.Is(err, ErrRateLimited) || errors.Is(err, ErrTimeout) || errors.Is(err, ErrServerError) {
		return true
	}
	return false
}
