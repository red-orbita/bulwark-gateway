package sentinel

import (
	"net/http"
	"time"
)

// Option is a functional option for configuring the Client.
type Option func(*clientConfig)

// clientConfig holds all configuration for the Client.
type clientConfig struct {
	baseURL    string
	apiKey     string
	tenant     string
	agent      string
	timeout    time.Duration
	httpClient *http.Client
	userAgent  string
	retries    int
	retryWait  time.Duration
	headers    map[string]string
}

// defaultConfig returns the default client configuration.
func defaultConfig() *clientConfig {
	return &clientConfig{
		baseURL:   "http://localhost:8080",
		timeout:   30 * time.Second,
		userAgent: "sentinel-go-sdk/0.1.0",
		retries:   0,
		retryWait: 1 * time.Second,
		headers:   make(map[string]string),
	}
}

// WithBaseURL sets the Sentinel Gateway base URL.
func WithBaseURL(url string) Option {
	return func(c *clientConfig) {
		c.baseURL = url
	}
}

// WithAPIKey sets the API key for authentication.
func WithAPIKey(key string) Option {
	return func(c *clientConfig) {
		c.apiKey = key
	}
}

// WithTenant sets the tenant ID for multi-tenant routing.
func WithTenant(tenant string) Option {
	return func(c *clientConfig) {
		c.tenant = tenant
	}
}

// WithAgent sets the agent ID for policy resolution.
func WithAgent(agent string) Option {
	return func(c *clientConfig) {
		c.agent = agent
	}
}

// WithTimeout sets the HTTP request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *clientConfig) {
		c.timeout = timeout
	}
}

// WithHTTPClient sets a custom HTTP client. When set, WithTimeout is ignored.
func WithHTTPClient(client *http.Client) Option {
	return func(c *clientConfig) {
		c.httpClient = client
	}
}

// WithUserAgent sets the User-Agent header for requests.
func WithUserAgent(ua string) Option {
	return func(c *clientConfig) {
		c.userAgent = ua
	}
}

// WithRetries sets the number of automatic retries for retryable errors.
// Only rate-limited (429), timeout, and server error (5xx) responses are retried.
func WithRetries(n int) Option {
	return func(c *clientConfig) {
		if n >= 0 {
			c.retries = n
		}
	}
}

// WithRetryWait sets the base wait time between retries (exponential backoff).
func WithRetryWait(d time.Duration) Option {
	return func(c *clientConfig) {
		c.retryWait = d
	}
}

// WithHeader adds a custom header to all requests.
func WithHeader(key, value string) Option {
	return func(c *clientConfig) {
		c.headers[key] = value
	}
}
