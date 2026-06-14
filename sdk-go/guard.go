package sentinel

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Guard provides local (offline) regex-based scanning without network calls.
// It contains the top 15 most critical detection patterns from the Sentinel Gateway,
// compiled once at creation time. Guard is safe for concurrent use.
//
// Use Guard when you need:
//   - Zero-latency scanning (no network round trip)
//   - Offline environments without gateway connectivity
//   - Pre-filtering before sending to the gateway API
//   - Edge deployments with limited connectivity
type Guard struct {
	patterns []guardPattern
}

// guardPattern is a compiled regex pattern with metadata.
type guardPattern struct {
	regex       *regexp.Regexp
	category    string
	severity    string
	description string
	patternID   string
}

// defaultPatterns contains the top 15 most critical detection patterns.
// These cover the highest-risk threat categories seen in production.
var defaultPatterns = []struct {
	pattern     string
	category    string
	severity    string
	description string
	patternID   string
}{
	// Prompt Injection (4 patterns)
	{
		pattern:     `(?i)ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)`,
		category:    "prompt_injection",
		severity:    "critical",
		description: "Instruction override attempt — classic prompt injection prefix",
		patternID:   "SEN-PI-001",
	},
	{
		pattern:     `(?i)you\s+are\s+now\s+(a|an|the)\s+\w+`,
		category:    "prompt_injection",
		severity:    "high",
		description: "Role reassignment via persona injection",
		patternID:   "SEN-PI-002",
	},
	{
		pattern:     `(?i)(system\s*prompt|system\s*message)\s*[:=]\s*`,
		category:    "prompt_injection",
		severity:    "critical",
		description: "Direct system prompt override attempt",
		patternID:   "SEN-PI-003",
	},
	{
		pattern:     `(?i)\[\s*INST\s*\]|\[\s*\/INST\s*\]|<\|im_start\|>|<\|im_end\|>`,
		category:    "prompt_injection",
		severity:    "critical",
		description: "Model-specific token injection (Llama/ChatML format tokens)",
		patternID:   "SEN-PI-004",
	},

	// Jailbreak (3 patterns)
	{
		pattern:     `(?i)(DAN|do\s+anything\s+now)\s*(mode|prompt|jailbreak)?`,
		category:    "jailbreak",
		severity:    "critical",
		description: "DAN (Do Anything Now) jailbreak attempt",
		patternID:   "SEN-JB-001",
	},
	{
		pattern:     `(?i)developer\s+mode\s+(enabled|activated|on)|act\s+as\s+.*?without\s+(restriction|filter|limit)`,
		category:    "jailbreak",
		severity:    "high",
		description: "Developer mode activation or unrestricted persona request",
		patternID:   "SEN-JB-002",
	},
	{
		pattern:     `(?i)pretend\s+(you\s+)?(are|have)\s+no\s+(restrictions?|limitations?|rules?|filters?|guardrails?)`,
		category:    "jailbreak",
		severity:    "high",
		description: "Restriction removal via pretend/roleplay",
		patternID:   "SEN-JB-003",
	},

	// Reverse Shell / RCE (3 patterns)
	{
		pattern:     `(?i)(bash|sh|nc|ncat|netcat)\s+-[a-z]*\s+.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+`,
		category:    "reverse_shell",
		severity:    "critical",
		description: "Reverse shell command with IP and port",
		patternID:   "SEN-RS-001",
	},
	{
		pattern:     `(?i)python[23]?\s+-c\s+['"]import\s+(socket|os|subprocess|pty)`,
		category:    "reverse_shell",
		severity:    "critical",
		description: "Python reverse shell one-liner",
		patternID:   "SEN-RS-002",
	},
	{
		pattern:     `(?i)(curl|wget)\s+.*\|\s*(bash|sh|zsh|python)`,
		category:    "command_injection",
		severity:    "critical",
		description: "Remote code execution via pipe to shell",
		patternID:   "SEN-CI-001",
	},

	// Command Injection (2 patterns)
	{
		pattern:     "(?i)[;&|`]\\s*(rm|chmod|chown|mkfs|dd|wget|curl)\\s",
		category:    "command_injection",
		severity:    "high",
		description: "Shell command chaining with dangerous commands",
		patternID:   "SEN-CI-002",
	},
	{
		pattern:     `(?i)\$\((.*?(rm|wget|curl|nc|bash).*?)\)|\x60(.*?(rm|wget|curl|nc|bash).*?)\x60`,
		category:    "command_injection",
		severity:    "high",
		description: "Command substitution with dangerous commands",
		patternID:   "SEN-CI-003",
	},

	// Credential Leak (3 patterns)
	{
		pattern:     `(?i)(AKIA|ASIA)[A-Z0-9]{16}`,
		category:    "credential_leak",
		severity:    "critical",
		description: "AWS access key ID detected",
		patternID:   "SEN-CL-001",
	},
	{
		pattern:     `(?i)(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9]{20,})`,
		category:    "credential_leak",
		severity:    "critical",
		description: "OpenAI API key detected",
		patternID:   "SEN-CL-002",
	},
	{
		pattern:     `(?i)(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})`,
		category:    "credential_leak",
		severity:    "high",
		description: "GitHub personal access token detected",
		patternID:   "SEN-CL-003",
	},
}

// NewGuard creates a new local Guard with the default pattern set.
// Patterns are compiled once and safe for concurrent use.
// Returns an error if any pattern fails to compile.
func NewGuard() (*Guard, error) {
	patterns := make([]guardPattern, 0, len(defaultPatterns))
	for _, p := range defaultPatterns {
		compiled, err := regexp.Compile(p.pattern)
		if err != nil {
			// SECURITY (L-10 fix): Return error instead of panicking.
			// A panic in production on invalid regex is a DoS vector.
			return nil, fmt.Errorf("sentinel: failed to compile pattern %s: %w", p.patternID, err)
		}
		patterns = append(patterns, guardPattern{
			regex:       compiled,
			category:    p.category,
			severity:    p.severity,
			description: p.description,
			patternID:   p.patternID,
		})
	}

	return &Guard{patterns: patterns}, nil
}

// Scan checks the input text against all local patterns and returns a ScanResult.
// This method is safe for concurrent use from multiple goroutines.
//
// The scan runs entirely in-memory with no network calls. Typical latency
// is under 1ms for normal-length inputs.
func (g *Guard) Scan(input string) *ScanResult {
	start := time.Now()

	if input == "" {
		return &ScanResult{
			Verdict: VerdictAllow,
			Metadata: Metadata{
				Latency:         time.Since(start),
				PatternsChecked: 0,
			},
		}
	}

	// Normalize: collapse whitespace for detection evasion resistance
	normalized := normalizeInput(input)

	var findings []Finding
	maxSeverity := ""

	for _, p := range g.patterns {
		if p.regex.MatchString(normalized) {
			findings = append(findings, Finding{
				Category:    p.category,
				Severity:    p.severity,
				Description: p.description,
				PatternID:   p.patternID,
				Confidence:  1.0, // Regex matches are binary
			})

			// Track highest severity
			if severityRank(p.severity) > severityRank(maxSeverity) {
				maxSeverity = p.severity
			}
		}
	}

	verdict := VerdictAllow
	if len(findings) > 0 {
		// Block on high/critical, warn on medium/low
		if severityRank(maxSeverity) >= severityRank("high") {
			verdict = VerdictBlock
		} else {
			verdict = VerdictWarn
		}
	}

	return &ScanResult{
		Verdict:  verdict,
		ScanID:   "local",
		Findings: findings,
		Metadata: Metadata{
			Latency:         time.Since(start),
			PatternsChecked: len(g.patterns),
		},
	}
}

// PatternCount returns the number of active patterns in the guard.
func (g *Guard) PatternCount() int {
	return len(g.patterns)
}

// Categories returns the unique threat categories covered by the guard.
func (g *Guard) Categories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, p := range g.patterns {
		if !seen[p.category] {
			seen[p.category] = true
			cats = append(cats, p.category)
		}
	}
	return cats
}

// normalizeInput performs Unicode normalization to resist evasion techniques.
// SECURITY (H-18 fix): Applies NFKC normalization (resolves homoglyphs,
// compatibility decomposition) and strips zero-width/invisible characters
// before collapsing whitespace. Matches Python proxy behavior.
func normalizeInput(s string) string {
	// Step 1: NFKC normalization (homoglyph resolution, compatibility decomposition)
	s = norm.NFKC.String(s)

	// Step 2: Strip zero-width and invisible characters
	var cleaned strings.Builder
	cleaned.Grow(len(s))
	for _, r := range s {
		if isInvisibleChar(r) {
			continue
		}
		cleaned.WriteRune(r)
	}
	s = cleaned.String()

	// Step 3: Collapse multiple spaces/tabs/newlines into single space
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if !prevSpace {
				b.WriteRune(' ')
				prevSpace = true
			}
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return strings.ToLower(b.String())
}

// isInvisibleChar returns true for zero-width and invisible Unicode characters
// commonly used in evasion attacks.
func isInvisibleChar(r rune) bool {
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\uFEFF', // BOM / zero-width no-break space
		'\u00AD', // soft hyphen
		'\u200E', // left-to-right mark
		'\u200F', // right-to-left mark
		'\u2060', // word joiner
		'\u2061', // function application
		'\u2062', // invisible times
		'\u2063', // invisible separator
		'\u2064': // invisible plus
		return true
	}
	// Also strip characters in Unicode category "Format" (Cf) not already handled
	return unicode.Is(unicode.Cf, r) && r != '\n' && r != '\r' && r != '\t'
}

// severityRank returns a numeric rank for severity comparison.
func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
