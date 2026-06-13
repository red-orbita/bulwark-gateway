"""
Tool Policy Engine — RBAC enforcement on tool calls.

Defines which tools each agent/tenant can use, with what parameters,
and under what conditions. Includes:
- Default-deny for unknown tools (no policy = only safe tools allowed)
- Self-protection: blocks modifications to gateway config files
- Sensitive file read blocking
- Network tool blocking
- IOC-aware URL validation via domain_intel
- Subdomain-aware matching
"""

import re
import unicodedata
from dataclasses import dataclass, field

from src.models import GuardrailResult, SecurityEvent, ThreatCategory, ToolCall, Verdict

# Self-protection: paths that tool calls must NEVER modify
_PROTECTED_PATHS = (
    "config/policies/",
    "config/iocs.json",
    "src/middleware/auth.py",
    "src/models.py",
    ".opencode/",
    ".env",
    "secrets.enc.yaml",
    ".security/",
)

# Sensitive paths that should NEVER be read by agents (regardless of policy)
_SENSITIVE_READ_PATTERNS: list[re.Pattern] = [
    re.compile(r"(^|/)\.env(\.|$|/)", re.IGNORECASE),
    re.compile(r"(^|/)\.aws/credentials", re.IGNORECASE),
    re.compile(r"(^|/)\.ssh/(id_rsa|id_ed25519|id_dsa|authorized_keys|config)", re.IGNORECASE),
    re.compile(r"/etc/(passwd|shadow|sudoers|hosts)", re.IGNORECASE),
    re.compile(r"\.(pem|key|p12|pfx|jks)$", re.IGNORECASE),
    re.compile(r"(^|/)credentials\.(json|yaml|yml|toml|xml)$", re.IGNORECASE),
    re.compile(r"(^|/)secrets?\.(json|yaml|yml|toml|xml|enc)$", re.IGNORECASE),
    re.compile(r"(^|/)(gcloud|kubectl)/.*config$", re.IGNORECASE),
    re.compile(r"(^|/)\.docker/config\.json$", re.IGNORECASE),
    re.compile(r"(^|/)\.git-credentials$", re.IGNORECASE),
    re.compile(r"(^|/)\.netrc$", re.IGNORECASE),
    re.compile(r"(^|/)\.pgpass$", re.IGNORECASE),
    re.compile(r"(^|/)kubeconfig$", re.IGNORECASE),
    re.compile(r"/proc/(self|[0-9]+)/environ", re.IGNORECASE),
    re.compile(r"/proc/(self|[0-9]+)/(cmdline|maps|fd)", re.IGNORECASE),
    # V5: New sensitive paths
    re.compile(r"(^|/)\.git/config$", re.IGNORECASE),
    re.compile(r"(^|/)\.npmrc$", re.IGNORECASE),
    re.compile(r"(^|/)terraform\.tfvars$", re.IGNORECASE),
    re.compile(r"(^|/)terraform\.tfstate$", re.IGNORECASE),
    re.compile(r"/var/run/secrets/", re.IGNORECASE),
    re.compile(r"(^|/)\.dockerconfigjson$", re.IGNORECASE),
    re.compile(r"/dev/fd/", re.IGNORECASE),
    re.compile(r"(^|/)\.pypirc$", re.IGNORECASE),
    re.compile(r"(^|/)\.gradle/gradle\.properties$", re.IGNORECASE),
    re.compile(r"(^|/)\.m2/settings\.xml$", re.IGNORECASE),
    re.compile(r"(^|/)\.kube/config$", re.IGNORECASE),
    re.compile(r"(^|/)\.config/gcloud/", re.IGNORECASE),
    # data: and file: URI schemes
    re.compile(r"^data:", re.IGNORECASE),
    re.compile(r"^file://", re.IGNORECASE),
]

# All argument names to inspect for path values (comprehensive)
_PATH_ARG_NAMES = (
    "path",
    "file",
    "filename",
    "filepath",
    "target",
    "file_path",
    "destination",
    "source",
    "input",
    "location",
    "resource",
    "url",
    "uri",
    "src",
    "dst",
    "directory",
    "dir",
    "folder",
    "content_path",
    "config",
    "config_file",
)

# === Tool Classification Sets ===
# Used for default-deny policy when no explicit tenant policy exists.

# Execution tools — ALWAYS blocked without explicit allow
_EXECUTION_TOOLS = frozenset(
    {
        "run_command",
        "execute",
        "bash",
        "shell",
        "terminal",
        "subprocess",
        "system",
        "os_exec",
        "eval",
        "exec",
        "spawn",
        "popen",
        "os.system",
        "os.popen",
        "cmd",
        "sh",
        "powershell",
        "python",
        "node",
        "ruby",
        "perl",
        "php",
        "lua",
        "java",
        "gcc",
        "make",
        "npm",
        "pip",
    }
)

# File write tools — ALWAYS blocked without explicit allow
_WRITE_TOOLS = frozenset(
    {
        "write_file",
        "create_file",
        "edit_file",
        "save",
        "delete_file",
        "rm",
        "mv",
        "rename",
        "append",
        "patch",
        "update_file",
        "overwrite",
        "modify",
        "mkdir",
        "rmdir",
        "chmod",
        "chown",
    }
)

# File read tools — allowed but subject to sensitive path checks
_READ_TOOLS = frozenset(
    {
        "read_file",
        "read",
        "cat",
        "get_file",
        "open_file",
        "view_file",
        "head",
        "tail",
        "less",
        "more",
        "open",
        "get_file_contents",
        "file_read",
        "fetch_file",
        "view",
        "inspect",
        "get",
        "load",
        "import_file",
        "grep",
        "find",
        "ls",
        "dir",
        "list_files",
        "list_directory",
    }
)

# Network tools — blocked without explicit allow_network_access
_NETWORK_TOOLS = frozenset(
    {
        "http_request",
        "webhook",
        "fetch",
        "dns_lookup",
        "curl",
        "wget",
        "request",
        "api_call",
        "send_request",
        "http_get",
        "http_post",
        "http_put",
        "http_delete",
        "send_email",
        "smtp",
        "ftp",
        "scp",
        "rsync",
        "socket",
        "connect",
        "tcp",
        "udp",
        "nslookup",
        "dig",
    }
)

# Safe tools — always allowed even without policy (informational only)
_SAFE_TOOLS = frozenset(
    {
        "web_search",
        "search",
        "calculate",
        "math",
        "get_time",
        "get_date",
        "get_weather",
        "read_knowledge_base",
        "get_ticket_info",
        "create_ticket",
        "update_ticket",
        "list_tickets",
        "get_status",
        "schedule_appointment",
        "get_calendar",
        "summarize",
        "translate",
        "spell_check",
    }
)

# Zero-width characters that must be stripped from tool names
_ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\ufeff\u00ad")

# Confusable character map: Cyrillic/Greek homoglyphs → Latin equivalents
_CONFUSABLE_MAP = str.maketrans(
    "еаосрхуіңтмквзн"  # Cyrillic lowercase
    "ЕАОСРХУІҢТМКВЗН"  # Cyrillic uppercase
    "ΑΒΕΗΙΚΜΝΟΡΤΧΥΖαβεηικμνοτυ",  # Greek
    "eaocpxyintmkvzn"  # Latin lowercase
    "EAOCPXYINТMKVZN"  # Latin uppercase
    "ABEHIKMNOPTXYZabenikmnoty",  # Latin
)


# SECURITY FIX (C-06): Normalize tool names to prevent Unicode/case bypass
def _normalize_tool_name(name: str) -> str:
    """Normalize a tool name to prevent bypass via Unicode tricks, case, or whitespace.

    Applies:
      1. NFKC normalization — collapses fullwidth and compatibility chars
      2. Confusable map — translates Cyrillic/Greek homoglyphs to Latin
      3. Zero-width character removal (U+200B, U+200C, U+200D, U+FEFF, U+00AD)
      4. casefold() — locale-aware lowercase for case-insensitive comparison
      5. strip() — removes leading/trailing whitespace
    """
    # 1. NFKC normalization (fullwidth → ASCII, compatibility decomposition)
    name = unicodedata.normalize("NFKC", name)
    # 2. Map cross-script homoglyphs (Cyrillic а → Latin a, etc.)
    name = name.translate(_CONFUSABLE_MAP)
    # 3. Remove zero-width characters
    name = "".join(ch for ch in name if ch not in _ZERO_WIDTH_CHARS)
    # 4. Case-insensitive comparison
    name = name.casefold()
    # 5. Strip whitespace
    name = name.strip()
    return name


@dataclass
class ToolPolicy:
    """Policy for a single tool."""

    name: str
    allowed: bool = True
    max_calls_per_request: int = 10
    denied_arguments: dict[str, list[str]] = field(default_factory=dict)
    required_arguments: list[str] = field(default_factory=list)
    argument_patterns: dict[str, str] = field(default_factory=dict)  # regex allowlist per arg


@dataclass
class AgentPolicy:
    """Complete policy for an agent within a tenant."""

    tenant_id: str
    agent_id: str
    allowed_tools: list[str] = field(default_factory=list)  # empty = all allowed
    denied_tools: list[str] = field(default_factory=list)
    tool_policies: dict[str, ToolPolicy] = field(default_factory=dict)
    max_tool_calls_per_request: int = 20
    allow_command_execution: bool = False
    allow_file_write: bool = False
    allow_network_access: bool = True
    sandbox_level: str = "standard"  # "minimal", "standard", "strict"


class ToolPolicyEngine:
    """Enforces tool-level RBAC policies."""

    def __init__(self):
        self.policies: dict[str, AgentPolicy] = {}  # key: "tenant_id:agent_id"

    def register_policy(self, policy: AgentPolicy):
        key = f"{policy.tenant_id}:{policy.agent_id}"
        self.policies[key] = policy

    def get_policy(self, tenant_id: str, agent_id: str) -> AgentPolicy | None:
        return self.policies.get(f"{tenant_id}:{agent_id}")

    def evaluate_tool_call(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str, call_count: int = 0
    ) -> GuardrailResult:
        """Evaluate a single tool call against the policy."""
        # SECURITY FIX (C-06): Normalize tool names to prevent Unicode/case bypass
        tool_call = tool_call.model_copy(
            update={"name": _normalize_tool_name(tool_call.name)}
        )

        policy = self.get_policy(tenant_id, agent_id)

        # No policy = use defaults (deny dangerous tools)
        if not policy:
            return self._evaluate_default(tool_call, tenant_id, agent_id)

        events: list[SecurityEvent] = []

        # Check if tool is explicitly denied
        if tool_call.name in {_normalize_tool_name(t) for t in policy.denied_tools}:
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.POLICY_VIOLATION,
                    description=f"Tool '{tool_call.name}' is denied by policy",
                    source="tool_policy_engine",
                    severity="high",
                    tool_name=tool_call.name,
                )
            )
            return GuardrailResult(
                verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
            )

        # Check allowlist (if defined, only listed tools are allowed)
        if policy.allowed_tools and tool_call.name not in {
            _normalize_tool_name(t) for t in policy.allowed_tools
        }:
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.POLICY_VIOLATION,
                    description=f"Tool '{tool_call.name}' not in allowlist",
                    source="tool_policy_engine",
                    severity="high",
                    tool_name=tool_call.name,
                )
            )
            return GuardrailResult(
                verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
            )

        # Check rate limit per request
        if call_count >= policy.max_tool_calls_per_request:
            events.append(
                SecurityEvent(
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    verdict=Verdict.BLOCK,
                    category=ThreatCategory.POLICY_VIOLATION,
                    description=f"Max tool calls per request exceeded ({policy.max_tool_calls_per_request})",
                    source="tool_policy_engine",
                    severity="medium",
                    tool_name=tool_call.name,
                )
            )
            return GuardrailResult(verdict=Verdict.BLOCK, events=events)

        # Check command execution permission
        if tool_call.name in _EXECUTION_TOOLS:
            if not policy.allow_command_execution:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.TOOL_ABUSE,
                        description="Command execution not allowed for this agent",
                        source="tool_policy_engine",
                        severity="critical",
                        tool_name=tool_call.name,
                    )
                )
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                )

        # Check file write permission
        if tool_call.name in _WRITE_TOOLS:
            if not policy.allow_file_write:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.TOOL_ABUSE,
                        description="File write not allowed for this agent",
                        source="tool_policy_engine",
                        severity="high",
                        tool_name=tool_call.name,
                    )
                )
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                )

        # Check network access permission
        if tool_call.name in _NETWORK_TOOLS:
            if not policy.allow_network_access:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.TOOL_ABUSE,
                        description="Network access not allowed for this agent",
                        source="tool_policy_engine",
                        severity="high",
                        tool_name=tool_call.name,
                    )
                )
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                )

        # Check tool-specific policies
        tool_policy = policy.tool_policies.get(tool_call.name)
        if tool_policy:
            result = self._evaluate_tool_policy(tool_call, tool_policy, tenant_id, agent_id)
            if result.verdict == Verdict.BLOCK:
                return result

        # Sensitive path read check (global, regardless of policy)
        sensitive = self._check_sensitive_read(tool_call, tenant_id, agent_id)
        if sensitive:
            return sensitive

        # Self-protection: block modifications to gateway-critical files
        self_prot = self._check_self_protection(tool_call, tenant_id, agent_id)
        if self_prot:
            return self_prot

        # SSRF protection: detect private/internal IPs in any argument
        ssrf = self._check_ssrf(tool_call, tenant_id, agent_id)
        if ssrf:
            return ssrf

        return GuardrailResult(verdict=Verdict.ALLOW, events=events)

    def evaluate_tool_calls(
        self, tool_calls: list[ToolCall], tenant_id: str, agent_id: str
    ) -> GuardrailResult:
        """Evaluate a batch of tool calls."""
        all_events: list[SecurityEvent] = []
        blocked: list[str] = []

        for i, tc in enumerate(tool_calls):
            result = self.evaluate_tool_call(tc, tenant_id, agent_id, call_count=i)
            all_events.extend(result.events)
            blocked.extend(result.blocked_tools)
            if result.verdict == Verdict.BLOCK:
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=all_events, blocked_tools=blocked
                )

        return GuardrailResult(verdict=Verdict.ALLOW, events=all_events)

    def _evaluate_default(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str
    ) -> GuardrailResult:
        """Default policy when no explicit policy exists: DEFAULT-DENY.

        Only tools in _SAFE_TOOLS and _READ_TOOLS (with path checks) are allowed.
        Everything else is blocked.
        """
        # ALWAYS check sensitive file reads first
        sensitive = self._check_sensitive_read(tool_call, tenant_id, agent_id)
        if sensitive:
            return sensitive

        # ALWAYS check self-protection
        self_prot = self._check_self_protection(tool_call, tenant_id, agent_id)
        if self_prot:
            return self_prot

        # Safe tools are always allowed
        if tool_call.name in _SAFE_TOOLS:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Read tools allowed (path already checked above)
        if tool_call.name in _READ_TOOLS:
            return GuardrailResult(verdict=Verdict.ALLOW)

        # Everything else is BLOCKED by default (execution, write, network, unknown)
        if tool_call.name in _EXECUTION_TOOLS:
            category = ThreatCategory.TOOL_ABUSE
            desc = f"Execution tool '{tool_call.name}' blocked by default policy"
        elif tool_call.name in _WRITE_TOOLS:
            category = ThreatCategory.TOOL_ABUSE
            desc = f"Write tool '{tool_call.name}' blocked by default policy"
        elif tool_call.name in _NETWORK_TOOLS:
            category = ThreatCategory.TOOL_ABUSE
            desc = f"Network tool '{tool_call.name}' blocked by default policy"
        else:
            category = ThreatCategory.POLICY_VIOLATION
            desc = f"Unknown tool '{tool_call.name}' blocked by default-deny policy (no tenant policy configured)"

        event = SecurityEvent(
            tenant_id=tenant_id,
            agent_id=agent_id,
            verdict=Verdict.BLOCK,
            category=category,
            description=desc,
            source="tool_policy_engine",
            severity="high",
            tool_name=tool_call.name,
        )
        return GuardrailResult(
            verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name]
        )

    def _evaluate_tool_policy(
        self, tool_call: ToolCall, policy: ToolPolicy, tenant_id: str, agent_id: str
    ) -> GuardrailResult:
        """Evaluate tool-specific argument constraints."""
        events: list[SecurityEvent] = []

        # Check required arguments
        for req_arg in policy.required_arguments:
            if req_arg not in tool_call.arguments or not tool_call.arguments[req_arg]:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=f"Required argument '{req_arg}' missing for {tool_call.name}",
                        source="tool_policy_engine",
                        severity="medium",
                        tool_name=tool_call.name,
                    )
                )
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                )

        # Check denied argument values
        for arg_name, denied_values in policy.denied_arguments.items():
            arg_value = str(tool_call.arguments.get(arg_name, ""))
            # Normalize: NFKC, backslash→slash, strip null bytes
            arg_value_norm = unicodedata.normalize("NFKC", arg_value).replace("\\", "/").replace("\x00", "")
            for denied in denied_values:
                if denied.lower() in arg_value.lower() or denied.lower() in arg_value_norm.lower():
                    events.append(
                        SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.POLICY_VIOLATION,
                            description=f"Denied argument value '{denied}' in {arg_name}",
                            source="tool_policy_engine",
                            severity="high",
                            tool_name=tool_call.name,
                            matched_pattern=denied,
                        )
                    )
                    return GuardrailResult(
                        verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                    )

        # Check argument allowlist patterns
        for arg_name, pattern_str in policy.argument_patterns.items():
            arg_value = str(tool_call.arguments.get(arg_name, ""))
            # SECURITY FIX (H-03): Compile with timeout protection against ReDoS
            if len(pattern_str) > 500:
                import structlog
                structlog.get_logger().warning(
                    "argument_pattern_too_complex", pattern_length=len(pattern_str)
                )
                continue
            try:
                compiled = re.compile(pattern_str)
            except re.error:
                continue
            # Limit input length to prevent catastrophic backtracking
            match_result = compiled.match(arg_value) if len(arg_value) < 10000 else None
            if arg_value and not match_result:
                events.append(
                    SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.POLICY_VIOLATION,
                        description=f"Argument '{arg_name}' doesn't match allowed pattern",
                        source="tool_policy_engine",
                        severity="medium",
                        tool_name=tool_call.name,
                    )
                )
                return GuardrailResult(
                    verdict=Verdict.BLOCK, events=events, blocked_tools=[tool_call.name]
                )

        return GuardrailResult(verdict=Verdict.ALLOW, events=events)

    def _check_self_protection(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str
    ) -> GuardrailResult | None:
        """Block tool calls that attempt to modify gateway-critical files."""
        if tool_call.name not in _WRITE_TOOLS:
            return None

        # Extract ALL string values from arguments (flat + nested)
        path_values = self._extract_path_values(tool_call.arguments)
        for value in path_values:
            value_normalized = value.replace("\\", "/").lower()
            value_normalized = unicodedata.normalize("NFKC", value_normalized)
            for protected in _PROTECTED_PATHS:
                if protected.lower() in value_normalized:
                    event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.TOOL_ABUSE,
                        description=f"Self-protection: blocked modification to '{protected}' via {tool_call.name}",
                        source="tool_policy_engine.self_protection",
                        severity="critical",
                        tool_name=tool_call.name,
                        matched_pattern=protected,
                    )
                    return GuardrailResult(
                        verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name]
                    )
        return None

    def _check_sensitive_read(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str
    ) -> GuardrailResult | None:
        """Block read access to sensitive files (credentials, keys, configs).

        Applies to ALL read-capable tools regardless of policy configuration.
        Inspects ALL argument values (flat + nested JSON) for sensitive paths.
        """
        read_tools = _READ_TOOLS
        if tool_call.name not in read_tools:
            return None

        # Extract ALL string values from arguments (flat + nested)
        path_values = self._extract_path_values(tool_call.arguments)
        for value in path_values:
            value_normalized = value.replace("\\", "/")
            # Normalize Unicode dot leaders/confusables to ASCII
            value_normalized = unicodedata.normalize("NFKC", value_normalized)
            value_normalized = value_normalized.replace("\u2024", ".").replace("\uff0e", ".")
            # Strip glob wildcards — expand * to match any suffix
            # For "/etc/shado*" we want to check "/etc/shadow" etc.
            # Strategy: if contains glob, also check without trailing partial + wildcard
            value_deglobbed = value_normalized.replace("*", "").replace("?", "")
            # Also try expanding glob by treating * as regex .*
            import re as _re
            value_glob_regex = None
            if "*" in value_normalized or "?" in value_normalized:
                glob_re = value_normalized.replace(".", r"\.").replace("*", ".*").replace("?", ".")
                value_glob_regex = glob_re
            # Double URL decode
            value_urldecoded = value_normalized
            if "%" in value_urldecoded:
                import urllib.parse
                try:
                    value_urldecoded = urllib.parse.unquote(urllib.parse.unquote(value_urldecoded))
                except Exception:
                    pass
            # Cyrillic confusable normalization (comprehensive)
            _confusable_map = str.maketrans(
                "еаосрхуЕАОСРХУіІңНтТмМкКвВзЗнь",
                "eaocpxyEAOCPXYiInHtTmMkKvVzZn'",
            )
            value_deconfused = value_normalized.translate(_confusable_map)

            # Check all normalized variants against patterns
            for check_value in {value_normalized, value_deglobbed, value_urldecoded, value_deconfused}:
                for pattern in _SENSITIVE_READ_PATTERNS:
                    if pattern.search(check_value):
                        event = SecurityEvent(
                            tenant_id=tenant_id,
                            agent_id=agent_id,
                            verdict=Verdict.BLOCK,
                            category=ThreatCategory.CREDENTIAL_ACCESS,
                            description=f"Sensitive file read blocked: '{value}' via {tool_call.name}",
                            source="tool_policy_engine.sensitive_read",
                            severity="critical",
                            tool_name=tool_call.name,
                            matched_pattern=pattern.pattern,
                        )
                        return GuardrailResult(
                            verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name]
                        )
            # Glob regex matching: check if the glob pattern could match any sensitive path
            if value_glob_regex:
                import re as _re2
                try:
                    glob_compiled = _re2.compile(value_glob_regex, _re2.IGNORECASE)
                    # Test against known sensitive file paths
                    _SENSITIVE_PATHS = [
                        "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/hosts",
                        ".env", ".env.local", ".env.production",
                        ".aws/credentials", ".ssh/id_rsa", ".ssh/id_ed25519",
                        "credentials.json", "secrets.json", ".git-credentials",
                        ".netrc", ".pgpass", "kubeconfig", ".kube/config",
                    ]
                    for sp in _SENSITIVE_PATHS:
                        if glob_compiled.search(sp):
                            event = SecurityEvent(
                                tenant_id=tenant_id,
                                agent_id=agent_id,
                                verdict=Verdict.BLOCK,
                                category=ThreatCategory.CREDENTIAL_ACCESS,
                                description=f"Glob pattern matches sensitive file: '{value}' → {sp}",
                                source="tool_policy_engine.sensitive_read",
                                severity="critical",
                                tool_name=tool_call.name,
                                matched_pattern=f"glob:{value}",
                            )
                            return GuardrailResult(
                                verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name]
                            )
                except _re2.error:
                    pass
        return None

    @staticmethod
    def _extract_path_values(arguments: dict, max_depth: int = 4) -> list[str]:
        """Recursively extract all string values from arguments dict.

        This ensures sensitive path checks cover ALL argument names
        (source, input, location, resource, nested JSON, etc.)
        not just the predefined path_args list.
        """
        values: list[str] = []

        def _recurse(obj, depth: int = 0):
            if depth > max_depth:
                return
            if isinstance(obj, str):
                if len(obj) > 2:  # Skip trivially short values
                    values.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    _recurse(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    _recurse(item, depth + 1)

        _recurse(arguments)
        return values

    # Compiled SSRF patterns for private/internal network detection
    _SSRF_PATTERNS = [
        re.compile(r"https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
        re.compile(r"https?://172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}", re.I),
        re.compile(r"https?://192\.168\.\d{1,3}\.\d{1,3}", re.I),
        re.compile(r"https?://127\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.I),
        re.compile(r"https?://0\.0\.0\.0", re.I),
        re.compile(r"https?://localhost", re.I),
        re.compile(r"https?://\[?::1\]?", re.I),  # IPv6 loopback
        re.compile(r"https?://\[?fd[0-9a-f]{2}:", re.I),  # IPv6 private
        re.compile(r"https?://\[?fe80:", re.I),  # IPv6 link-local
        re.compile(r"https?://169\.254\.\d{1,3}\.\d{1,3}", re.I),  # link-local/metadata
        re.compile(r"https?://metadata\.google\.internal", re.I),
        re.compile(r"https?://100\.100\.100\.200", re.I),  # Alibaba metadata
        re.compile(r"https?://\d{8,10}(/|$|\?)", re.I),  # Decimal IP (e.g., 2130706433 = 127.0.0.1)
        re.compile(r"https?://0x[0-9a-f]{8}", re.I),  # Hex IP
        re.compile(r"https?://0[0-7]{1,3}\.0*[0-7]{1,3}\.0*[0-7]{1,3}\.0*[0-7]{1,3}", re.I),  # Octal IP (0177.0.0.1)
        re.compile(r"https?://[\w.-]*\.(nip\.io|xip\.io|sslip\.io|localtest\.me|lvh\.me|vcap\.me)", re.I),  # DNS rebinding services
        re.compile(r"https?://[\w.-]*127[\w.-]*\.(com|io|net|org)", re.I),  # DNS with 127 in hostname
    ]

    def _check_ssrf(
        self, tool_call: ToolCall, tenant_id: str, agent_id: str
    ) -> GuardrailResult | None:
        """Block SSRF attempts targeting private/internal networks."""
        from urllib.parse import unquote

        all_values = self._extract_path_values(tool_call.arguments)
        for value in all_values:
            value_norm = unicodedata.normalize("NFKC", value)
            # SECURITY FIX (H-10): URL-decode arguments before SSRF pattern matching
            # Prevents bypass via double-encoding (%31%32%37 → 127)
            decoded_value = unquote(unquote(value_norm))
            for pattern in self._SSRF_PATTERNS:
                if pattern.search(decoded_value):
                    event = SecurityEvent(
                        tenant_id=tenant_id,
                        agent_id=agent_id,
                        verdict=Verdict.BLOCK,
                        category=ThreatCategory.EXFILTRATION,
                        description=f"SSRF attempt: private/internal network target detected in '{tool_call.name}'",
                        source="tool_policy_engine.ssrf_protection",
                        severity="critical",
                        tool_name=tool_call.name,
                        matched_pattern=pattern.pattern,
                    )
                    return GuardrailResult(
                        verdict=Verdict.BLOCK, events=[event], blocked_tools=[tool_call.name]
                    )
        return None
