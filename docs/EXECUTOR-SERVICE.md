# P10: Separate Executor Service

## Delivered Boundary

`src.executor.app.create_app` builds a standalone FastAPI ASGI application with
one endpoint: `POST /execute`. It does not mount into the proxy, start the admin,
load models, discover plugins, import agent-named modules, or register tools by
default. Calling the factory without explicit configuration raises `ValueError`,
even with `BULWARK_DEBUG=true`. Importing the package starts no app or connections.

Operator code injects `ExecutorSettings`, a registry of `RegisteredTool`, strict
`AgentPolicy` objects, an allowlist of `(tenant_id, agent_id, subject)` principals,
and a `ReplayStore`. Only exact lowercase ASCII registry names dispatch. A signed
token does not authorize arbitrary Python calls, commands, URLs or modules.
There are no shell tools, `eval`, dynamic imports, retries, or batch execution.

Authorization is the intersection of authenticated principal, registered tool,
explicit policy allowlist, `ToolPolicyEngine`, closed strict Pydantic argument
model, argument DLP, and an unused signed action. Missing policies never reach
the policy engine's legacy safe-tool fallback. Policy snapshots are detached
from caller mutations. The shared output filter runs with email/phone protection
enabled. Any finding (including WARN or REDACT) withholds the entire output;
encoded secrets are not assumed safely redactable. Argument findings block
before the handler. No event payloads, matched secrets, exception text or
validation input values are returned.

## Wire Contract

```json
{
  "request_id": "action-unique-for-business-operation",
  "tool": "lookup",
  "arguments": {"item": "public-item"}
}
```

The request must have `Content-Type: application/json` and exactly one
`Authorization: Bearer <action-token>`. Compressed bodies are rejected. Identity,
credentials, handler names, headers and URLs are not accepted as envelope fields.
`X-Tenant-ID` and `X-Agent-ID` do not influence identity. Cookies are not auth.

Tokens are issued by a **separate trusted corporate authorizer**, not by the
agent, with an Ed25519 private key. The executor receives only its PEM public key.
PyJWT verifies exactly `algorithms=["EdDSA"]`, with an Ed25519 key, and requires:

| Claim | Requirement |
| --- | --- |
| `iss`, `aud` | Exact operator-configured issuer and dedicated executor audience |
| `sub`, `tenant_id`, `agent_id` | Nonempty bounded ASCII identifiers; exact principal allowlist match |
| `iat`, `exp` | Strict integers, valid current time, positive lifetime <= configured maximum (300s ceiling) |
| `jti` | Unique single-use token ID, bounded ASCII identifier |
| `request_id` | Must equal the envelope action ID |
| `action_sha256` | Must match the exact tool and arguments |

Unknown claims are rejected. No `kid` URL lookup, key discovery, proxy API key,
shared default secret, or algorithm negotiation is supported. The authorizer
must authorize the actual business operation before signing, not blindly sign
agent requests. It must reuse the business action ID when an outcome is unknown;
minting a new action ID bypasses deduplication by design. A compromised authorized
issuer can authorize new actions. There is no revocation service integration in
this standalone slice; use short lifetimes and stop/rotate the executor key or
principal configuration for emergency revocation (restart required).

`action_digest(tool, arguments)` is available in `src.executor.app`. Its hash
input is ASCII JSON of `{"tool": tool, "arguments": arguments}` with sorted keys,
compact separators, `ensure_ascii=True`, `allow_nan=False`, hashed with SHA-256.
The body hash is checked before argument-model defaults are applied. Security
inspection recursively snapshots the actual declared model fields, including
nested models, defaults and validator-normalized values, without using serializers.
Only JSON-native scalar/container fields are supported. The model's JSON dump
must exactly match this snapshot: omitted/excluded fields, transforming field or
model serializers, and non-JSON types cause rejection before replay reservation.
Lossless serializers are permitted. Policy inspects the snapshot; the handler
receives the validated model whose fields were checked. Validators and handlers
remain trusted operator code, not a sandbox for computed properties or malicious
attribute access. Cross-language issuers must match Python JSON number/string encoding;
prefer bounded strings and integers rather than floating-point arguments.

Success is `200` with `request_id`, `status="completed"`, and public text `output`.
Errors are generic: 401 authentication, 403 authorization/DLP, 409 replay, 413
size, 415 media/encoding, 422 schema, 429 rate/concurrency, 502 output withheld,
503 unavailable/unknown execution outcome. Output withholding occurs **after**
invocation and does not roll back a business action. Clients must not automatically
retry on any error, timeout, disconnect or missing response. Ingress/service-mesh
retries and hedging must also be disabled. No SDK client is necessary; use the
existing HTTP client with TLS verification, finite timeouts, redirects disabled,
and transport retries disabled. Never send backend credentials in this request.

## Limits

| Limit | Default / ceiling |
| --- | --- |
| Calls | Exactly one tool per action token/request; zero batching |
| Body | 64 KiB, checked while reading, regardless of Content-Length |
| Arguments | 16 KiB, max depth 8 and 1024 nodes before and after schema validation |
| Output | Text only, 16 KiB; no objects/headers/streams |
| Active requests | 8, configurable 1-128; rejected rather than queued |
| Principal rate | 60 requests per fixed 60s window, configurable 1-10000 |
| Authenticated global rate | 600 requests per fixed 60s window, authorized principals only |
| Rejected admission rate | Separate 600 requests per fixed 60s window; then 429 for invalid requests |
| Body read deadline | 5s, configurable up to 30s |
| Handler deadline | 10s, configurable up to 60s |
| Replay deadline | 2s, configurable up to 10s |
| Tools / principals | 128 / 1024 |
| Replay retention | 24h, configurable 600s-7 days; longer than any valid token lifetime |

`max_tool_calls_per_request` and tool-specific call budgets must permit the one
invocation; there is no implicit multi-step agent run. New requests require new
signed actions and are subject to rate limits. Rate windows are fixed, not a
sliding-window or lifetime business quota; boundary bursts are possible. Counters
are bounded by the static principal allowlist and reset on process restart.
`unauthenticated_requests_per_minute` configures the independent rejected-admission
budget (1-100000). Invalid signatures, missing credentials, unknown principals and
unknown endpoints do not consume the authenticated global or principal budgets.
Exhausting the rejected-admission budget does not reject a subsequently valid
principal. Authentication must still run to distinguish valid callers: this limit
does not bound signature-verification CPU during a flood. Connection/CPU DoS
protection remains an ingress/OS responsibility. Authenticated requests still
consume execution quotas even if later argument/policy checks reject the action.

**Only one worker and one replica are supported**, including when Redis is used.
Settings reject other declared counts. They cannot discover an orchestrator that
secretly starts additional workers/replicas: the operator must enforce these
values in deployment. Redis deduplication is shared; rate/concurrency quotas are
not distributed. This is not an HA release.

## Replay Durability

`ReplayStore.reserve(token_key, action_key, ttl)` is injectable so no SQL tables
or admin database abstraction are added. It must confirm both reservations before
execution, propagate errors, and never evict unexpired records to admit work.

`RedisReplayStore` uses two `SET NX EX` operations against an operator-provided
`redis.asyncio` client, under the service's storage timeout. The first key binds
issuer+jti; the second binds issuer+tenant+agent+request_id, across subjects and
new tokens. Stored key suffixes are SHA-256 digests, values are just `reserved`:
no bodies, tokens, credentials or results are persisted.

Sequential SETs intentionally prefer losing an action over executing twice.
A crash after the first SET can burn a token without executing anything. A failed
second SET leaves the first reservation intact. A timeout with an ambiguous Redis
write never invokes the handler. A confirmed reservation is **never removed** on
handler error, timeout, cancellation, output suppression or disconnect. Duplicate
attempts get 409, not a cached result and not another invocation.

The constructor requires explicit `durability_confirmed=True`. This is an
operator attestation, **not an automatic guarantee**. The Redis deployment must
preserve acknowledged writes on restart, use no-eviction for live reservations,
and forbid failover or snapshot restore that loses reservations. Plain Redis
async replication/AOF every-second is insufficient for strict crash-loss claims.
If these properties cannot be ensured, inject a stronger reservation service or
do not enable external actions. Production accepts no memory fallback. A Redis
error blocks execution until the store recovers. Redis ACL, authentication, TLS,
finite connection/socket timeouts, connection lifecycle and retry configuration
belong to the operator's existing approved client helper.

`MemoryReplayStore` is bounded (10000 records default) and accepted only when
`development=True` is explicitly configured. At capacity it fails closed instead
of evicting live records. It is for ASGI tests/local development only: restart
loses protection. No durability, multiworker or multireplica claims apply.

Deduplication lasts only for the retention window. It provides at-most-one
invocation **within that window and while the ledger preserves its records**,
not exactly-once effects, transactions or rollback. Persistently uncertain actions
require operator reconciliation with the destination before any replacement is
authorized. The server does not provide a result lookup/reconciliation endpoint.

## Operator Wiring

Reference: `config/examples/executor_operator.py`. It deliberately refuses startup
until the operator populates registry/policies/principals and confirms Redis
durability. Its standalone `get_redis_client` helper configures authenticated,
verified TLS, finite timeouts and zero retries, and can be replaced by the
operator's approved existing helper. It supplies no image, fake digest, default
credentials, real shell tools or deployment side effects. Its environment:

| Variable | Wiring |
| --- | --- |
| `BULWARK_EXECUTOR_PUBLIC_KEY_FILE` | Mounted Ed25519 public verification key PEM |
| `BULWARK_EXECUTOR_ISSUER` | Dedicated corporate action issuer |
| `BULWARK_EXECUTOR_AUDIENCE` | Dedicated executor audience |
| `BULWARK_EXECUTOR_REPLAY_DURABILITY_CONFIRMED` | Must be literal `true` after infrastructure review |
| `BULWARK_EXECUTOR_REDIS_HOST` | Fixed operator-selected Redis host |
| `BULWARK_EXECUTOR_REDIS_PORT` | TLS port, default 6380 |
| `BULWARK_EXECUTOR_REDIS_USERNAME` | Least-privilege Redis ACL user |
| `BULWARK_EXECUTOR_REDIS_PASSWORD_FILE` | Mounted nonempty Redis password |
| `BULWARK_EXECUTOR_REDIS_CA_FILE` | Mounted Redis CA bundle; hostname verification required |

All limits are configured via `ExecutorSettings`, not the proxy's global config.
Ed25519 verification requires the existing `cryptography` package (already pinned
in `requirements-admin.lock` and present in the validation venv). It is not in
the minimal proxy lock: that proxy-only image is **not** sufficient as-is. Use an
operator-approved existing image with this dependency provisioned. No dependency
files or images were changed or installed for this implementation.
After implementing/reviewing the operator factory, a separate uvicorn process
can use `python -m uvicorn config.examples.executor_operator:create_executor
--factory --workers 1 --host 0.0.0.0 --port 8091`. This command is documentation
only; no service was started during implementation. Use an operator-provided
existing approved image pinned to a real digest containing this code and the
static handler modules. Do not install or discover plugins at runtime.

Handlers receive only `(validated_arguments, ExecutionContext)` and return public
bounded text. Use strict Pydantic models with `extra="forbid"`, bounded fields,
closed nested models and no unconstrained arbitrary JSON or credential parameters.
Review custom validators/defaults as trusted operator code. Network and credential
clients are captured in server-side closures, never selected through agent data.
Use `RegisteredTool(..., protected_values=(SecretStr(actual_secret), ...))` for
exact-value input/output vetoes on opaque credentials that regex DLP cannot know.
Checks walk decoded keys and values, not escaped JSON substrings, and cover raw
input plus normalized/defaulted fields. Input strings and output text that contain
a complete JSON value are decoded recursively under depth/node/byte budgets;
duplicate object keys fail closed. The shared `OutputFilter` scans decoded values,
keys and synthetic `key=value` candidates, so a quoted JSON `password` field keeps
its credential-name context. Exhausted inspection budgets block/withhold, never
approve a partial scan. This only handles complete embedded JSON values, not JSON
fragments inside prose, arbitrary encodings or every possible credential name.
These values have no API/read endpoint and are excluded from repr. This is not
protection against a malicious handler encoding or splitting a secret; handlers
must never return credential material or raw backend response headers.

## Required Isolation

This is **not a Python sandbox**. Registry handlers execute trusted operator code
inside the executor process with that process's authority. A malicious handler,
compromised executor, or custom argument validator can bypass Python checks.
Cooperative async timeouts cannot terminate blocking code, undo remote side
effects, stop cancellation-suppressing code or control spawned background tasks.
Do not register blocking/untrusted handlers or handlers that create detached work.

Corporate deployment requires a distinct OS identity/container/pod from the agent,
no shared PID namespace, writable code, credential filesystem mounts, host paths,
Docker socket or Kubernetes API rights. Mount backend credentials only in the
executor. The signing private key stays only in the authorizer. Use non-root,
read-only root filesystem, dropped capabilities, no privilege escalation,
RuntimeDefault seccomp, restricted pod security, memory/CPU/PID limits and a
read-only reviewed registry. Apply default-deny ingress/egress: allow only the
authorised agent/authorizer path to the executor and precise executor destinations
and Redis; constrain DNS to cluster DNS. The agent must not reach backend APIs
directly, their credentials, the replay store, cloud metadata or secret stores.
TLS/mTLS at the network boundary, bounded ingress connections, and TCP probes
must be configured separately; this slice intentionally exposes no unauthenticated
health or introspection endpoint.

Generic tool-policy URL regex checks are not complete DNS-time SSRF protection.
Network handlers must use operator-fixed destinations, verify TLS, disable
redirects, validate/respect destination IP policy at connect time, set timeouts,
and never forward the caller's Authorization header. DLP is heuristic and cannot
promise to recognize arbitrary business secrets or covert channels. A destination
must itself enforce tenant ownership using the authenticated context, not an
agent-supplied tenant field. Handler-level resource authorization is still needed.

## Verification

Run from the repository root using the provisioned project environment:

```bash
python -m pytest tests/test_executor_service.py -q --tb=short -p no:cacheprovider
```

The test module overrides the repository's admin DB autouse fixture: tests use
ASGI transport, generated ephemeral signing keys, in-memory handlers and mocked
Redis calls only. They do not touch services, database abstraction, Docker,
models or external destinations. Real Redis crash/failover, TLS, OS/K8s isolation,
business handlers and deployment readiness require separate operator validation.

Coverage includes excluded fields/serializers, defaults/normalization, escaped
protected values, structured password DLP and admission-budget isolation. Retain
the results for the exact revision tested; this guide does not certify a release.
