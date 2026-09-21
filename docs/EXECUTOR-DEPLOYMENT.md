# P10 Executor Deployment

## Scope

This is opt-in deployment wiring for the standalone executor described in
[EXECUTOR-SERVICE.md](EXECUTOR-SERVICE.md), not a ready-to-run tool service or an HA
release. No operator image, business handler, authorizer, Redis instance, Secret,
TLS boundary or public ingress is provisioned by this wiring.

`helm/bulwark-gateway/templates/executor.yaml` reads `.Values.executor | default
dict`. With the key absent or `enabled: false`, it emits **no resources** and
requires no executor configuration. When enabled it emits exactly one Deployment,
one ClusterIP Service (8091), and one NetworkPolicy, even if the shared chart's
`networkPolicies.enabled` is false. It does not modify proxy wiring, shared
volumes/configuration, or shared network policies. The rest of the chart still
renders normally; the example is an independent values overlay, not a separate
executor-only chart.

## Operator Prerequisites

1. Supply an **actual approved image** as `executor.image=repository@sha256:digest`.
   Missing images, mutable tags and malformed digests fail Helm rendering. There
   is deliberately no default or fabricated deployment digest. Offline Helm can
   validate the reference format, not image existence, contents or provenance;
   verify these through your approved artifact process before deployment.
2. Bake `src.executor`, its existing dependencies (including `cryptography`,
   FastAPI, Pydantic, PyJWT, Redis and uvicorn), the operator factory and its
   statically imported handlers into that image. The minimal proxy image alone
   is insufficient. Use a shell-free, non-root runtime with `python3` available;
   no runtime package installation, dynamic tool discovery or writable code.
3. Set `factoryModule` to a dotted ASCII Python module name. Helm invokes the
   fixed attribute `create_executor` with uvicorn `--factory`; paths, colons,
   expressions and command arguments are rejected. This is trusted deployment
   configuration, **not** an import name supplied by an agent. Syntax validation
   cannot prove that the image's module is safe or even present.
4. Populate the reviewed factory's registry, strict policies and principal
   allowlist. The supplied `config/examples/executor_operator.py` remains empty
   and deliberately refuses startup **before file reads or client creation**.
   It is not made operational by toggling Helm flags. Implement a separate trusted
   corporate authorizer that checks resource/tenant ownership and business rights
   before signing the exact action. Network labels are not application identity.
5. Provision authenticated, hostname-verified TLS Redis with a dedicated ACL user
   limited to the reservation keyspace `bulwark:executor:*` and necessary client
   commands. Preserve acknowledged writes, prohibit eviction of live reservations
   and stale failover/restore. Plain asynchronous replication or AOF every-second
   is not a strict durability guarantee. Set `redis.durabilityConfirmed: true`
   only after review. Neither Helm nor this boolean verifies storage durability;
   runtime storage failures deny execution, with no memory fallback.
6. Establish the private TLS/mTLS boundary, CNI enforcement, peer-side policies,
   image admission/provenance controls, and restricted Pod Security admission
   outside this template. Only then attest `tls.confirmed: true` and choose
   `tls.boundary: serviceMesh` or `internalIngress`.

## Secret Contract

Provision four **distinct, dedicated existing Secrets** in the executor namespace.
The template creates none and projects only the selected key of each Secret as
`value`, read-only with mode `0440` and group 65532. Do not reuse an admin/proxy
Secret or place a signing private key in any selected entry. Secret names alone
cannot establish that their contents are safe; review both contents and RBAC.

| Values reference | Environment path | Purpose |
| --- | --- | --- |
| `secrets.publicKey` | `BULWARK_EXECUTOR_PUBLIC_KEY_FILE=/run/executor/publicKey/value` | Ed25519 public PEM only |
| `secrets.redisPassword` | `BULWARK_EXECUTOR_REDIS_PASSWORD_FILE=/run/executor/redisPassword/value` | Dedicated Redis password |
| `secrets.redisCA` | `BULWARK_EXECUTOR_REDIS_CA_FILE=/run/executor/redisCA/value` | Redis CA trust bundle |
| `secrets.toolCredential` | `BULWARK_EXECUTOR_TOOL_CREDENTIAL_FILE=/run/executor/toolCredential/value` | Dedicated backend credential |

`name` and `key` are required for every reference. Credential **values never go
into Helm values, ConfigMaps, environment variables, arguments or logs**. The
issuer, audience, Redis hostname, port and ACL username are non-secret settings.
There are no generic `extraEnv`, `envFrom`, volume, hostPath or socket escape
hatches in this template. Only the four Secret projections are mounted; no private
signing key, agent files, admin data, policy PVC or Kubernetes token is mounted.

The reference factory intentionally does not read/use the tool credential while
its registry is empty. Reviewed operator code must read it at initialization,
capture it in a fixed-destination client closure, and register
`RegisteredTool(..., protected_values=(SecretStr(actual_secret),))` for exact-value
DLP vetoes. Arguments must never select credentials, hosts, modules or arbitrary
headers. Credentials are available to trusted code in the executor process:
this deployment is **not a Python sandbox**. Rotate/restart the executor after
changing factory configuration, the verification key, or credentials read at boot.
The authorizer alone holds the signing private key; neither agent nor executor does.

## Runtime And Network

- One replica and one uvicorn worker are fixed. Overrides other than 1 and enabled
  autoscaling fail rendering; no executor HPA is created. `Recreate` avoids normal
  rolling-upgrade overlap, at the cost of downtime. No HA or distributed quota
  claim is made. Admission/RBAC must prevent manual scaling, competing releases,
  duplicate Deployments and forced deletion while a process may still run.
- UID/GID 65532, read-only root filesystem, all capabilities dropped,
  `allowPrivilegeEscalation: false`, `RuntimeDefault` seccomp, no host namespaces,
  no shared PID namespace, and `automountServiceAccountToken: false` are fixed.
  No ServiceAccount/RBAC grants or init/sidecar containers are created. Ensure the
  namespace's default identity has no ambient cloud/workload privileges; enforce
  PID limits with the cluster runtime/kubelet, not an unsupported Pod field.
- Requests are 100m CPU/128Mi memory; limits are 1 CPU/512Mi. All three probes are
  TCP-only: the executor intentionally has no unauthenticated health route. A
  listening socket is **not** proof of Redis durability, business handler readiness
  or a healthy event loop. Graceful shutdown has a 75s uvicorn deadline within a
  90s Pod grace period. Interrupted operations require reconciliation, not retries.
- The Service is ClusterIP only, with no Ingress, NodePort, LoadBalancer, hostPort
  or external IP. Uvicorn itself speaks internal HTTP. TLS 1.2+ / mTLS is explicitly
  expected from an **operator-managed service mesh or private internal ingress**.
  The attestation flag does not enable encryption. Do not expose 8091 publicly.
- Ingress allows only `network.authorizer.namespace` **AND** its nonempty
  `podLabels`, on TCP 8091. Direct agent/proxy access is not opened. With an internal
  ingress, those labels must select a dedicated private authorizer gateway, whose
  upstream authentication allows only the corporate authorizer. Do not select a
  shared general-purpose ingress controller. Mesh identity policies must likewise
  restrict callers to the authorizer. Provision TLS/identity integration outside
  this template; inspect any injected sidecars/credentials and resulting policies.
- Egress permits TCP/UDP 53 only to `kube-system` pods labeled `k8s-app=kube-dns`,
  and the configured Redis port only to the exact namespace/workload labels in
  `network.redis`. A hostname does not prove its resolved IP matches these pods;
  provision and verify that mapping. NodeLocal DNS or nonstandard mesh networking
  needs a separately reviewed integration, not a broad DNS exception.
- `network.toolDestinations` defaults to `[]`: no tool egress. Each entry requires
  an exact namespace, nonempty `podLabels` and one TCP port (normally 443).
  Namespace and pod selectors are combined in the **same peer**, never OR-ed.
  Raw rules, CIDRs and allow-any destinations are unsupported. External APIs must
  use a dedicated destination-restricted egress gateway selected by these labels,
  with its own explicit upstream policy. Do not use an open forwarding proxy.
- Authorizer egress and Redis/tool ingress allowances must be provided on those
  workloads by their owners. This template does not weaken their policies or use
  the chart's ordinary Redis as a presumed durable TLS ledger. It does not grant
  the agent access to Redis or tool destinations. Separately prevent agent bypass
  to tool APIs, credentials, cloud metadata and secret stores.

Kubernetes NetworkPolicies are **additive**: another policy selecting the executor
can widen access; this policy cannot subtract its grants. Enforcement depends on
the CNI, and standard policies have node/host-network caveats. They do **not**
constrain root on another host, cluster administrators, stolen credentials, or
tools invoked outside this path. Non-root execution here is not a global root
restriction. Protect namespace/workload labels, RBAC, node access and destination
credentials independently. DNS allowance also is not content-level exfiltration
protection. Review the complete policy union and actual packet paths before use.

Disable retries, hedging and request-body/header logging at every client, private
ingress and mesh hop. Use verified TLS, finite timeouts, bounded connections and
no redirects. An output veto or timeout does not undo a tool effect. Keep the same
business action ID for uncertain outcomes and reconcile at the destination before
authorizing replacement work. See the service contract for retention limits and
the difference between at-most-one invocation and exactly-once business effects.

## Offline Validation

`config/examples/executor-values.yaml` is safe/inert as shipped. Set the image to
your approved real digest, configure the four existing Secret references and exact
peer labels, implement the factory, then review both attestations before opt-in.
The following commands only render local manifests; they do not deploy anything:

```bash
# Disable unrelated backend/model requirements for offline review only.
helm template executor-review ./helm/bulwark-gateway \
  --set backend.type=none --set proxy.enrichment.enabled=false \
  -f config/examples/executor-values.yaml

# Only after supplying an operator-reviewed overlay with the real image/config:
helm template executor-review ./helm/bulwark-gateway \
  --set backend.type=none --set proxy.enrichment.enabled=false \
  -f config/examples/executor-values.yaml \
  -f /path/to/operator-reviewed-executor-values.yaml \
  --show-only templates/executor.yaml

PYTHONDONTWRITEBYTECODE=1 python \
  -m pytest tests/test_executor_deployment.py tests/test_executor_service.py \
  -q --tb=short -p no:cacheprovider
```

Deployment tests use local `helm template` if Helm is available, with a clearly
synthetic render-only image digest that is never pulled. Without Helm they report
render tests as skipped and still check static contracts and the refusing factory;
that is not equivalent to a successful render. They override the shared admin DB
fixture and use only local parsing/mocks, never infrastructure. Rendering and ASGI
tests cannot validate a real image, TLS handshakes, Redis crash durability,
NetworkPolicy enforcement or business authorization. Those remain explicit
operator acceptance gates; this work does not start a service or cluster.
