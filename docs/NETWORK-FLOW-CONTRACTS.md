# Network Flow Contracts And Redis Retention

These are chart configuration contracts, not proof of packet filtering on a
particular cluster. A compatible enforcing controller is required. Before an
upgrade, review existing claims, authentication keys and dependency traffic;
rendering a policy alone does not establish network isolation.

## Paired Allowed Flows

The chart now admits both ends of the following required communications under
default-deny. Pod selectors without a namespace selector are restricted to the
policy's namespace. Labels are operator-controlled; permission to create/relabel
pods in the application namespace is a trusted administrative capability.

| Source | Destination | Port | Scope |
| --- | --- | --- | --- |
| Ingress controller | Proxy | TCP 8080 | ingress-nginx namespace AND pod label |
| Admin | Proxy | TCP 8080 | Same namespace, selected roles |
| Prometheus | Proxy | TCP 8080 | Only when Prometheus is enabled |
| Helm test pods | Admin/proxy | TCP 8090/8080 | Same namespace, component=test |
| Admin | Bundled PostgreSQL | TCP 5432 on destination pod | DB pod selected by role and release instance |
| Admin | External PostgreSQL | Configured TCP port | Exact operator-supplied IPv4 /32 |
| Admin/proxy | Wazuh API | TCP 55000 | Exact SIEM namespace AND Wazuh pod label |
| Proxy | Wazuh log input | UDP 1514 | Exact SIEM namespace AND Wazuh pod label |
| Proxy | Configured IP backend | Configured TCP port | Exact backend.ip /32, no admin exception |
| Application/monitoring/test pods | DNS | UDP/TCP 53 | kube-system AND kube-dns pod label |

External admin PostgreSQL requires `admin.database.postgresql.egressCIDR` when
NetworkPolicy is enabled. Example: host `pg.internal.example`, egressCIDR
`10.20.30.40/32`, SSL mode `verify-full`. An IP-valued host must match the /32;
for DNS, the operator must keep the address current. NetworkPolicy does not verify
DNS identity or TLS certificates. IPv6/multi-address external DB policies are not
implemented by this minimal profile; do not broaden the rule to bypass validation.

For `backend.type=ip`, the chart derives a proxy-only /32 exception from validated
`backend.ip` and `backend.port`. This fixes the private headless endpoint path,
not arbitrary private DNS or in-cluster pod-backend access. Runtime SSRF and agent
egress authorization remain independent.

The bundled PostgreSQL service can expose a custom port, but its container port
remains 5432. The paired pod-level rule uses that actual destination port. This is
not TLS provisioning: bundled PostgreSQL TLS remains unimplemented and is rejected
unless the operator explicitly selects the development-only non-TLS mode.

Wazuh rules are emitted only when the chart's Wazuh component is enabled. External
collectors or dashboards require separate narrowly scoped rules for their actual
source, destination and port; they are not implicitly admitted by this chart.

## Security-State Retention

Redis in Compose and the chart's standalone/HA data configurations now uses
`maxmemory-policy noeviction`, instead of `allkeys-lru`. It stores revocations,
correlation/rate-limit state and counters, not just disposable cache. Memory
pressure must not silently discard revocation or risk keys.

This deliberately trades automatic eviction for write errors at the memory cap.
Reads may continue, while new counters, policies or revocations can fail to persist.
Operators need memory monitoring, TTL/capacity planning and explicit handling of
failed writes; `noeviction` is not a delivery or authorization guarantee. Existing
fallback semantics of individual components still apply. Sustained capacity/OOM
behavior on the final artifacts remains an acceptance test. Before changing an
existing Redis instance, check its actual use and schedule an operational window.
Preserve the selected persistent claim and verify backup/restore independently.
Use `redis.existingClaim` when a separately managed claim must remain authoritative;
do not let an upgrade silently select a new empty volume.

## Verification

`tests/test_network_policy_flows.py` renders the chart and checks positive and
negative namespace/role/port cases, external-IP bounds, feature gates and Redis
configuration. This verifies rendered intent, not actual packet filtering.

On an authorized isolated cluster, test ingress and egress separately: baseline,
deny-all, label-selected exception, removal of that label and restored baseline.
Require both allowed and denied paths, including new pods during controller
programming and controller restart. Review resource headroom, privileges and
rollback before installing or changing network infrastructure.

Exercise Redis memory exhaustion only on a disposable instance: verify existing
revocations remain, eviction counters do not increase, rejected writes are surfaced
correctly by the application and normal writes resume after recovery. Redis
retention alone does not prove that a new revocation was successfully persisted.
These contracts do not grant arbitrary outbound access for feeds or webhooks.
