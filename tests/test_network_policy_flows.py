"""Render-level permitted/denied flow contracts; not a CNI enforcement test."""

from pathlib import Path

import pytest
import yaml

from tests.test_helm_outbox import render


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """Network rendering does not need an admin database."""


def selector_matches(selector, labels):
    assert set(selector) <= {"matchLabels"}
    return all(labels.get(key) == value for key, value in selector.get("matchLabels", {}).items())


def permits(policy, direction, peer_ns, labels, port, protocol="TCP"):
    local_ns = policy["metadata"]["namespace"]
    for rule in policy["spec"].get(direction, []):
        if {"port": port, "protocol": protocol} not in rule.get("ports", []):
            continue
        for peer in rule.get("from" if direction == "ingress" else "to", []):
            if "ipBlock" in peer:
                continue
            if "namespaceSelector" in peer:
                if not selector_matches(peer["namespaceSelector"], {"kubernetes.io/metadata.name": peer_ns}):
                    continue
            elif peer_ns != local_ns:
                continue
            if "podSelector" in peer and not selector_matches(peer["podSelector"], labels):
                continue
            return True
    return False


def role(name):
    return {"app.kubernetes.io/name": name}


@pytest.fixture
def docs():
    return render({"backend": {"type": "none"}, "secrets": {"create": False},
                   "namespace": {"name": "isolated-gateway"},
                   "monitoring": {"prometheus": {"enabled": True}},
                   "wazuh": {"enabled": True, "namespace": "isolated-siem"}})


def test_admin_proxy_flow_has_both_sides_without_cross_namespace_access(docs):
    proxy = docs["NetworkPolicy", "proxy-access"]
    admin = docs["NetworkPolicy", "admin-access"]
    assert permits(proxy, "ingress", "isolated-gateway", role("admin"), 8080)
    assert permits(admin, "egress", "isolated-gateway", role("proxy"), 8080)
    assert not permits(proxy, "ingress", "foreign", role("admin"), 8080)
    assert not permits(proxy, "ingress", "isolated-gateway", role("random"), 8080)
    assert not permits(admin, "egress", "isolated-gateway", role("proxy"), 22)


def test_scraper_ingress_follows_feature_switch(docs):
    assert permits(docs["NetworkPolicy", "proxy-access"], "ingress", "isolated-gateway", role("prometheus"), 8080)
    disabled = render({"backend": {"type": "none"}, "secrets": {"create": False},
                       "monitoring": {"prometheus": {"enabled": False}}})
    assert not permits(disabled["NetworkPolicy", "proxy-access"], "ingress", "bulwark-gateway", role("prometheus"), 8080)


def test_ingress_controller_requires_both_namespace_and_pod(docs):
    proxy = docs["NetworkPolicy", "proxy-access"]
    assert permits(proxy, "ingress", "ingress-nginx", role("ingress-nginx"), 8080)
    assert not permits(proxy, "ingress", "ingress-nginx", role("untrusted"), 8080)
    assert not permits(proxy, "ingress", "foreign", role("ingress-nginx"), 8080)


def test_wazuh_namespace_and_role_are_conjunctive(docs):
    ingress = docs["NetworkPolicy", "allow-proxy-to-wazuh"]
    for name in ("proxy", "admin"):
        egress = docs["NetworkPolicy", name + "-access"]
        assert permits(egress, "egress", "isolated-siem", role("wazuh"), 55000)
        assert permits(ingress, "ingress", "isolated-gateway", role(name), 55000)
        assert not permits(egress, "egress", "foreign", role("wazuh"), 55000)
        assert not permits(egress, "egress", "isolated-siem", role("untrusted"), 55000)
        assert not permits(ingress, "ingress", "foreign", role(name), 55000)
    assert permits(docs["NetworkPolicy", "proxy-access"], "egress", "isolated-siem", role("wazuh"), 1514, "UDP")
    assert not permits(ingress, "ingress", "isolated-gateway", role("admin"), 1514, "UDP")


def test_disabled_wazuh_does_not_grant_admin_or_proxy_access():
    docs = render({"backend": {"type": "none"}, "secrets": {"create": False}, "wazuh": {"enabled": False}})
    for name in ("admin", "proxy"):
        assert not permits(docs["NetworkPolicy", name + "-access"], "egress", "bulwark-siem", role("wazuh"), 55000)


def test_helm_test_peers_have_ingress_and_egress(docs):
    peer = {"app.kubernetes.io/component": "test"}
    for name, port in (("proxy", 8080), ("admin", 8090)):
        assert permits(docs["NetworkPolicy", name + "-access"], "ingress", "isolated-gateway", peer, port)
        assert permits(docs["NetworkPolicy", "test-hook-access"], "egress", "isolated-gateway", role(name), port)
        assert not permits(docs["NetworkPolicy", name + "-access"], "ingress", "foreign", peer, port)


def test_internal_postgres_ingress_only_when_bundled():
    values = {"backend": {"type": "none"}, "secrets": {"create": False},
              "admin": {"database": {"type": "postgresql", "postgresql": {"sslMode": "disable"}}}}
    docs = render(values)
    policy = docs["NetworkPolicy", "admin-postgresql-ingress"]
    assert permits(policy, "ingress", "bulwark-gateway", role("admin"), 5432)
    assert not permits(policy, "ingress", "bulwark-gateway", role("proxy"), 5432)
    assert not permits(policy, "ingress", "foreign", role("admin"), 5432)
    assert policy["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/instance"] == "outbox-test"
    values["admin"]["database"]["postgresql"].update(internal=False, host="pg.example.test", egressCIDR="10.20.30.40/32")
    assert ("NetworkPolicy", "admin-postgresql-ingress") not in render(values)


def test_security_redis_never_uses_automatic_eviction(docs):
    assert "maxmemory-policy noeviction" in docs["ConfigMap", "redis-config"]["data"]["redis.conf"]
    root = Path(__file__).parents[1]
    compose = yaml.safe_load((root / "docker-compose.yml").read_text())
    assert "--maxmemory-policy noeviction" in compose["services"]["redis"]["command"]
    assert "allkeys-lru" not in (root / "helm/bulwark-gateway/templates/redis.yaml").read_text()


@pytest.mark.parametrize("cidr", ["", "0.0.0.0/0", "10.20.30.0/24", "999.1.1.1/32", "010.1.1.1/32"])
def test_external_admin_postgres_rejects_missing_or_broad_network(cidr):
    values = {"backend": {"type": "none"}, "secrets": {"create": False},
              "admin": {"database": {"type": "postgresql", "postgresql": {
                  "internal": False, "host": "pg.example.test", "sslMode": "verify-full", "egressCIDR": cidr,
              }}}}
    render(values, error="external admin PostgreSQL")


def test_external_admin_postgres_uses_only_configured_endpoint():
    values = {"backend": {"type": "none"}, "secrets": {"create": False},
              "admin": {"database": {"type": "postgresql", "postgresql": {
                  "internal": False, "host": "10.20.30.40", "sslMode": "verify-full", "egressCIDR": "10.20.30.40/32",
              }}}}
    docs = render(values)
    rules = docs["NetworkPolicy", "admin-access"]["spec"]["egress"]
    database = [rule for rule in rules if rule["ports"] == [{"port": 5432, "protocol": "TCP"}]]
    assert database == [{"to": [{"ipBlock": {"cidr": "10.20.30.40/32"}}],
                         "ports": [{"port": 5432, "protocol": "TCP"}]}]
    values["admin"]["database"]["postgresql"]["host"] = "10.20.30.41"
    render(values, error="IP host must match egressCIDR")


def test_dns_is_limited_to_coredns_on_both_protocols(docs):
    for name in ("proxy-access", "admin-access", "prometheus-access", "test-hook-access"):
        policy = docs["NetworkPolicy", name]
        for protocol in ("TCP", "UDP"):
            assert permits(policy, "egress", "kube-system", {"k8s-app": "kube-dns"}, 53, protocol)
            assert not permits(policy, "egress", "kube-system", {"k8s-app": "untrusted"}, 53, protocol)
            assert not permits(policy, "egress", "foreign", {"k8s-app": "kube-dns"}, 53, protocol)


def test_private_backend_endpoint_has_exact_proxy_only_network_exception():
    docs = render({"backend": {"type": "ip", "ip": "192.168.49.1", "port": 11434},
                   "secrets": {"create": False}})
    expected = {"to": [{"ipBlock": {"cidr": "192.168.49.1/32"}}],
                "ports": [{"port": 11434, "protocol": "TCP"}]}
    assert expected in docs["NetworkPolicy", "proxy-access"]["spec"]["egress"]
    assert expected not in docs["NetworkPolicy", "admin-access"]["spec"]["egress"]


@pytest.mark.parametrize("ip,port", [("192.168.0.1/24", 11434), ("300.1.1.1", 11434),
                                   ("192.168.001.1", 11434), ("192.168.49.1", 0),
                                   ("192.168.49.1", 65536), ("192.168.49.1", "11434")])
def test_private_backend_rejects_ambiguous_ip_or_port(ip, port):
    render({"backend": {"type": "ip", "ip": ip, "port": port}, "secrets": {"create": False}}, error="backend.")
