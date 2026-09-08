"""Wazuh ECS rule structure and deployment readiness checks."""

import xml.etree.ElementTree as ET
from pathlib import Path


def test_wazuh_rules_match_ecs_not_suricata():
    # Repository-owned rule fixture, never uploaded or external XML.
    root = ET.fromstring(Path("docker/wazuh/bulwark-rules.xml").read_text())  # noqa: S314
    rules = {r.attrib["id"]: r for r in root.findall("rule")}
    assert rules["100100"].findtext("decoded_as") == "json"
    fields = {f.attrib["name"]: f.text for f in rules["100100"].findall("field")}
    assert fields["observer.type"] == "^bulwark-gateway$"
    assert fields["bulwark.verdict"] == "^(block|warn|redact|allow)$"
    assert rules["100110"].findtext("if_sid") == "100101"
    assert rules["100110"].find("field").attrib["name"] == "bulwark.threat_category"
    assert "86600" not in Path("docker/wazuh/bulwark-rules.xml").read_text()


def test_wazuh_chart_seeds_packaged_defaults_and_checks_daemons():
    chart = Path("helm/bulwark-gateway/templates/wazuh.yaml").read_text()
    assert "/var/ossec/data_tmp/permanent/var/ossec/etc/" in chart
    assert "chown -R 999:999 /mnt/wazuh-etc/lists" in chart
    readiness = chart.split("readinessProbe:", 1)[1].split("volumes:", 1)[0]
    assert "wazuh-analysisd" in readiness and "wazuh-logcollector" in readiness
    assert "tcpSocket" not in readiness
