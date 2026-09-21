"""Recovery config tests never contact Docker or read actual credentials."""

import copy
import importlib.util
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_force_password_change():
    """No user database needed."""


@pytest.fixture
def runner():
    path = Path(__file__).parents[1] / "scripts/recover-local-admin.py"
    spec = importlib.util.spec_from_file_location("local_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def original():
    return {"Id": "a" * 64, "Config": {"Env": ["BULWARK_REDIS_URL=redis://old", "KEY_FILE=/run/secrets/key"],
            "User": "65532:65532", "Entrypoint": ["python3"], "Cmd": None, "Labels": {}},
            "HostConfig": {"ReadonlyRootfs": True, "Memory": 256 * 1024**2,
                           "PortBindings": {"8090/tcp": [{"HostPort": "8090"}]},
                           "RestartPolicy": {"Name": "unless-stopped"}},
            "Mounts": [{"Type": "bind", "Source": "/checkout/admin/routes", "Destination": "/app/admin/routes", "RW": False},
                       {"Type": "bind", "Source": "/checkout/src", "Destination": "/app/src", "RW": False},
                       {"Type": "bind", "Source": "/secrets/key", "Destination": "/run/secrets/key", "RW": False},
                       {"Type": "volume", "Name": "original-data", "Destination": "/app/data", "RW": True}],
            "NetworkSettings": {"Networks": {"app-net": {"Aliases": ["admin", "a" * 12]}}}}


def test_cloned_config_never_mounts_original_data_or_mixed_source(runner, original):
    before = copy.deepcopy(original)
    config = runner.coherent_config(original, clones={"original-data": "copy-data"})
    assert config["Image"] == runner.CANDIDATE
    mounts = config["HostConfig"]["Mounts"]
    assert mounts == [
        {"Type": "bind", "Source": "/secrets/key", "Target": "/run/secrets/key", "ReadOnly": True},
        {"Type": "volume", "Source": "copy-data", "Target": "/app/data", "ReadOnly": False},
    ]
    assert config["HostConfig"]["ReadonlyRootfs"]
    assert config["NetworkingConfig"]["EndpointsConfig"] == {"app-net": {"Aliases": ["admin"]}}
    assert before == original


def test_trial_has_no_network_or_exposed_ports(runner, original):
    config = runner.coherent_config(original, clones={"original-data": "copy-data"}, isolated=True)
    assert config["HostConfig"]["NetworkMode"] == "none"
    assert config["HostConfig"]["PortBindings"] == {}
    assert config["HostConfig"]["RestartPolicy"] == {"Name": "no"}
    assert "NetworkingConfig" not in config
    assert "BULWARK_REDIS_URL=" in config["Env"]
    assert "KEY_FILE=/run/secrets/key" in config["Env"]


def test_missing_clone_refuses_partial_mount_configuration(runner, original):
    with pytest.raises(KeyError):
        runner.coherent_config(original, clones={})
