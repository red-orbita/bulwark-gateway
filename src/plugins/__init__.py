"""
Sentinel Plugins — Plugin Hub and Marketplace framework.

This package provides the plugin specification, lifecycle manager, and CLI
for installing, managing, and developing third-party scanner plugins.

Plugins extend Sentinel Gateway with custom detection logic without
modifying the core codebase. Each plugin is a self-contained directory
with a sentinel-plugin.yaml manifest and a scanner.py implementation.

Usage:
    from src.plugins import PluginSpec, PluginManager, PluginCLI

    # Manage plugins programmatically
    manager = PluginManager(plugin_dir=Path("plugins"))
    manager.install("./my-plugin", source="local")
    scanner = manager.get_scanner("my-plugin")

    # Run CLI
    from src.plugins.cli import main
    main(["install", "my-scanner", "--source", "local"])
"""

from src.plugins.cli import main as PluginCLI
from src.plugins.manager import PluginManager
from src.plugins.spec import PluginSpec

__all__ = [
    "PluginCLI",
    "PluginManager",
    "PluginSpec",
]
