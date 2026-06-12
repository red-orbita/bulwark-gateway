"""
Plugin CLI — Command-line interface for Sentinel plugin management.

Usage:
    sentinel plugin install <name> [--source hub|local]
    sentinel plugin uninstall <name>
    sentinel plugin list
    sentinel plugin create <name> [--output-dir <path>]
    sentinel plugin test <path>
    sentinel plugin enable <name>
    sentinel plugin disable <name>
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from src.plugins.manager import PluginManager
from src.plugins.spec import load_plugin_spec, validate_plugin_spec

logger = logging.getLogger(__name__)

# Default plugin directory
_DEFAULT_PLUGIN_DIR = Path("plugins")


def _get_manager(plugin_dir: Path | None = None) -> PluginManager:
    """Create a PluginManager with the given or default directory."""
    directory = plugin_dir or _DEFAULT_PLUGIN_DIR
    return PluginManager(plugin_dir=directory)


# --------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------


def _cmd_install(args: argparse.Namespace) -> int:
    """Handle 'install' command."""
    manager = _get_manager(args.plugin_dir)
    source = args.source or "hub"

    print(f"Installing plugin '{args.name}' from {source}...")
    success = manager.install(args.name, source=source)

    if success:
        print(f"  [OK] Plugin '{args.name}' installed successfully.")
        return 0
    else:
        print(f"  [FAIL] Failed to install plugin '{args.name}'.", file=sys.stderr)
        return 1


def _cmd_uninstall(args: argparse.Namespace) -> int:
    """Handle 'uninstall' command."""
    manager = _get_manager(args.plugin_dir)

    print(f"Uninstalling plugin '{args.name}'...")
    success = manager.uninstall(args.name)

    if success:
        print(f"  [OK] Plugin '{args.name}' uninstalled.")
        return 0
    else:
        print(f"  [FAIL] Plugin '{args.name}' not found.", file=sys.stderr)
        return 1


def _cmd_list(args: argparse.Namespace) -> int:
    """Handle 'list' command."""
    manager = _get_manager(args.plugin_dir)
    plugins = manager.list_installed()

    if not plugins:
        print("No plugins installed.")
        return 0

    print(f"{'Name':<30} {'Version':<12} {'Type':<18} {'Author':<20}")
    print("-" * 80)
    for plugin in plugins:
        state = manager._state.get(plugin.name, {})
        enabled = state.get("enabled", True)
        status = "" if enabled else " (disabled)"
        print(
            f"{plugin.name:<30} {plugin.version:<12} "
            f"{plugin.type.value:<18} {plugin.author:<20}{status}"
        )

    print(f"\n{len(plugins)} plugin(s) installed.")
    return 0


def _cmd_create(args: argparse.Namespace) -> int:
    """Handle 'create' command — scaffold a new plugin."""
    manager = _get_manager(args.plugin_dir)
    output_dir = Path(args.output_dir) if args.output_dir else Path.cwd()

    print(f"Creating plugin scaffold '{args.name}' in {output_dir}...")
    plugin_path = manager.scaffold(args.name, output_dir=output_dir)

    print(f"  [OK] Plugin scaffold created at: {plugin_path}")
    print()
    print("  Created files:")
    print(f"    {plugin_path}/sentinel-plugin.yaml  (plugin spec)")
    print(f"    {plugin_path}/scanner.py            (scanner implementation)")
    print(f"    {plugin_path}/tests/test_scanner.py (test template)")
    print(f"    {plugin_path}/README.md             (documentation)")
    print()
    print("  Next steps:")
    print(f"    1. Edit {plugin_path}/scanner.py with your detection logic")
    print(f"    2. Run tests: cd {plugin_path} && pytest tests/ -v")
    print(f"    3. Install: sentinel plugin install {plugin_path} --source local")
    return 0


def _cmd_test(args: argparse.Namespace) -> int:
    """Handle 'test' command — validate and security-check a plugin."""
    plugin_path = Path(args.path)

    if not plugin_path.is_dir():
        print(f"  [FAIL] Not a directory: {plugin_path}", file=sys.stderr)
        return 1

    spec_file = plugin_path / "sentinel-plugin.yaml"
    if not spec_file.exists():
        print(f"  [FAIL] No sentinel-plugin.yaml found in {plugin_path}", file=sys.stderr)
        return 1

    # Load and validate spec
    print(f"Testing plugin at: {plugin_path}")
    print()

    try:
        spec = load_plugin_spec(spec_file)
    except Exception as e:
        print(f"  [FAIL] Failed to load spec: {e}", file=sys.stderr)
        return 1

    print(f"  Name:    {spec.name}")
    print(f"  Version: {spec.version}")
    print(f"  Type:    {spec.type.value}")
    print(f"  Author:  {spec.author}")
    print()

    # Validate spec
    errors = validate_plugin_spec(spec)
    if errors:
        print("  Spec validation errors:")
        for err in errors:
            print(f"    - {err}")
        print()
    else:
        print("  [OK] Spec validation passed.")

    # Security check
    manager = _get_manager(args.plugin_dir)
    warnings = manager._security_check(plugin_path)
    if warnings:
        print()
        print("  Security warnings:")
        for w in warnings:
            print(f"    - {w}")
        print()
        print(f"  [WARN] {len(warnings)} security issue(s) found.")
        return 1
    else:
        print("  [OK] Security check passed.")

    # Check scanner.py exists
    scanner_file = plugin_path / "scanner.py"
    if not scanner_file.exists():
        print("  [WARN] No scanner.py found — plugin has no scanner implementation.")
    else:
        print("  [OK] scanner.py found.")

    print()
    print("  All checks passed." if not errors else "  Spec has validation issues.")
    return 1 if errors else 0


def _cmd_enable(args: argparse.Namespace) -> int:
    """Handle 'enable' command."""
    manager = _get_manager(args.plugin_dir)

    success = manager.enable(args.name)
    if success:
        print(f"  [OK] Plugin '{args.name}' enabled.")
        return 0
    else:
        print(f"  [FAIL] Plugin '{args.name}' not found.", file=sys.stderr)
        return 1


def _cmd_disable(args: argparse.Namespace) -> int:
    """Handle 'disable' command."""
    manager = _get_manager(args.plugin_dir)

    success = manager.disable(args.name)
    if success:
        print(f"  [OK] Plugin '{args.name}' disabled.")
        return 0
    else:
        print(f"  [FAIL] Plugin '{args.name}' not found.", file=sys.stderr)
        return 1


# --------------------------------------------------------------------------
# CLI entrypoint
# --------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint for plugin management.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code (0 = success, non-zero = error).
    """
    parser = argparse.ArgumentParser(
        prog="sentinel plugin",
        description="Sentinel Gateway Plugin Manager",
    )
    parser.add_argument(
        "--plugin-dir",
        type=Path,
        default=None,
        help=f"Plugin directory (default: {_DEFAULT_PLUGIN_DIR})",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # install
    install_parser = subparsers.add_parser("install", help="Install a plugin")
    install_parser.add_argument("name", help="Plugin name or path")
    install_parser.add_argument(
        "--source",
        choices=["hub", "local"],
        default="hub",
        help="Installation source (default: hub)",
    )

    # uninstall
    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall a plugin")
    uninstall_parser.add_argument("name", help="Plugin name")

    # list
    subparsers.add_parser("list", help="List installed plugins")

    # create
    create_parser = subparsers.add_parser("create", help="Create a new plugin scaffold")
    create_parser.add_argument("name", help="Plugin name (kebab-case)")
    create_parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory (default: current directory)",
    )

    # test
    test_parser = subparsers.add_parser("test", help="Validate and security-check a plugin")
    test_parser.add_argument("path", help="Path to plugin directory")

    # enable
    enable_parser = subparsers.add_parser("enable", help="Enable a disabled plugin")
    enable_parser.add_argument("name", help="Plugin name")

    # disable
    disable_parser = subparsers.add_parser("disable", help="Disable an enabled plugin")
    disable_parser.add_argument("name", help="Plugin name")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    commands = {
        "install": _cmd_install,
        "uninstall": _cmd_uninstall,
        "list": _cmd_list,
        "create": _cmd_create,
        "test": _cmd_test,
        "enable": _cmd_enable,
        "disable": _cmd_disable,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
