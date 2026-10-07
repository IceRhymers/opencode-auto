#!/usr/bin/env python3
"""Install the opencode-auto plugin into an opencode.json config's plugin array.

Idempotent: adds the plugin entry only if not already present. Preserves the
existing file's formatting (2-space indent) and key order. Backs up the file
first. Usage:

    install.py <config-path> [--entry <entry>] [--dry-run] [--remove]

<entry> defaults to file://<repo>/src/index.ts. --dry-run enables dryRun mode.
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
DEFAULT_ENTRY = f"file://{REPO}/src/index.ts"
MARKER = "opencode-auto/src/index.ts"


def is_ours(p) -> bool:
    if isinstance(p, str):
        return MARKER in p
    if isinstance(p, list) and p and isinstance(p[0], str):
        return MARKER in p[0]
    return False


def remove_from(config_path: Path) -> str:
    """Remove our plugin entry from one config. Returns a status string."""
    if not config_path.exists():
        return f"skip (missing): {config_path}"
    data = json.loads(config_path.read_text())
    plugins = data.get("plugin", [])
    if not isinstance(plugins, list) or not any(is_ours(p) for p in plugins):
        return f"not installed: {config_path}"
    data["plugin"] = [p for p in plugins if not is_ours(p)]
    backup = config_path.with_suffix(config_path.suffix + f".bak-auto-jev-{time.strftime('%Y%m%dT%H%M%S')}")
    shutil.copy2(config_path, backup)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    return f"removed: {config_path} (backup: {backup.name})"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", help="path to opencode.json")
    ap.add_argument("--entry", default=None, help="plugin array entry to add/remove")
    ap.add_argument("--dry-run", action="store_true", help="add with {dryRun: true} options")
    ap.add_argument("--remove", action="store_true", help="remove the plugin instead")
    ap.add_argument(
        "--project-config",
        default=str(REPO / ".opencode" / "opencode.json"),
        help="project-local config to also clean on --remove (default: this repo's .opencode/opencode.json)",
    )
    args = ap.parse_args()

    config_path = Path(args.config).expanduser()

    if args.remove:
        # Clean the named config AND the project-local one: the project
        # registration is what keeps loading the plugin in this repo after a
        # global uninstall (the "still loading after restart" footgun).
        print(remove_from(config_path))
        proj = Path(args.project_config).expanduser()
        if proj.resolve() != config_path.resolve():
            print(remove_from(proj))
        return 0

    if not config_path.exists():
        print(f"error: config not found: {config_path}", file=sys.stderr)
        return 1

    entry = args.entry
    if entry is None:
        entry = ["file://" + str(REPO / "src" / "index.ts"), {"dryRun": True}] if args.dry_run else DEFAULT_ENTRY

    data = json.loads(config_path.read_text())
    plugins = data.setdefault("plugin", [])
    if not isinstance(plugins, list):
        print("error: 'plugin' is not an array", file=sys.stderr)
        return 1

    already = any(is_ours(p) for p in plugins)
    if already:
        print(f"already installed in {config_path} (no change)")
        return 0
    plugins.append(entry)

    backup = config_path.with_suffix(config_path.suffix + f".bak-auto-jev-{time.strftime('%Y%m%dT%H%M%S')}")
    shutil.copy2(config_path, backup)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"installed in {config_path}")
    print(f"backup: {backup}")
    if args.dry_run:
        print("dryRun: true — watch .opencode/auto-jev.log; re-run 'just install*' (no --dry-run) to go live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
