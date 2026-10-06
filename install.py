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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", help="path to opencode.json")
    ap.add_argument("--entry", default=None, help="plugin array entry to add/remove")
    ap.add_argument("--dry-run", action="store_true", help="add with {dryRun: true} options")
    ap.add_argument("--remove", action="store_true", help="remove the plugin instead")
    args = ap.parse_args()

    config_path = Path(args.config).expanduser()
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

    def is_ours(p) -> bool:
        if isinstance(p, str):
            return MARKER in p
        if isinstance(p, list) and p and isinstance(p[0], str):
            return MARKER in p[0]
        return False

    already = any(is_ours(p) for p in plugins)

    if args.remove:
        if not already:
            print(f"not installed in {config_path}")
            return 0
        data["plugin"] = [p for p in plugins if not is_ours(p)]
        action = "removed"
    else:
        if already:
            print(f"already installed in {config_path} (no change)")
            return 0
        plugins.append(entry)
        action = "installed"

    backup = config_path.with_suffix(config_path.suffix + f".bak-auto-jev-{time.strftime('%Y%m%dT%H%M%S')}")
    shutil.copy2(config_path, backup)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"{action} in {config_path}")
    print(f"backup: {backup}")
    if not args.remove and args.dry_run:
        print("dryRun: true — watch .opencode/auto-jev.log; re-run 'just install*' (no --dry-run) to go live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
