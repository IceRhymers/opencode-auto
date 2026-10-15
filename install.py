#!/usr/bin/env python3
"""Install the opencode-auto plugin into an opencode.json config's plugin array.

Writes the V2 `plugins` object form ({"package", "options"}) when the config
already uses `plugins`; otherwise appends the V1 tuple form to `plugin` (V2
normalizes it on load). Both keys are never written at once — when both are
present V2 normalization can shadow entries. Removal scans both keys.

Idempotent: adds the plugin entry only if not already present. Preserves the
existing file's formatting (2-space indent) and key order. Backs up the file
first. Usage:

    install.py <config-path> [--entry <entry>] [--dry-run] [--remove]

<entry> defaults to file://<repo> (V2 loads plugin package directories, not
single files; package.json's "main" points at src/index.ts). --dry-run enables
dryRun mode.
"""
import argparse
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent
DEFAULT_ENTRY = f"file://{REPO}"
MARKER = "opencode-auto"


def is_ours(p) -> bool:
    if isinstance(p, str):
        return MARKER in p
    if isinstance(p, list) and p and isinstance(p[0], str):
        return MARKER in p[0]
    if isinstance(p, dict):
        return MARKER in str(p.get("package", ""))
    return False


def build_entry(key: str, path_str: str, options: dict):
    """Plugin array entry in the shape the config's key expects."""
    if key == "plugins":
        entry = {"package": path_str}
        if options:
            entry["options"] = options
        return entry
    return [path_str, options] if options else path_str


def remove_from(config_path: Path) -> str:
    """Remove our plugin entry from one config. Returns a status string."""
    if not config_path.exists():
        return f"skip (missing): {config_path}"
    data = json.loads(config_path.read_text())
    changed = False
    for key in ("plugin", "plugins"):
        plugins = data.get(key, [])
        if isinstance(plugins, list) and any(is_ours(p) for p in plugins):
            data[key] = [p for p in plugins if not is_ours(p)]
            changed = True
    if not changed:
        return f"not installed: {config_path}"
    backup = config_path.with_suffix(config_path.suffix + f".bak-auto-jev-{time.strftime('%Y%m%dT%H%M%S')}")
    shutil.copy2(config_path, backup)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    return f"removed: {config_path} (backup: {backup.name})"


def build_options(args) -> dict:
    """Plugin options from the CLI flags (only those explicitly set)."""
    opts = {}
    if args.dry_run:
        opts["dryRun"] = True
    for flag, key in [
        ("provider", "provider"),
        ("profile", "profile"),
        ("host", "host"),
        ("url", "url"),
        ("model", "model"),
        ("api_key_env", "apiKeyEnv"),
        ("run_profile", "runProfile"),
    ]:
        v = getattr(args, flag, None)
        if v is not None:
            opts[key] = v
    return opts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("config", help="path to opencode.json")
    ap.add_argument("--entry", default=None, help="plugin array entry to add/remove")
    ap.add_argument("--dry-run", action="store_true", help="add with {dryRun: true} options")
    ap.add_argument("--remove", action="store_true", help="remove the plugin instead")
    ap.add_argument("--provider", choices=["systemone", "databricks"], default=None)
    ap.add_argument("--profile", default=None, help="databricks CLI profile")
    ap.add_argument("--host", default=None, help="databricks workspace host")
    ap.add_argument("--url", default=None, help="full SystemOne-compatible endpoint URL (overrides host/path)")
    ap.add_argument("--model", default=None, help="classifier model name")
    ap.add_argument("--api-key-env", default=None, help="env var holding the TypeSafe API key (default TYPESAFE_API_KEY)")
    ap.add_argument("--run-profile", choices=["interactive", "unattended"], default=None)
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

    path_str = "file://" + str(REPO)
    options = build_options(args)

    data = json.loads(config_path.read_text())
    # Match the key the config already uses: V2 `plugins` (object entries) or
    # V1 `plugin` (string/tuple entries, normalized by V2 on load). Never
    # write both — V2 merges them and existing entries can be shadowed.
    key = "plugins" if "plugins" in data else "plugin"
    entry = args.entry if args.entry is not None else build_entry(key, path_str, options)
    plugins = data.setdefault(key, [])
    if not isinstance(plugins, list):
        print(f"error: '{key}' is not an array", file=sys.stderr)
        return 1

    backup = config_path.with_suffix(config_path.suffix + f".bak-auto-jev-{time.strftime('%Y%m%dT%H%M%S')}")

    # Replace in place when already installed so re-running updates options
    # (e.g. adding --profile to an existing bare install) instead of no-oping.
    for i, p in enumerate(plugins):
        if is_ours(p):
            if p == entry:
                print(f"already installed in {config_path} (no change)")
                return 0
            shutil.copy2(config_path, backup)
            plugins[i] = entry
            config_path.write_text(json.dumps(data, indent=2) + "\n")
            print(f"updated install in {config_path} (backup: {backup.name})")
            print(f"  entry: {json.dumps(entry)}")
            return 0

    plugins.append(entry)
    shutil.copy2(config_path, backup)
    config_path.write_text(json.dumps(data, indent=2) + "\n")
    print(f"installed in {config_path}")
    print(f"backup: {backup}")
    if options:
        print(f"options: {json.dumps(options)}")
    if args.dry_run:
        print("dryRun: true — watch .opencode/auto-jev.log; re-run 'just install*' (no --dry-run) to go live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
