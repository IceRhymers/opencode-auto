# opencode-auto — install into opencode configs
#
#   just install            # normal opencode (~/.config/opencode), live
#   just install-ug         # ug setup (~/.ucode/opencode-xdg/opencode), live
#   just install-ug --profile fevm-west   # install with backend options
#   just install-dry        # normal, dry-run mode (log only, no action)
#   just install-ug-dry     # ug, dry-run mode
#   just uninstall          # remove from normal (+ this repo's project config)
#   just uninstall-ug       # remove from ug (+ this repo's project config)
#   just uninstall-project  # remove from this repo's .opencode/opencode.json only
#   just status             # show install state in all three configs
#   just whoami [--profile X|--provider P|--url U]  # show+probe the backend
#   just test / just eval / just eval-sweep / just replay

NORMAL_CONFIG := env_var('HOME') / ".config/opencode/opencode.json"
UG_CONFIG := env_var('HOME') / ".ucode/opencode-xdg/opencode/opencode.json"
PROJECT_CONFIG := justfile_directory() / ".opencode/opencode.json"

default:
    @just --list

# --- install (live) ---
# extra args pass through to install.py, e.g.:
#   just install --profile fevm-west
#   just install-ug --provider systemone        (uses TYPESAFE_API_KEY)
install *ARGS:
    python3 install.py "{{NORMAL_CONFIG}}" {{ARGS}}

install-ug *ARGS:
    python3 install.py "{{UG_CONFIG}}" {{ARGS}}

# --- install (dry-run: log decisions, don't act) ---
install-dry *ARGS:
    python3 install.py "{{NORMAL_CONFIG}}" --dry-run {{ARGS}}

install-ug-dry *ARGS:
    python3 install.py "{{UG_CONFIG}}" --dry-run {{ARGS}}

# print the resolved backend (provider/url/model/auth) + probe it
whoami *ARGS:
    bun run src/whoami.ts {{ARGS}}

# --- uninstall ---
# uninstall also cleans the project config so the plugin stops loading in this
# repo (the project registration is what survived a plain global uninstall).
uninstall:
    python3 install.py "{{NORMAL_CONFIG}}" --remove

uninstall-ug:
    python3 install.py "{{UG_CONFIG}}" --remove

# remove only from this repo's project config (dogfooding off, globals kept)
uninstall-project:
    python3 install.py "{{PROJECT_CONFIG}}" --remove --project-config "{{PROJECT_CONFIG}}"

# --- status ---
status:
    @echo "normal ({{NORMAL_CONFIG}}):"; \
      grep -q "opencode-auto" "{{NORMAL_CONFIG}}" && echo "  installed" || echo "  not installed"
    @echo "ug ({{UG_CONFIG}}):"; \
      grep -q "opencode-auto" "{{UG_CONFIG}}" && echo "  installed" || echo "  not installed"
    @echo "project ({{PROJECT_CONFIG}}):"; \
      grep -q "opencode-auto" "{{PROJECT_CONFIG}}" && echo "  installed" || echo "  not installed"

# --- dev ---
test:
    bun test

typecheck:
    bun x tsc --noEmit -p .

eval:
    bun run eval/run.ts

eval-sweep:
    bun run eval/sweep.ts

# replay the audit log through the current rules (before/after diff)
replay:
    bun run eval/replay.ts
