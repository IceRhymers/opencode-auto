# opencode-auto — install into opencode configs
#
#   just install            # normal opencode (~/.config/opencode), live
#   just install-ug         # ug setup (~/.ucode/opencode-xdg/opencode), live
#   just install-dry        # normal, dry-run mode (log only, no action)
#   just install-ug-dry     # ug, dry-run mode
#   just uninstall          # remove from normal
#   just uninstall-ug       # remove from ug
#   just status             # show install state in both configs
#   just test / just eval / just eval-sweep

NORMAL_CONFIG := env_var('HOME') / ".config/opencode/opencode.json"
UG_CONFIG := env_var('HOME') / ".ucode/opencode-xdg/opencode/opencode.json"

default:
    @just --list

# --- install (live) ---
install:
    python3 install.py "{{NORMAL_CONFIG}}"

install-ug:
    python3 install.py "{{UG_CONFIG}}"

# --- install (dry-run: log decisions, don't act) ---
install-dry:
    python3 install.py "{{NORMAL_CONFIG}}" --dry-run

install-ug-dry:
    python3 install.py "{{UG_CONFIG}}" --dry-run

# --- uninstall ---
uninstall:
    python3 install.py "{{NORMAL_CONFIG}}" --remove

uninstall-ug:
    python3 install.py "{{UG_CONFIG}}" --remove

# --- status ---
status:
    @echo "normal ({{NORMAL_CONFIG}}):"; \
      grep -q "opencode-auto/src/index.ts" "{{NORMAL_CONFIG}}" && echo "  installed" || echo "  not installed"
    @echo "ug ({{UG_CONFIG}}):"; \
      grep -q "opencode-auto/src/index.ts" "{{UG_CONFIG}}" && echo "  installed" || echo "  not installed"

# --- dev ---
test:
    bun test

typecheck:
    bun x tsc --noEmit -p .

eval:
    bun run eval/run.ts

eval-sweep:
    bun run eval/sweep.ts
