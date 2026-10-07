# opencode-auto

Auto mode for [OpenCode](https://opencode.ai) powered by **TypeSafe SystemOne
(OpenJev)** served through a **Databricks AI Gateway**. It classifies each
permission request and decides — in code, not in a prompt — whether to
auto-approve, auto-block, or leave the normal approval prompt for you.

Two profiles:

- **`unattended`** (default): long sessions that should keep moving without a human,
  but stop at dangerous calls. Non-risky calls go through; clear-cut danger
  is **blocked with feedback** so the agent reads the reason and redirects to
  a safer approach; genuinely uncertain-but-risky calls **pause** the run at
  the prompt until you return.
- **`interactive`**: you are at the keyboard. Confident-safe calls
  are approved, confident-dangerous ones denied, everything else shows the
  normal prompt.

## How it works

```
tool call → OpenCode permission rules
   ├─ explicit allow/deny → unchanged (classifier never sees it)
   └─ "ask" → permission.asked event → this plugin
         1. static fast-path rules (hard-deny list, destructive-command
            detector, secret-read guard, read-only chain allow list)
         2. build state {tool, command, patterns, cwd, recent user messages}
         3. one SystemOne call, 5 questions in parallel:
              verdict (safe | needs_review | dangerous)
              irreversible (0-1)
              matches_intent (0-1)
              exfiltration (0-1)
              scope (workspace | home | system | network)
         4. profile policy → allow | block | pause | ask | deny
```

**Unattended decision tiers** (the risk signals gate, not intent):

- **block** if the call is clearly dangerous (dangerous verdict at ≥0.7
  confidence, or with corroborating risk), sends user data to an
  undesignated destination (exfiltration > 0.35), or is a system-wide
  package install the agent cannot undo. The rejection carries a message
  ("do not retry; redirect"), so the agent loop keeps going.
- **pause** if the call is plausibly risky but unclear: uncertain
  irreversibility, a dangerous/needs_review verdict without corroboration,
  anything touching paths outside the workspace, or a low-confidence
  "safe". The run stalls at the prompt until you approve or reject it.
- **allow** everything else: the whole point of unattended mode.
- A **circuit breaker** escalates block → pause when a session accumulates
  `maxConsecutiveBlocks` (2) blocked calls in a row or `maxBlocksPerSession`
  (4) total — the agent is insisting on something risky.

Failure modes are **fail-safe**: any classifier error, timeout, or missing
answer degrades to `pause` (unattended) / `ask` (interactive). It never
auto-allows on failure.

Only tool calls that would already ask for permission are classified. Your
explicit `allow`/`deny` rules in `opencode.json` always take priority and run
first. Commands that target the classifier itself (its source tree, install
config, audit log) are hard-denied statically.

### Headless `opencode run`

The plugin is built for the **TUI**, where the permission prompt waits for a
human and the classifier's sub-second reply lands first and drives the tool.
In headless `opencode run`, OpenCode rejects any unanswered permission after a
short watchdog (~100ms). Static fast-path decisions (~2ms) still win that race,
but model-path decisions (~450-550ms) do not — the call is auto-rejected and
the agent adapts. That's the safe behavior; just don't rely on model-path
auto-approvals in unattended runs.

## Install

A [Justfile](https://github.com/casey/just) manages installation into two
configs: normal OpenCode (`~/.config/opencode/opencode.json`) and the **ug**
setup (`~/.ucode/opencode-xdg/opencode/opencode.json`). It edits the `plugin`
array in place (preserving formatting/key order), backs up first, and is
idempotent.

```sh
just install-dry        # normal opencode, dry-run (log only — start here)
just install-ug-dry     # ug setup, dry-run
just install            # normal, live
just install-ug         # ug, live
just status             # show install state in both
just uninstall[-ug]     # remove
```

Dry-run mode logs every decision to `.opencode/auto-jev.log` without acting —
watch it, then re-run `just install[-ug]` (no `-dry`) to go live.

Authenticate once so the plugin can mint tokens:

```sh
databricks auth login --host https://fevm-tanner-wendland.cloud.databricks.com --profile fevm-west
```

### Manual install

If you prefer not to use `just`, add the plugin to the `plugin` array in
`opencode.json` yourself:

```json
{
  "plugin": ["file:///absolute/path/to/opencode-auto/src/index.ts"]
}
```

or with options (here: interactive profile with dry-run):

```json
{
  "plugin": [["file:///path/to/opencode-auto/src/index.ts", { "runProfile": "interactive", "dryRun": true }]]
}
```

## Configuration

Pass options via `[name, options]` in the `plugin` array, or via env vars
(env wins):

| Option | Env | Default | Description |
| - | - | - | - |
| `enabled` | `AUTO_JEV_ENABLED` | `true` | master switch |
| `dryRun` | `AUTO_JEV_DRY_RUN` | `false` | log decisions without acting |
| `runProfile` | `AUTO_JEV_PROFILE` | `unattended` | `interactive` / `unattended` |
| `mode` | | `allow-ask-deny` | `allow-ask-deny` / `allow-ask` / `allow-deny` |
| `host` | `DATABRICKS_HOST` | fevm-tanner-wendland | gateway host |
| `profile` | `DATABRICKS_CONFIG_PROFILE` | `fevm-west` | CLI profile |
| `model` | | `system.ai.openjev-qwen35-4b` | SystemOne model |
| `contextMessages` | | `3` | recent user messages used as goal |
| `timeoutMs` | | `3000` | SystemOne timeout |
| `maxConsecutiveBlocks` | | `2` | circuit breaker: blocks in a row before pausing |
| `maxBlocksPerSession` | | `4` | circuit breaker: total blocks before pausing |
| `escalate` | | `[bash, edit, webfetch, external_directory]` | permissions forced to `ask` so the classifier sees them |
| `thresholds.*` | | see `policy.ts` | interactive-profile gates |

## Audit log

Every classified request appends a JSON line to `.opencode/auto-jev.log`
(configurable via `logPath`): the tool, command, decision, reason, source
(`static`/`model`/`error`), latency, and token usage.

## Development

```sh
bun install
bun test          # unit tests (policy, state, context, breaker)
bun x tsc --noEmit -p .   # typecheck
```

### Eval

Tune questions and gates against the live endpoint. `eval/corpus.ts` holds
cases labeled for the unattended tiers (`allow`/`block`/`pause`/`deny`);
`run.ts` replays the **full pipeline** (static rules → model → unattended
policy), reports accuracy + confusion, and caches live answers to
`eval/cache.json`; `sweep.ts` grid-searches the risk gates offline over the
cache. The primary safety metric is `block/deny -> allow`, which must be 0.

```sh
bun run eval/run.ts --verbose            # live, writes cache
bun run eval/run.ts --cached --verbose   # offline replay
bun run eval/sweep.ts                    # grid search over cache
```

Current corpus results (57 cases, stable across runs):
`accuracy = 56/57 (98.2%)`, `block/deny -> allow = 0`. The single mismatch is
fail-safe (an upload to an external service is blocked rather than paused).

## Layout

```
src/index.ts        plugin entry (config + event hooks, v2 reply w/ feedback)
src/config.ts       option/env resolution (interactive/unattended profiles)
src/auth.ts         databricks CLI token mint/cache
src/systemone.ts    typed HTTP client, timeout, 429/529 backoff
src/classifier.ts   orchestration: static -> state -> model -> decide
src/state.ts        build classifier state from permission + user msgs
src/questions.ts    the 5 SystemOne questions
src/policy.ts       static rules + tier logic (pure, unit-tested)
src/breaker.ts      per-session circuit breaker (block -> pause)
src/context.ts      fetch recent user messages
test/               bun test
eval/               corpus + runner + gate sweep (+ cached live answers)
```
