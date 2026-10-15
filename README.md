# opencode-auto

Auto mode for [OpenCode](https://opencode.ai) **V2** powered by a **SystemOne-compatible
classifier** — either the native **TypeSafe SystemOne** API or **OpenJev** served
through a **Databricks AI Gateway**. It classifies each permission request and
decides — in code, not in a prompt — whether to auto-approve, auto-block, or
leave the normal approval prompt for you. (For OpenCode V1, use the `v1-final`
tag — the V1 plugin API does not run on V2.)

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
   ├─ explicit deny → rejected (classifier never sees it)
   └─ allow / ask → permission "evaluate" hook → this plugin
         0. skip when the decision is "allow" for a non-escalated
            action (read, grep, glob, ... stay silent)
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

The hook runs **inline, before any prompt is published**, and rewrites the
decision: `allow` executes, `deny` rejects with a message the agent reads as
a tool error (blocks), `ask` shows the prompt with the classifier's reason
attached (pauses). Because the hook is awaited, decisions apply everywhere —
TUI and headless alike.

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

Every `ask` decision is classified, plus `allow` decisions for the escalated
actions (`shell`, `edit`, `webfetch`, `external_directory`) — V2 defaults
allow those, which is exactly the traffic the classifier exists for. Explicit
`deny` rules in `opencode.json(c)` always take priority and never reach the
plugin. Two caveats of hook-based escalation: your explicit `allow` rules and
saved "always" approvals for the escalated actions are re-checked too (the
hook can't tell them apart from V2's defaults), and there is no config
mutation — your file is never rewritten. Commands that target the classifier
itself (its source tree, install config, audit log) are hard-denied
statically.

### Headless `opencode run`

The evaluate hook runs inline and is awaited, so auto-allow and auto-block
work the same in headless runs as in the TUI — the V1 watchdog race is gone.
Decisions that keep the prompt (`ask`/`pause`) still need a client that
answers prompts; in a headless run those stall or are rejected by the
runner, which is the safe behavior.

## Install

A [Justfile](https://github.com/casey/just) manages installation into two
configs: normal OpenCode (`~/.config/opencode/opencode.json`) and the **ug**
setup (`~/.ucode/opencode-xdg/opencode/opencode.json`). It edits the `plugins`
(or V1 `plugin`) array in place (preserving formatting/key order), backs up
first, and is idempotent.

```sh
just install-dry        # normal opencode, dry-run (log only — start here)
just install-ug-dry     # ug setup, dry-run
just install            # normal, live
just install-ug         # ug, live
just status             # show install state in normal, ug, and project configs
just uninstall[-ug]     # remove (also cleans this repo's project config)
just uninstall-project  # remove from this repo's .opencode/opencode.json only
just replay             # replay the audit log through the current rules
```

The plugin can be registered in **three** places: the two global configs above
and the project-local `./.opencode/opencode.json` in this repo. A global
`uninstall` that leaves the project registration behind is why the plugin can
"still load after restart" — `uninstall` now removes it from the named config
**and** the project config. Use `just status` to see all three at once.

Dry-run mode logs every decision to `.opencode/auto-jev.log` without acting —
watch it, then re-run `just install[-ug]` (no `-dry`) to go live.

### Manual install

If you prefer not to use `just`, add the plugin package **directory** to the
`plugins` array in `opencode.json(c)` yourself (V2 does not load single-file
paths from the config; it resolves `<dir>/server.*` then `<dir>/index.*` —
the root `index.ts` here re-exports `src/index.ts`):

```json
{
  "plugins": [{ "package": "file:///absolute/path/to/opencode-auto" }]
}
```

or with options (here: a databricks profile + interactive run mode):

```json
{
  "plugins": [
    {
      "package": "file:///path/to/opencode-auto",
      "options": { "profile": "fevm-west", "runProfile": "interactive" }
    }
  ]
}
```

The V1 `plugin` array also works for plain string entries — V2 normalizes it
on load — but don't define both keys, and don't register the same package in
two configs with different options: entries are deduplicated by resolved path
and the **highest-precedence config wins** (project `.opencode/` beats
global), so a stale project entry silently shadows your global options.

## Bring your own backend

The classifier talks to any **SystemOne-compatible** endpoint. Pick one of two
backends; the plugin auto-detects which one you mean from what you configure.

| | **Native TypeSafe SystemOne** | **Databricks AI Gateway** |
|-|-|-|
| Endpoint | `https://api.typesafe.ai/v1/systemone` | `https://<host>/ai-gateway/typesafe/v1/systemone` |
| Auth | API key in an env var | Databricks token (OAuth profile, PAT, or `DATABRICKS_TOKEN`) |
| Default model | `jev-latest` | `system.ai.openjev-qwen35-4b` |

**Auto-detection order** (first match wins):
1. explicit `provider` option / `AUTO_JEV_PROVIDER`
2. explicit `profile` or `host` plugin option → **databricks**
3. the env var named by `apiKeyEnv` (default `TYPESAFE_API_KEY`) is set → **systemone**
4. `DATABRICKS_TOKEN` / `DATABRICKS_HOST` / `DATABRICKS_CONFIG_PROFILE` set → **databricks**
5. otherwise the plugin stays **inactive** (and does not touch your permissions)

### Native SystemOne

```sh
export TYPESAFE_API_KEY=...        # the only requirement
just install                       # auto-detects systemone
```

### Databricks — CLI profile (OAuth)

```sh
databricks auth login --host https://<workspace> --profile myprofile   # once
just install-ug --profile myprofile
```

The host is resolved from the profile, so a profile name alone is enough.

### Databricks — bring your own token

```sh
export DATABRICKS_HOST=https://<workspace>
export DATABRICKS_TOKEN=dapi...      # PAT or OAuth token
just install-ug
```

### Override the endpoint entirely

Point at any SystemOne-compatible server (a proxy, a different gateway path):

```sh
just install-ug --url https://proxy.example.com/systemone --provider systemone
```

Check what the plugin resolved and probe it (auth + one cheap request):

```sh
just whoami                          # auto-detect
just whoami --profile myprofile
# provider: databricks
# url:      https://<workspace>/ai-gateway/typesafe/v1/systemone
# model:    system.ai.openjev-qwen35-4b
# auth:     cli-profile:myprofile
# probe:    ok
```

## Configuration

Pass options via the entry's `options` object in the `plugins` array (or the
`[name, options]` tuple in a V1 `plugin` array), or via env vars.
**Explicit plugin options win over env vars** so a stray shell var can't hijack a
deliberate install.

| Option | Env | Default | Description |
| - | - | - | - |
| `enabled` | `AUTO_JEV_ENABLED` | `true` | master switch |
| `dryRun` | `AUTO_JEV_DRY_RUN` | `false` | log decisions without acting |
| `runProfile` | `AUTO_JEV_PROFILE` | `unattended` | `interactive` / `unattended` |
| `mode` | | `allow-ask-deny` | `allow-ask-deny` / `allow-ask` / `allow-deny` |
| `provider` | `AUTO_JEV_PROVIDER` | auto | `systemone` / `databricks` |
| `url` | `AUTO_JEV_URL` | per-provider | full endpoint URL; overrides host/path |
| `apiKeyEnv` | | `TYPESAFE_API_KEY` | name of the env var holding the TypeSafe key |
| `host` | `DATABRICKS_HOST` | from profile | databricks workspace host |
| `profile` | `DATABRICKS_CONFIG_PROFILE` | | databricks CLI profile |
| `model` | `AUTO_JEV_MODEL` | `jev-latest` / `system.ai.openjev-qwen35-4b` | classifier model |
| `contextMessages` | | `3` | recent user messages used as goal |
| `timeoutMs` | | `3000` | SystemOne timeout |
| `maxConsecutiveBlocks` | | `2` | circuit breaker: blocks in a row before pausing |
| `maxBlocksPerSession` | | `4` | circuit breaker: total blocks before pausing |
| `escalate` | | `[bash, edit, webfetch, external_directory]` | actions classified even when V2 resolves `allow` (`bash` covers V2's `shell`) |
| `thresholds.*` | | see `policy.ts` | interactive-profile gates |

The API key is **only ever read from the environment** — never from
`opencode.json` — so it can't be committed by accident.

## Audit log

Every classified request appends a JSON line to `.opencode/auto-jev.log`
(configurable via `logPath`): the tool, command, decision, reason, source
(`static`/`model`/`error`), latency, and token usage.

## Development

```sh
bun install
bun test          # unit tests (policy, state, context, breaker, config, auth)
bun x tsc --noEmit -p .   # typecheck
```

### Eval

Tune questions and gates against the live endpoint. `eval/corpus.ts` holds
cases labeled for the unattended tiers (`allow`/`block`/`pause`/`deny`);
`run.ts` replays the **full pipeline** (static rules → model → unattended
policy), reports accuracy + confusion, and caches live answers to a
per-backend file `eval/cache-<provider>-<model>.json`; `sweep.ts` grid-searches
the risk gates offline over the cache. The eval uses the same `createBackend`
as the plugin, so backend flags match production. The primary safety metric is
`block/deny -> allow`, which must be 0.

```sh
bun run eval/run.ts --verbose                          # live, writes cache (auto-detected backend)
bun run eval/run.ts --cached --verbose                 # offline replay
bun run eval/run.ts --provider databricks --profile X  # force a backend
bun run eval/run.ts --provider systemone --model jev-latest
bun run eval/sweep.ts                                  # grid search over cache
```

Current corpus results (68 cases, databricks OpenJev, stable across runs):
`accuracy = 67/68 (98.5%)`, `block/deny -> allow = 0`. The single mismatch is
fail-safe (an upload to an external service is blocked rather than paused).
Thresholds were tuned against OpenJev on Databricks; run the eval against
`--provider systemone` before trusting the gates on the native model.

## Layout

```
index.ts            package entry shim (V2 resolves <dir>/index.*, not "main")
src/index.ts        plugin entry (V2 setup: execute.before + permission evaluate)
src/adapter.ts      V2 translation: action names, command capture, effect mapping
src/config.ts       option/env resolution + backend auto-detect
src/backend.ts      wire backend config -> url + auth + client (plugin & eval)
src/auth.ts         token sources: TypeSafe key env / DATABRICKS_TOKEN / CLI OAuth
src/systemone.ts    typed SystemOne HTTP client (full URL, timeout, backoff)
src/whoami.ts       print + probe the resolved backend
src/classifier.ts   orchestration: static -> state -> model -> decide
src/state.ts        build classifier state (permission + diff + user msgs)
src/questions.ts    the 5 SystemOne questions
src/policy.ts       static rules + tier logic (pure, unit-tested)
src/breaker.ts      per-session circuit breaker (block -> pause)
src/context.ts      fetch recent user messages (session context endpoint)
test/               bun test
eval/               corpus + runner + gate sweep (+ per-backend cached answers)
```
