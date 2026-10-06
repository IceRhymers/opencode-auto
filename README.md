# opencode-auto

Auto mode for [OpenCode](https://opencode.ai) powered by **TypeSafe SystemOne
(OpenJev)** served through a **Databricks AI Gateway**. It classifies each
permission request and decides — in code, not in a prompt — whether to
auto-approve, auto-deny, or leave the normal approval prompt for you.

## How it works

```
tool call → OpenCode permission rules
   ├─ explicit allow/deny → unchanged (classifier never sees it)
   └─ "ask" → permission.asked event → this plugin
         1. static fast-path rules (hard-deny list / trivial read-only allow list)
         2. build state {tool, command, patterns, cwd, recent user messages}
         3. one SystemOne call, 5 questions in parallel:
              verdict (safe | needs_review | dangerous)
              irreversible (0-1)
              matches_intent (0-1)
              exfiltration (0-1)
              scope (workspace | home | system | network)
         4. threshold policy → allow | deny | ask
```

**Decision logic** (all thresholds configurable):

- **allow** if `verdict=safe`, confidence ≥ `safeConfidence` (0.80),
  `irreversible` ≤ 0.3, `matches_intent` ≥ 0.6
- **deny** if `verdict=dangerous` with confidence ≥ `dangerousConfidence`
  (0.90), or `exfiltration` > 0.8
- **otherwise → ask** (the normal OpenCode prompt)

Failure modes are **fail-safe**: any classifier error, timeout, or missing
answer degrades to `ask`. It never auto-allows on failure. Auto-deny requires
high confidence (0.90), so uncertain-but-dangerous actions still reach you.

Only tool calls that would already ask for permission are classified. Your
explicit `allow`/`deny` rules in `opencode.json` always take priority and run
first.

## Install

Load by file path in `opencode.json` (project `.opencode/opencode.json` or
global `~/.config/opencode/opencode.json`):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "plugin": ["file:///absolute/path/to/opencode-auto/src/index.ts"]
}
```

Authenticate once so the plugin can mint tokens:

```sh
databricks auth login --host https://fevm-tanner-wendland.cloud.databricks.com --profile fevm-west
```

## Configuration

Pass options via `[name, options]` in the `plugin` array, or via env vars
(env wins):

| Option | Env | Default | Description |
| - | - | - | - |
| `enabled` | `AUTO_JEV_ENABLED` | `true` | master switch |
| `dryRun` | `AUTO_JEV_DRY_RUN` | `false` | log decisions without acting |
| `mode` | | `allow-ask-deny` | `allow-ask-deny` / `allow-ask` / `allow-deny` |
| `host` | `DATABRICKS_HOST` | fevm-tanner-wendland | gateway host |
| `profile` | `DATABRICKS_CONFIG_PROFILE` | `fevm-west` | CLI profile |
| `model` | | `system.ai.openjev-qwen35-4b` | SystemOne model |
| `contextMessages` | | `3` | recent user messages used as goal |
| `timeoutMs` | | `3000` | SystemOne timeout |
| `escalate` | | `[bash, edit, webfetch, external_directory]` | permissions forced to `ask` so the classifier sees them |
| `thresholds.*` | | see `policy.ts` | `safeConfidence`, `dangerousConfidence`, `irreversibleMax`, `intentMin`, `exfiltrationMax` |

Example:

```json
{
  "plugin": [
    ["file:///path/to/opencode-auto/src/index.ts", {
      "dryRun": true,
      "thresholds": { "safeConfidence": 0.85 }
    }]
  ]
}
```

## Audit log

Every classified request appends a JSON line to `.opencode/auto-jev.log`
(configurable via `logPath`): the tool, command, decision, reason, source
(`static`/`model`/`error`), latency, and token usage.

## Development

```sh
bun install
bun test          # unit tests (policy, state, context)
bun x tsc --noEmit -p .   # typecheck
```

### Eval

Tune questions and thresholds against the live endpoint. `eval/corpus.ts`
holds labeled cases; `run.ts` reports accuracy + confusion (primary safety
metric: `dangerous->allow` must be 0); `sweep.ts` grid-searches thresholds
offline over cached live answers.

```sh
bun run eval/run.ts --verbose
bun run eval/sweep.ts
```

Current corpus results: `dangerous->allow = 0`, `deny->deny = 8`,
`deny->ask = 6`, `allow->ask = 2`. No dangerous action is ever silently
auto-approved; uncertain dangerous actions surface to the user.

## Layout

```
src/index.ts        plugin entry (config + event hooks)
src/config.ts       option/env resolution
src/auth.ts         databricks CLI token mint/cache
src/systemone.ts    typed HTTP client, timeout, 429/529 backoff
src/classifier.ts   orchestration: static -> state -> model -> decide
src/state.ts        build classifier state from permission + user msgs
src/questions.ts    the 5 SystemOne questions
src/policy.ts       static rules + threshold logic (pure, unit-tested)
src/context.ts      fetch recent user messages
test/               bun test
eval/               corpus + runner + threshold sweep
```
