/**
 * Replay the audit log (.opencode/auto-jev.log) through the CURRENT static
 * rules and show old action -> new action per entry. This is the measuring
 * stick for policy changes: it answers "would this command still have
 * prompted/denied/paused?" without re-running the session.
 *
 * Only static decisions are reproduced exactly; model-path entries are
 * replayed against the cached answers in eval/cache.json when the command
 * matches a corpus case (offline approximation), otherwise marked "(model)".
 *
 * Usage: bun run eval/replay.ts [path-to-log]
 */
import { staticDecision, type SelfPaths } from "../src/policy.ts"
import { CORPUS } from "./corpus.ts"
import { pipeline } from "./run.ts"
import type { Answer } from "../src/systemone.ts"

const LOG = process.argv[2] ?? ".opencode/auto-jev.log"
const CACHE = new URL("./cache.json", import.meta.url).pathname
const SELF: SelfPaths = { worktree: "/Users/tanner.wendland/projects/opencode-auto", logPath: ".opencode/auto-jev.log" }

type LogEntry = {
  permission?: string
  command?: string
  patterns?: string[]
  action?: string
  source?: string
  reason?: string
}

// Corpus lookup by command so replayed model-path entries reuse cached answers.
const cache: { name: string; answers: Record<string, Answer> }[] = JSON.parse(await Bun.file(CACHE).text())
const answersByName = new Map(cache.map((e) => [e.name, e.answers]))
const corpusByCommand = new Map(CORPUS.filter((c) => c.command).map((c) => [c.command, c]))

const text = await Bun.file(LOG).text()
const entries = text
  .split("\n")
  .filter((l) => l.trim())
  .map((l) => JSON.parse(l) as LogEntry)
  .filter((e) => e.permission && e.action)

// Normalize old decisions into the current tier vocabulary for comparison.
function tier(action: string): string {
  if (action === "ask") return "pause" // interactive "ask" == unattended "pause": both wait for the user
  return action
}

const moves: Record<string, number> = {}
let oldPrompts = 0 // ask/pause: stopped for the user
let oldDenied = 0
let newPrompts = 0
let newStopped = 0 // pause + block + deny
let safetyRegressions = 0 // was stopped (pause/block/deny), now allowed
const regressions: string[] = []
const rows: string[] = []

for (const e of entries) {
  const metadata = e.command ? { command: e.command } : {}
  let stat = staticDecision({ permission: e.permission!, metadata }, { self: SELF })
  let source = "static"

  if (!stat) {
    const c = e.command ? corpusByCommand.get(e.command) : undefined
    if (c) {
      const r = pipeline(c, answersByName.get(c.name))
      stat = r.d
      source = r.source
    }
  }

  const oldT = tier(e.action!)
  const newT = stat ? tier(stat.action) : "(model)"
  const key = `${oldT}->${newT}`
  moves[key] = (moves[key] ?? 0) + 1

  if (oldT === "pause") oldPrompts++
  if (oldT === "deny" || oldT === "block") oldDenied++
  if (newT === "pause") newPrompts++
  if (newT === "pause" || newT === "deny" || newT === "block") newStopped++
  if ((oldT === "pause" || oldT === "deny" || oldT === "block") && newT === "allow") {
    safetyRegressions++
    regressions.push(`  ${oldT}->allow: ${e.command ?? e.patterns?.[0] ?? e.permission}`)
  }

  const label = (e.command ?? e.patterns?.[0] ?? e.permission)!.slice(0, 90)
  rows.push(`  ${oldT.padEnd(7)} -> ${newT.padEnd(8)} (${source}) ${label}`)
}

console.log("=== Per-entry replay (old -> new) ===")
for (const r of rows) console.log(r)

console.log("\n=== Transition totals (old -> new) ===")
for (const [k, v] of Object.entries(moves).sort()) console.log(`  ${k}: ${v}`)

console.log(`\nEntries: ${entries.length}`)
console.log(`Stopped for the user (ask/pause): ${oldPrompts} -> ${newPrompts}`)
console.log(`Rejected (block/deny):            ${oldDenied} -> ${Object.entries(moves)
  .filter(([k]) => k.endsWith("->deny") || k.endsWith("->block"))
  .reduce((n, [, v]) => n + v, 0)}`)
console.log(`Safety regressions (stopped -> allow): ${safetyRegressions}  (must be reviewed)`)
if (regressions.length) {
  console.log("  review these:")
  for (const r of regressions) console.log(r)
}
