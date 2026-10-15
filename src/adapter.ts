/**
 * V2 adapter: translate between OpenCode V2 permission evaluations and the
 * classifier's internal vocabulary.
 *
 * Internal names stay on the V1 vocabulary ("bash", "task") so policy rules,
 * SystemOne questions, the eval corpus, and the tuned thresholds are
 * untouched; only this module knows the V2 names ("shell", "subagent").
 *
 * The V2 shell permission assert carries NO metadata — only the sub-commands
 * the shell scanner split out (resources). The full command line is captured
 * from the tool.execute.before hook (keyed by tool call id) and passed in
 * here; the fallback joins resources, which loses quoting/pipes and therefore
 * weakens the static rules, so it is only a fallback.
 */
import type { PermissionLike } from "./state.js"
import type { Decision } from "./policy.js"
import type { Mode } from "./config.js"

/** V2 permission evaluation, structurally typed (no plugin-package import). */
export type EvaluationLike = {
  action: string
  resources: readonly string[]
  metadata?: Record<string, unknown>
  source?: { type: string; messageID?: string; id?: string }
  effect: "allow" | "deny" | "ask"
  message?: string
}

/** Map a V2 action name to the classifier's internal permission name. */
export function canonicalAction(action: string): string {
  if (action === "shell") return "bash"
  if (action === "subagent") return "task"
  return action
}

/** Call id linking every permission assert a single tool call raises. */
export function callIDOf(ev: EvaluationLike): string | undefined {
  return ev.source?.type === "tool" ? ev.source.id : undefined
}

/**
 * Should this evaluation be classified at all? Explicit deny rules never
 * reach the hook (V2 resolves them earlier). "ask" is always classified.
 * "allow" is classified only for escalated actions — V2 defaults allow
 * shell/edit/webfetch, which is exactly the traffic the classifier exists
 * for. This mirrors the V1 config hook that forced those tools to "ask".
 *
 * Trade-off (accepted): explicit allow rules and saved "always" approvals
 * for escalated actions are re-checked too — the hook can't distinguish them
 * from V2's built-in defaults.
 */
export function shouldClassify(
  effect: "allow" | "deny" | "ask",
  action: string,
  escalate: ReadonlySet<string>,
): boolean {
  if (effect === "ask") return true
  if (effect === "allow") return escalate.has(canonicalAction(action))
  return false
}

/**
 * Build the classifier input from an evaluation. `command` is the full shell
 * command line captured at execute.before; when present the call is judged
 * as "bash" even for the external_directory half of the pair (one decision
 * covers both asserts of the same shell call, like V1).
 */
export function evaluationToPermission(ev: EvaluationLike, command?: string): PermissionLike {
  const meta: Record<string, unknown> = { ...(ev.metadata ?? {}) }
  if (command !== undefined) {
    meta.command = command
    return { permission: "bash", patterns: [...ev.resources], metadata: meta }
  }
  return { permission: canonicalAction(ev.action), patterns: [...ev.resources], metadata: meta }
}

/**
 * Apply a decision to the evaluation, preserving V1 mode gating exactly:
 *   allow — applied unless mode is "allow-ask"
 *   deny  — applied only when mode is "allow-ask-deny"
 *   block — always applied (unattended profile); a deny whose message the
 *           agent reads as a tool error, so the loop keeps going
 *   ask / pause — the prompt shows; the message annotates it
 * dryRun never touches the evaluation (observe-only — unlike V1 dry-run,
 * which still forced prompts through its config hook).
 */
export function applyDecision(
  ev: EvaluationLike,
  final: Decision,
  opts: { mode: Mode; dryRun: boolean },
): void {
  if (opts.dryRun) return
  switch (final.action) {
    case "allow":
      if (opts.mode === "allow-ask") return
      ev.effect = "allow"
      return
    case "deny":
      if (opts.mode !== "allow-ask-deny") return
      ev.effect = "deny"
      ev.message = `auto-jev denied: ${final.reason}`
      return
    case "block":
      ev.effect = "deny"
      ev.message = final.reason
      return
    case "ask":
      ev.effect = "ask"
      ev.message = `auto-jev: ${final.reason}`
      return
    case "pause":
      ev.effect = "ask"
      ev.message = `auto-jev paused: ${final.reason}`
      return
  }
}
