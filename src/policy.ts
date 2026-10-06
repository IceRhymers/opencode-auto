/**
 * Decision policy: static fast-path rules + threshold logic over the SystemOne
 * answers. Pure functions, fully unit-tested. The plugin feeds it a permission
 * and the classifier's answers; it returns a Decision.
 */
import type { Answer } from "./systemone.js"

export type Decision =
  | { action: "allow"; reason: string }
  | { action: "deny"; reason: string }
  | { action: "ask"; reason: string }

export type Thresholds = {
  /** confidence on verdict=safe required to auto-allow */
  safeConfidence: number
  /** max irreversible probability tolerated for auto-allow */
  irreversibleMax: number
  /** min matches_intent probability for auto-allow */
  intentMin: number
  /** confidence on verdict=dangerous required to auto-deny */
  dangerousConfidence: number
  /** exfiltration probability above this auto-denies */
  exfiltrationMax: number
}

export const DEFAULT_THRESHOLDS: Thresholds = {
  safeConfidence: 0.85,
  irreversibleMax: 0.3,
  intentMin: 0.6,
  dangerousConfidence: 0.9,
  exfiltrationMax: 0.8,
}

/** Commands that are always denied without consulting the model. */
const HARD_DENY: RegExp[] = [
  /\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+~?\//, // rm -rf / or ~/
  /\bmkfs\b/,
  /\bdd\s+.*of=\/dev\//,
  /:\(\)\{\s*:\|:&\s*\};:/, // fork bomb
  /\bshutdown\b|\breboot\b|\bhalt\b/,
  /\bgit\s+push\b[^|]*\s--force(?!-with-lease)/,
  /\/etc\/(passwd|shadow|sudoers)/,
]

/** Read-only commands that are always allowed without the model. */
const TRIVIAL_ALLOW: RegExp[] = [
  /^(git\s+(status|diff|log|show|branch|rev-parse|blame))\b/,
  /^(ls|pwd|echo|cat|head|tail|wc|which|whoami|date|env)\b/,
  /^(bun|npm|pnpm|yarn)\s+(test|run\s+test)\b/,
  /^(tsc|bun\s+x\s+tsc)\b.*--noEmit/,
]

function bashCommand(p: { permission: string; metadata?: Record<string, unknown> }): string {
  return typeof p.metadata?.command === "string" ? p.metadata.command.trim() : ""
}

/** Static rules short-circuit the model. Returns undefined when no rule hits. */
export function staticDecision(p: { permission: string; metadata?: Record<string, unknown> }): Decision | undefined {
  if (p.permission !== "bash") return undefined
  const cmd = bashCommand(p)
  if (!cmd) return undefined
  for (const re of HARD_DENY) {
    if (re.test(cmd)) return { action: "deny", reason: `hard-deny rule: ${re.source}` }
  }
  // don't trivially allow compound commands; only single simple commands
  if (!/[|;&`]|\$\(/.test(cmd)) {
    for (const re of TRIVIAL_ALLOW) {
      if (re.test(cmd)) return { action: "allow", reason: `trivial-allow rule: ${re.source}` }
    }
  }
  return undefined
}

function num(a: Answer | undefined, key: "noul"): number | undefined {
  return a && a.type === "noul" ? a.noul : undefined
}

/** Threshold logic over classifier answers. Missing/odd answers degrade to ask. */
export function decide(answers: Record<string, Answer>, t: Thresholds = DEFAULT_THRESHOLDS): Decision {
  const verdict = answers.verdict
  if (!verdict || verdict.type !== "choice") return { action: "ask", reason: "no verdict answer" }

  // Missing answers must only ever push toward "ask", never allow or deny.
  // irreversible defaults high so it blocks allow; intent low so it blocks
  // allow; exfiltration low so it does NOT trigger a deny on absent data.
  const irreversible = num(answers.irreversible, "noul") ?? 1
  const intent = num(answers.matches_intent, "noul") ?? 0
  const exfil = num(answers.exfiltration, "noul") ?? 0
  const scope = answers.scope?.type === "choice" ? answers.scope.choice : undefined

  // hard denies first
  if (verdict.choice === "dangerous" && verdict.confidence >= t.dangerousConfidence) {
    return { action: "deny", reason: `dangerous (conf ${verdict.confidence.toFixed(2)})` }
  }
  if (exfil >= t.exfiltrationMax) {
    return { action: "deny", reason: `possible data exfiltration (p=${exfil.toFixed(2)})` }
  }

  // confident allow requires several independent signals
  if (
    verdict.choice === "safe" &&
    verdict.confidence >= t.safeConfidence &&
    irreversible <= t.irreversibleMax &&
    intent >= t.intentMin
  ) {
    return {
      action: "allow",
      reason: `safe (conf ${verdict.confidence.toFixed(2)}, intent ${intent.toFixed(2)}, irrev ${irreversible.toFixed(2)}${scope ? `, ${scope}` : ""})`,
    }
  }

  return {
    action: "ask",
    reason: `uncertain (verdict=${verdict.choice} conf=${verdict.confidence.toFixed(2)}, intent=${intent.toFixed(2)}, irrev=${irreversible.toFixed(2)}, exfil=${exfil.toFixed(2)})`,
  }
}
