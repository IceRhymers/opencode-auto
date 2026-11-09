/**
 * Classifier: turn a permission request into a Decision.
 * Order of operations:
 *   1. static fast-path rules (no model)
 *   2. build state from permission + recent user messages
 *   3. one SystemOne call, 5 questions in parallel
 *   4. threshold policy -> allow / ask / deny (interactive) or
 *      allow / block / pause (unattended)
 * Any classifier error degrades to "ask" (interactive) or "pause"
 * (unattended): never auto-allow, never deny on error.
 */
import { buildState, type PermissionLike } from "./state.js"
import { decide, staticDecision, type Decision } from "./policy.js"
import { QUESTIONS } from "./questions.js"
import type { Answer, SystemOne } from "./systemone.js"
import type { Config } from "./config.js"

export type ClassifyInput = PermissionLike & { sessionID: string }

export type ClassifyResult = Decision & {
  source: "static" | "model" | "error"
  latencyMs?: number
  usage?: { input_tokens: number; output_tokens: number }
  /** raw model answers, logged for offline tuning */
  answers?: Record<string, Answer>
}

export function createClassifier(deps: {
  systemone: SystemOne
  config: Config
  getUserMessages: (sessionID: string) => Promise<string[]>
  worktree: string
  /** destinations the user owns (git remotes, workspace hosts) */
  designated?: () => string[]
  /** per-session ledger summary of resources the agent created */
  created?: (sessionID: string) => string | undefined
}) {
  const { systemone, config, getUserMessages, worktree } = deps
  const unattended = config.mode_profile === "unattended"
  const self = { worktree, logPath: config.logPath }

  return async function classify(input: ClassifyInput): Promise<ClassifyResult> {
    const stat = staticDecision(input, { self, unattended, cwd: worktree })
    if (stat) return { ...stat, source: "static" }

    try {
      const messages = await getUserMessages(input.sessionID)
      const state = buildState(input, messages, worktree, {
        created: deps.created?.(input.sessionID),
        designated: deps.designated?.(),
      })
      const t0 = Date.now()
      const res = await systemone.ask(state, QUESTIONS)
      const d = decide(res.answers, config.thresholds, {
        unattended,
        permission: input.permission,
        metadata: input.metadata,
        cwd: worktree,
      })
      return { ...d, source: "model", latencyMs: Date.now() - t0, usage: res.usage, answers: res.answers }
    } catch (e) {
      const reason = `classifier error: ${e instanceof Error ? e.message : String(e)}`
      return unattended ? { action: "pause", reason, source: "error" } : { action: "ask", reason, source: "error" }
    }
  }
}

export type Classifier = ReturnType<typeof createClassifier>
