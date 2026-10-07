/**
 * Builds the SystemOne `state` from a permission request plus light session
 * context. Keep it small and structured — the model only needs enough to judge
 * risk and intent-match. Everything is capped so a huge command or transcript
 * can't blow up the request.
 */

export type PermissionLike = {
  permission: string
  patterns?: string[]
  metadata?: Record<string, unknown>
}

const MAX_FIELD = 1200
/** the diff/content of an edit gets more room: it's the main risk signal */
const MAX_DIFF = 4000
const MAX_MESSAGE = 800

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + "…" : s)

/** Fields whose content the model should judge directly, at higher budget. */
const CONTENT_FIELDS = new Set(["diff", "content", "newString", "oldString"])

export function buildState(p: PermissionLike, userMessages: string[], worktree: string) {
  const meta = p.metadata ?? {}
  const command = typeof meta.command === "string" ? clip(meta.command, MAX_FIELD) : undefined
  const recent = userMessages.slice(-3).map((m) => clip(m, MAX_MESSAGE))

  const state: Record<string, unknown> = {
    user_goal: recent.length ? recent.join("\n---\n") : "(not available)",
    action: {
      tool: p.permission,
      ...(command ? { command } : {}),
      patterns: p.patterns ?? [],
      cwd: worktree,
    },
  }
  // Include other metadata fields verbatim (capped). For edit/write this is
  // where the model sees the actual change (filepath, diff, content) instead
  // of just a path — the difference between "judging a filename" and
  // "judging a change".
  for (const [k, v] of Object.entries(meta)) {
    if (k === "command" || typeof v !== "string") continue
    const budget = CONTENT_FIELDS.has(k) ? MAX_DIFF : MAX_FIELD
    ;(state.action as Record<string, unknown>)[k] = clip(v, budget)
  }
  return state
}
