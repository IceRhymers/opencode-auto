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
const MAX_MESSAGE = 800

const clip = (s: string, n: number) => (s.length > n ? s.slice(0, n) + "…" : s)

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
  // Include any other short metadata fields (e.g. filePath for edit) verbatim.
  for (const [k, v] of Object.entries(meta)) {
    if (k === "command" || typeof v !== "string") continue
    ;(state.action as Record<string, unknown>)[k] = clip(v, MAX_FIELD)
  }
  return state
}
