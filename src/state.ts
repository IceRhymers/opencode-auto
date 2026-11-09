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

export type StateOpts = {
  /** summary of resources the agent created this session (scratch tables, branches, temp files) */
  created?: string
  /** destinations the user owns (git remotes, workspace hosts); not exfiltration */
  designated?: string[]
}

export function buildState(p: PermissionLike, userMessages: string[], worktree: string, opts?: StateOpts) {
  const meta = p.metadata ?? {}
  const command = typeof meta.command === "string" ? clip(meta.command, MAX_FIELD) : undefined
  // context.ts already chose the window (task anchor + recent messages)
  const recent = userMessages.map((m) => clip(m, MAX_MESSAGE))
  // The call's own working directory when it ran elsewhere (e.g. the session
  // temp dir); otherwise the project worktree.
  const cwd = typeof meta.cwd === "string" ? meta.cwd : worktree

  const action: Record<string, unknown> = {
    tool: p.permission,
    ...(command ? { command } : {}),
    patterns: p.patterns ?? [],
    cwd,
  }
  if (opts?.created) action.created_this_session = opts.created

  const state: Record<string, unknown> = {
    user_goal: recent.length ? recent.join("\n---\n") : "(not available)",
    action,
    ...(opts?.designated?.length ? { designated_destinations: opts.designated } : {}),
  }
  // Include other metadata fields verbatim (capped). For edit/write this is
  // where the model sees the actual change (filepath, diff, content) instead
  // of just a path — the difference between "judging a filename" and
  // "judging a change".
  for (const [k, v] of Object.entries(meta)) {
    if (k === "command" || k === "cwd" || typeof v !== "string") continue
    if (k === "tool") {
      // the V2 tool name (shell/read/...); action.tool stays the permission
      action.tool_name = clip(v, 100)
      continue
    }
    const budget = CONTENT_FIELDS.has(k) ? MAX_DIFF : MAX_FIELD
    action[k] = clip(v, budget)
  }
  return state
}
