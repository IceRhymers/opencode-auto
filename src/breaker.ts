/**
 * Session circuit breaker for unattended mode.
 *
 * A single blocked call is usually recoverable: the agent reads the feedback
 * and redirects. Repeated blocks mean the agent is insisting on something the
 * classifier keeps flagging (or fighting the classifier itself), so the next
 * decision in the session is escalated to "pause" — the prompt stays up until
 * the user returns.
 *
 * Two triggers, whichever fires first:
 *   - `consecutiveBlocks` blocks with no allow in between (insisting)
 *   - `maxBlocksPerSession` total blocks in the session (noisy session)
 *
 * A `session_id` of undefined maps to a single default bucket so the policy is
 * safe even when callers fail to thread the session through.
 */
export type BreakerOptions = {
  consecutiveBlocks: number
  maxBlocksPerSession: number
}

type SessionState = { blocks: number; consecutive: number }

export function createBreaker(opts: BreakerOptions) {
  const sessions = new Map<string, SessionState>()
  const key = (sessionID: string | undefined) => sessionID ?? "(unknown)"

  const get = (k: string): SessionState => {
    let s = sessions.get(k)
    if (!s) {
      s = { blocks: 0, consecutive: 0 }
      sessions.set(k, s)
    }
    return s
  }

  return {
    /** Record an allow: resets the consecutive counter for that session. */
    allow(sessionID: string | undefined) {
      get(key(sessionID)).consecutive = 0
    },
    /** Record a block: bumps both counters. Returns the new block count. */
    block(sessionID: string | undefined): number {
      const s = get(key(sessionID))
      s.blocks++
      s.consecutive++
      return s.blocks
    },
    /**
     * True when this session should escalate block -> pause. Checked BEFORE
     * recording the current decision, so a session that trips the threshold
     * pauses on the tripping call.
     */
    tripped(sessionID: string | undefined): boolean {
      const s = get(key(sessionID))
      return s.consecutive >= opts.consecutiveBlocks || s.blocks >= opts.maxBlocksPerSession
    },
    /** Forget a session (session end). */
    clear(sessionID: string | undefined) {
      sessions.delete(key(sessionID))
    },
  }
}

export type Breaker = ReturnType<typeof createBreaker>
