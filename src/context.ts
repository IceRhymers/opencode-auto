/**
 * Fetches the most recent user-authored text for the classifier's user_goal,
 * from the V2 session context endpoint. Failures are non-fatal — the caller
 * falls back to "(not available)". Returns the last `count` user messages,
 * oldest-to-newest.
 */

// Minimal structural types so we don't depend on the full SDK generics.
// SessionMessageInfo entries are typed unions; user messages carry `text`.
type ContextEntry = { type?: string; text?: string }

export type MessagesClient = {
  session: {
    context(opts: { sessionID: string }): Promise<ContextEntry[]>
  }
}

export async function recentUserMessages(
  client: MessagesClient,
  sessionID: string,
  count = 3,
): Promise<string[]> {
  try {
    const entries = await client.session.context({ sessionID })
    const out: string[] = []
    for (const e of entries) {
      if (e.type !== "user" || typeof e.text !== "string") continue
      const text = e.text.trim()
      if (text) out.push(text)
    }
    return out.slice(-count)
  } catch {
    return []
  }
}
