/**
 * Fetches the most recent user-authored text for the classifier's user_goal.
 * Failures are non-fatal — the caller falls back to "(not available)".
 */

// Minimal structural types so we don't depend on the full SDK generics.
type TextPart = { type: string; text?: string }
type MessageEntry = { info?: { role?: string }; parts?: TextPart[] }

export type MessagesClient = {
  session: {
    messages(opts: {
      path: { id: string }
      query?: { limit?: number }
    }): Promise<{ data?: MessageEntry[] } | MessageEntry[]>
  }
}

export async function recentUserMessages(
  client: MessagesClient,
  sessionID: string,
  count = 3,
): Promise<string[]> {
  try {
    const res = await client.session.messages({ path: { id: sessionID }, query: { limit: 50 } })
    const entries: MessageEntry[] = Array.isArray(res) ? res : (res.data ?? [])
    const out: string[] = []
    for (const e of entries) {
      if (e.info?.role !== "user" || !Array.isArray(e.parts)) continue
      const text = e.parts
        .filter((p) => p.type === "text" && typeof p.text === "string")
        .map((p) => p.text!.trim())
        .filter(Boolean)
        .join("\n")
      if (text) out.push(text)
    }
    return out.slice(-count)
  } catch {
    return []
  }
}
