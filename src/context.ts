/**
 * Fetches user-authored text for the classifier's user_goal from the V2
 * session context endpoint. The goal keeps the first user message (the task
 * often scrolls out of a long session), the last `count` messages, and answers
 * to the question tool. Failures are non-fatal — the caller falls back to
 * "(not available)".
 */

// Minimal structural types so we don't depend on the full SDK generics.
type ToolContent = { type?: string; text?: string }
type ToolPart = {
  type?: string
  name?: string
  state?: { status?: string; content?: ToolContent[] }
}
type ContextEntry = {
  type?: string
  text?: string
  content?: Array<string | ToolPart>
  status?: string
  summary?: string
}

export type MessagesClient = {
  context(opts: { sessionID: string }): Promise<ContextEntry[]>
}

function questionAnswers(entry: ContextEntry): string[] {
  if (entry.type !== "assistant" || !Array.isArray(entry.content)) return []
  const out: string[] = []
  for (const part of entry.content) {
    if (typeof part === "string" || part?.type !== "tool" || part.name !== "question") continue
    if (part.state?.status !== "completed" || !Array.isArray(part.state.content)) continue
    const text = part.state.content
      .filter((c) => c?.type === "text" && typeof c.text === "string")
      .map((c) => c.text!.trim())
      .filter(Boolean)
      .join("\n")
    if (text) out.push(`User chose: ${text}`)
  }
  return out
}

export async function recentUserMessages(
  client: MessagesClient,
  sessionID: string,
  count = 3,
): Promise<string[]> {
  try {
    const entries = await client.context({ sessionID })
    const messages: string[] = []
    let firstUser: string | undefined
    let compactionSummary: string | undefined

    for (const entry of entries) {
      if (entry.type === "user" && typeof entry.text === "string" && entry.text.trim()) {
        const text = entry.text.trim()
        if (!firstUser) firstUser = text
        messages.push(text)
        continue
      }
      messages.push(...questionAnswers(entry))
      if (!compactionSummary && entry.type === "compaction" && entry.status === "completed" && entry.summary?.trim()) {
        compactionSummary = `Session summary: ${entry.summary.trim()}`
      }
    }

    // The first message is the stable task anchor. Keep it in addition to the
    // recent window, without duplicating it in short sessions.
    const recent = messages.slice(-Math.max(1, count))
    const anchor = firstUser ?? compactionSummary
    if (anchor && !recent.includes(anchor)) return [anchor, ...recent]
    return recent
  } catch {
    return []
  }
}
