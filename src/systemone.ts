/**
 * Minimal typed client for a SystemOne-compatible endpoint: the native
 * TypeSafe SystemOne API, a Databricks AI Gateway path, or the Databricks
 * AI Decide function API (beta). No SDK dependency — one fetch with a
 * timeout and bounded retries on 429/529.
 *
 * Two wire shapes, selected by `wire` (default "systemone"):
 *   - "systemone": POST { model, state, questions }
 *                  -> { model, answers, usage }
 *   - "ai-decide": POST { state, questions, options: { version } }
 *                  -> { response: { answers }, metadata: { version } }
 *     No model selection, no token usage, and noul answers carry
 *     `probability` instead of `noul`; normalizeResponse maps both shapes to
 *     SystemOneResponse so everything downstream is wire-agnostic.
 */
import type { Question } from "./questions.js"

export type Wire = "systemone" | "ai-decide"

/** The only function API version AI Decide currently supports. */
export const AI_DECIDE_VERSION = "1.0"

export type SystemOneConfig = {
  /** full endpoint URL, e.g. https://api.typesafe.ai/v1/systemone */
  url: string
  model: string
  wire?: Wire
  timeoutMs?: number
  maxRetries?: number
}

export type ChoiceAnswer = {
  type: "choice"
  choice: string
  confidence: number
  probabilities: Record<string, number>
}
export type NoulAnswer = { type: "noul"; noul: number }
export type Answer = ChoiceAnswer | NoulAnswer

export type SystemOneResponse = {
  model: string
  answers: Record<string, Answer>
  usage?: { input_tokens: number; output_tokens: number }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

/** Map either wire shape to SystemOneResponse (see file header). */
function normalizeResponse(raw: unknown, wire: Wire): SystemOneResponse {
  if (wire === "systemone") return raw as SystemOneResponse
  const r = raw as {
    response?: { answers?: Record<string, unknown> }
    metadata?: { version?: string }
  }
  const answers = r?.response?.answers
  if (!answers || typeof answers !== "object") {
    throw new Error("ai-decide response missing response.answers")
  }
  const out: Record<string, Answer> = {}
  for (const [id, a] of Object.entries(answers)) {
    const ans = a as { type?: string; probability?: number }
    out[id] = ans?.type === "noul" ? { type: "noul", noul: ans.probability as number } : (ans as unknown as Answer)
  }
  return { model: `ai-decide@${r?.metadata?.version ?? AI_DECIDE_VERSION}`, answers: out }
}

export function createSystemOne(cfg: SystemOneConfig, getToken: () => Promise<string>) {
  const url = cfg.url
  const wire: Wire = cfg.wire ?? "systemone"
  const timeoutMs = cfg.timeoutMs ?? 3000
  const maxRetries = cfg.maxRetries ?? 2

  return {
    url,
    async ask(state: unknown, questions: Record<string, Question>): Promise<SystemOneResponse> {
      const token = await getToken()
      const body =
        wire === "ai-decide"
          ? JSON.stringify({ state, questions, options: { version: AI_DECIDE_VERSION } })
          : JSON.stringify({ model: cfg.model, state, questions })

      let lastErr: unknown
      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const ac = new AbortController()
        const timer = setTimeout(() => ac.abort(), timeoutMs)
        try {
          const res = await fetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${token}`,
            },
            body,
            signal: ac.signal,
          })
          if (res.status === 429 || res.status === 529) {
            lastErr = new Error(`systemone ${res.status}`)
            await sleep(250 * 2 ** attempt)
            continue
          }
          if (!res.ok) {
            const text = await res.text().catch(() => "")
            throw new Error(`systemone ${res.status}: ${text.slice(0, 300)}`)
          }
          return normalizeResponse(await res.json(), wire)
        } catch (e) {
          lastErr = e
          if (e instanceof Error && e.name === "AbortError") {
            throw new Error(`systemone timeout after ${timeoutMs}ms`)
          }
          // network errors: brief backoff then retry
          await sleep(250 * 2 ** attempt)
        } finally {
          clearTimeout(timer)
        }
      }
      throw lastErr instanceof Error ? lastErr : new Error(String(lastErr))
    },
  }
}

export type SystemOne = ReturnType<typeof createSystemOne>
