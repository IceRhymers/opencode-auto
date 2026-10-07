/**
 * Minimal typed client for a SystemOne-compatible endpoint (native TypeSafe
 * SystemOne, or a Databricks AI Gateway path). No SDK dependency — one fetch
 * with a timeout and bounded retries on 429/529.
 */
import type { Question } from "./questions.js"

export type SystemOneConfig = {
  /** full endpoint URL, e.g. https://api.typesafe.ai/v1/systemone */
  url: string
  model: string
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
  usage: { input_tokens: number; output_tokens: number }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

export function createSystemOne(cfg: SystemOneConfig, getToken: () => Promise<string>) {
  const url = cfg.url
  const timeoutMs = cfg.timeoutMs ?? 3000
  const maxRetries = cfg.maxRetries ?? 2

  return {
    url,
    async ask(state: unknown, questions: Record<string, Question>): Promise<SystemOneResponse> {
      const token = await getToken()
      const body = JSON.stringify({ model: cfg.model, state, questions })

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
          return (await res.json()) as SystemOneResponse
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
