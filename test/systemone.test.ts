import { afterEach, describe, expect, test } from "bun:test"
import { createSystemOne } from "../src/systemone.ts"

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

function mockFetch(impl: (url: string, init: RequestInit) => Promise<Response>) {
  globalThis.fetch = impl as unknown as typeof fetch
}

const token = () => Promise.resolve("tok")

describe("systemone wire", () => {
  test("sends model and passes the response through", async () => {
    let seen: { url?: string; body?: Record<string, unknown> } = {}
    mockFetch(async (url, init) => {
      seen = { url, body: JSON.parse(String(init.body)) }
      return Response.json({
        model: "jev-latest",
        answers: { ok: { type: "noul", noul: 0.9 } },
        usage: { input_tokens: 10, output_tokens: 2 },
      })
    })
    const c = createSystemOne({ url: "https://x/systemone", model: "jev-latest" }, token)
    const res = await c.ask({ s: 1 }, { ok: { type: "noul", instructions: "i" } })
    expect(seen.url).toBe("https://x/systemone")
    expect(seen.body?.model).toBe("jev-latest")
    expect("options" in (seen.body ?? {})).toBe(false)
    expect(res.model).toBe("jev-latest")
    expect(res.answers.ok).toEqual({ type: "noul", noul: 0.9 })
    expect(res.usage?.input_tokens).toBe(10)
  })
})

describe("ai-decide wire", () => {
  const decideResponse = {
    response: {
      answers: {
        verdict: {
          type: "choice",
          choice: "safe",
          probabilities: { safe: 0.9, dangerous: 0.1 },
          confidence: 0.9,
        },
        irreversible: { type: "noul", probability: 0.2 },
      },
    },
    metadata: { version: "1.0" },
  } as const

  test("sends no model, requests version 1.0, translates the response", async () => {
    let seen: Record<string, unknown> = {}
    mockFetch(async (_url, init) => {
      seen = JSON.parse(String(init.body))
      return Response.json(decideResponse)
    })
    const c = createSystemOne(
      { url: "https://x/api/2.0/ai-functions/ai-decide", model: "v1.0", wire: "ai-decide" },
      token,
    )
    const res = await c.ask(
      { s: 1 },
      { verdict: { type: "choice", instructions: "i", criteria: { safe: "s", dangerous: "d" } } },
    )
    expect("model" in seen).toBe(false)
    expect(seen.options).toEqual({ version: "1.0" })
    expect(res.model).toBe("ai-decide@1.0")
    // probability -> noul
    expect(res.answers.irreversible).toEqual({ type: "noul", noul: 0.2 })
    // choice answers pass through with confidence + probabilities
    expect(res.answers.verdict).toEqual(decideResponse.response.answers.verdict)
    // no token usage on this wire
    expect(res.usage).toBeUndefined()
  })

  test("missing response.answers throws (classifier fail-safe path)", async () => {
    mockFetch(async () => Response.json({ metadata: { version: "1.0" } }))
    const c = createSystemOne({ url: "https://x", model: "v1.0", wire: "ai-decide", maxRetries: 0 }, token)
    await expect(c.ask({}, {})).rejects.toThrow(/answers/)
  })
})

test("timeoutMs is honored", async () => {
  mockFetch(
    (_url, init) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")))
      }),
  )
  const c = createSystemOne({ url: "https://x", model: "m", timeoutMs: 50, maxRetries: 0 }, token)
  await expect(c.ask({}, {})).rejects.toThrow(/timeout after 50ms/)
})
