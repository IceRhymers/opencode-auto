import { describe, expect, test } from "bun:test"
import { recentUserMessages } from "../src/context.ts"

const client = (data: unknown) => ({
  session: {
    messages: async () => ({ data: data as never }),
  },
})

describe("recentUserMessages", () => {
  test("extracts text from user messages only", async () => {
    const msgs = [
      { info: { role: "user" }, parts: [{ type: "text", text: "first" }] },
      { info: { role: "assistant" }, parts: [{ type: "text", text: "ignore me" }] },
      { info: { role: "user" }, parts: [{ type: "text", text: "second" }] },
    ]
    expect(await recentUserMessages(client(msgs), "s")).toEqual(["first", "second"])
  })

  test("returns last N", async () => {
    const msgs = [1, 2, 3, 4, 5].map((i) => ({
      info: { role: "user" },
      parts: [{ type: "text", text: `m${i}` }],
    }))
    expect(await recentUserMessages(client(msgs), "s", 2)).toEqual(["m4", "m5"])
  })

  test("non-text parts are skipped", async () => {
    const msgs = [
      { info: { role: "user" }, parts: [{ type: "tool", name: "x" }, { type: "text", text: "hi" }] },
    ]
    expect(await recentUserMessages(client(msgs), "s")).toEqual(["hi"])
  })

  test("throws => empty array", async () => {
    const bad = { session: { messages: async () => { throw new Error("boom") } } }
    expect(await recentUserMessages(bad, "s")).toEqual([])
  })
})
