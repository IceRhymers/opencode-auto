import { describe, expect, test } from "bun:test"
import { recentUserMessages } from "../src/context.ts"

const client = (data: unknown) => ({
  session: {
    context: async () => data as never,
  },
})

describe("recentUserMessages", () => {
  test("extracts text from user messages only", async () => {
    const msgs = [
      { type: "user", text: "first" },
      { type: "assistant", text: "ignore me" },
      { type: "user", text: "second" },
    ]
    expect(await recentUserMessages(client(msgs), "s")).toEqual(["first", "second"])
  })

  test("returns last N", async () => {
    const msgs = [1, 2, 3, 4, 5].map((i) => ({ type: "user", text: `m${i}` }))
    expect(await recentUserMessages(client(msgs), "s", 2)).toEqual(["m4", "m5"])
  })

  test("blank and non-string text are skipped", async () => {
    const msgs = [
      { type: "user", text: "   " },
      { type: "user" },
      { type: "user", text: "hi" },
    ]
    expect(await recentUserMessages(client(msgs), "s")).toEqual(["hi"])
  })

  test("throws => empty array", async () => {
    const bad = {
      session: {
        context: async () => {
          throw new Error("boom")
        },
      },
    }
    expect(await recentUserMessages(bad, "s")).toEqual([])
  })
})
