import { describe, expect, test } from "bun:test"
import { createBreaker } from "../src/breaker.ts"

describe("createBreaker", () => {
  const opts = { consecutiveBlocks: 2, maxBlocksPerSession: 3 }

  test("does not trip before any block", () => {
    const b = createBreaker(opts)
    expect(b.tripped("s1")).toBe(false)
  })

  test("trips after consecutiveBlocks with no allow between", () => {
    const b = createBreaker(opts)
    b.block("s1")
    expect(b.tripped("s1")).toBe(false)
    b.block("s1")
    expect(b.tripped("s1")).toBe(true)
  })

  test("an allow resets the consecutive counter but not the total", () => {
    const b = createBreaker({ consecutiveBlocks: 2, maxBlocksPerSession: 10 })
    b.block("s1")
    b.allow("s1")
    b.block("s1")
    expect(b.tripped("s1")).toBe(false) // consecutive back to 1
    b.block("s1")
    expect(b.tripped("s1")).toBe(true) // consecutive 2
  })

  test("trips on session total even if never consecutive", () => {
    const b = createBreaker({ consecutiveBlocks: 5, maxBlocksPerSession: 3 })
    b.block("s1")
    b.allow("s1")
    b.block("s1")
    b.allow("s1")
    b.block("s1")
    expect(b.tripped("s1")).toBe(true)
  })

  test("sessions are independent", () => {
    const b = createBreaker(opts)
    b.block("s1")
    b.block("s1")
    expect(b.tripped("s1")).toBe(true)
    expect(b.tripped("s2")).toBe(false)
  })

  test("undefined session shares a single safe default bucket", () => {
    const b = createBreaker(opts)
    b.block(undefined)
    b.block(undefined)
    expect(b.tripped(undefined)).toBe(true)
  })

  test("clear resets the session", () => {
    const b = createBreaker(opts)
    b.block("s1")
    b.block("s1")
    b.clear("s1")
    expect(b.tripped("s1")).toBe(false)
  })
})
