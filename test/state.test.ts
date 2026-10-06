import { describe, expect, test } from "bun:test"
import { buildState } from "../src/state.ts"

describe("buildState", () => {
  test("includes goal, tool, command, cwd", () => {
    const s = buildState(
      { permission: "bash", patterns: ["git status"], metadata: { command: "git status" } },
      ["add a login page"],
      "/repo",
    ) as { user_goal: string; action: Record<string, unknown> }
    expect(s.user_goal).toBe("add a login page")
    expect(s.action.tool).toBe("bash")
    expect(s.action.command).toBe("git status")
    expect(s.action.cwd).toBe("/repo")
  })

  test("keeps only last 3 user messages, joined", () => {
    const s = buildState(
      { permission: "bash", metadata: {} },
      ["one", "two", "three", "four"],
      "/repo",
    ) as { user_goal: string }
    expect(s.user_goal).toBe("two\n---\nthree\n---\nfour")
  })

  test("clips very long fields", () => {
    const long = "x".repeat(5000)
    const s = buildState(
      { permission: "bash", metadata: { command: long } },
      [long],
      "/repo",
    ) as { user_goal: string; action: { command: string } }
    expect(s.action.command.length).toBeLessThan(1300)
    expect(s.user_goal.length).toBeLessThan(900)
  })

  test("no messages => placeholder", () => {
    const s = buildState({ permission: "bash", metadata: {} }, [], "/repo") as { user_goal: string }
    expect(s.user_goal).toBe("(not available)")
  })
})
