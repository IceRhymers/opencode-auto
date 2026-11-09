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

  test("joins every message it is given (context.ts picks the window)", () => {
    const s = buildState(
      { permission: "bash", metadata: {} },
      ["anchor task", "two", "three", "four"],
      "/repo",
    ) as { user_goal: string }
    expect(s.user_goal).toBe("anchor task\n---\ntwo\n---\nthree\n---\nfour")
  })

  test("call cwd, ledger, and designated destinations", () => {
    const s = buildState(
      { permission: "bash", metadata: { command: "ls", cwd: "/tmp/opencode/x", tool: "shell" } },
      ["g"],
      "/repo",
      { created: "tables created by the agent: a.b.c", designated: ["github.com"] },
    ) as { designated_destinations: string[]; action: Record<string, unknown> }
    expect(s.action.cwd).toBe("/tmp/opencode/x")
    expect(s.action.tool).toBe("bash")
    expect(s.action.tool_name).toBe("shell")
    expect(s.action.created_this_session).toBe("tables created by the agent: a.b.c")
    expect(s.designated_destinations).toEqual(["github.com"])
    // cwd is not duplicated by the metadata passthrough
    expect(Object.keys(s.action).filter((k) => k === "cwd")).toHaveLength(1)
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
