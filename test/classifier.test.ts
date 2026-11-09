/**
 * Guards the classifier wiring: the run profile must reach the static rules
 * (a missing `unattended` flag made interactive static decisions behave like
 * unattended ones), and the session context must reach the model state.
 */
import { describe, expect, test } from "bun:test"
import { createClassifier } from "../src/classifier.ts"
import { resolveConfig } from "../src/config.ts"
import type { SystemOne } from "../src/systemone.ts"

const answers = {
  verdict: { type: "choice", choice: "safe", confidence: 0.95, probabilities: {} },
  irreversible: { type: "noul", noul: 0.05 },
  matches_intent: { type: "noul", noul: 0.95 },
  exfiltration: { type: "noul", noul: 0.01 },
}

const fake = (seen: unknown[] = []) =>
  ({
    ask: async (state: unknown) => {
      seen.push(state)
      return { model: "fake", answers }
    },
  }) as unknown as SystemOne

const make = (runProfile: "interactive" | "unattended", seen: unknown[] = []) =>
  createClassifier({
    systemone: fake(seen),
    config: resolveConfig({ runProfile, provider: "systemone", url: "http://127.0.0.1:1/x" }),
    getUserMessages: async () => ["score the floors", "User chose: drop it after checking"],
    worktree: "/repo",
    designated: () => ["github.com"],
    created: () => "tables created by the agent: main.gold.floors_verify",
  })

describe("createClassifier", () => {
  test("the run profile reaches the static rules", async () => {
    const input = { sessionID: "s", permission: "bash", metadata: { command: "rm -rf ./dist" } }
    expect((await make("interactive")(input)).action).toBe("ask")
    expect((await make("unattended")(input)).action).toBe("pause")
  })

  test("model state carries goal, ledger, designated destinations, and cwd", async () => {
    const seen: unknown[] = []
    const r = await make("unattended", seen)({
      sessionID: "s",
      permission: "bash",
      metadata: { command: "npm install lodash", cwd: "/repo/app", tool: "shell" },
    })
    expect(r.source).toBe("model")
    expect(r.action).toBe("allow")
    expect(r.answers).toEqual(answers as never)
    const state = seen[0] as Record<string, unknown> & { action: Record<string, unknown> }
    expect(state.user_goal).toContain("User chose: drop it after checking")
    expect(state.designated_destinations).toEqual(["github.com"])
    expect(state.action.created_this_session).toContain("main.gold.floors_verify")
    expect(state.action.cwd).toBe("/repo/app")
    expect(state.action.tool).toBe("bash")
  })
})
