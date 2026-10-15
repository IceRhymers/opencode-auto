/**
 * Drives the plugin's setup with a fake V2 context and exercises the hook
 * wiring end to end through STATIC decisions (no model calls, no network):
 * static allow, hard-deny, block, pairing, allow-escalation, dryRun, and the
 * fail-safe error path (unreachable backend => pause).
 */
import { afterEach, describe, expect, test } from "bun:test"
import plugin from "../src/index.ts"

type Hook = (ev: never) => Promise<void> | void

const makeCtx = (options: Record<string, unknown>) => {
  const hooks: Record<string, Hook> = {}
  const ctx = {
    options,
    location: {
      directory: "/tmp/auto-jev-test",
      project: { id: "p", directory: "/tmp/auto-jev-test", canonical: "/tmp/auto-jev-test" },
    },
    session: {
      context: async () => [] as { type: string; text: string }[],
    },
    tool: {
      hook: async (name: string, cb: Hook) => {
        hooks[`tool:${name}`] = cb
        return { dispose: async () => {} }
      },
    },
    permission: {
      hook: async (name: string, cb: Hook) => {
        hooks[`permission:${name}`] = cb
        return { dispose: async () => {} }
      },
    },
  }
  return { ctx, hooks }
}

// A systemone backend with an unreachable URL: construction and warmup are
// fine (the key is only read when a token is needed), so the plugin is
// active and static decisions run; the model path fails fast.
const OPTS = { provider: "systemone", url: "http://127.0.0.1:1/systemone" }

const setup = async (options: Record<string, unknown> = OPTS) => {
  const { ctx, hooks } = makeCtx(options)
  const cleanup = await plugin.setup(ctx as never)
  return { hooks, cleanup: typeof cleanup === "function" ? cleanup : async () => {} }
}

const shellCall = (hooks: Record<string, Hook>, id: string, command: string) =>
  hooks["tool:execute.before"]({
    tool: "shell",
    sessionID: "s1",
    agent: "a",
    messageID: "m1",
    id,
    input: { command },
  } as never)

const evaluate = (
  hooks: Record<string, Hook>,
  over: Record<string, unknown>,
): { effect: string; message?: string } & Record<string, unknown> => {
  const ev: Record<string, unknown> = {
    sessionID: "s1",
    action: "shell",
    resources: [],
    effect: "ask",
    ...over,
  }
  return ev as { effect: string; message?: string } & Record<string, unknown>
}

let cleanups: (() => Promise<void> | void)[] = []
afterEach(async () => {
  for (const c of cleanups) await c()
  cleanups = []
})

describe("plugin setup (V2)", () => {
  test("static allow approves a read-only shell command", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    await shellCall(hooks, "c1", "git status")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c1" }, resources: ["git status"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("allow")
  })

  test("hard-deny rejects rm -rf / with a reason", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    await shellCall(hooks, "c2", "rm -rf /")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c2" }, resources: ["rm -rf /"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("deny")
    expect(String(ev.message)).toContain("auto-jev denied:")
  })

  test("credential exfiltration is blocked (deny + feedback message)", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    await shellCall(hooks, "c3", "env | grep TOKEN")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c3" }, resources: ["env", "grep TOKEN"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("deny")
    expect(String(ev.message)).toContain("auto-jev blocked")
  })

  test("external_directory inherits the shell decision via the call id", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    await shellCall(hooks, "c4", "cat ~/.aws/credentials")
    const src = { type: "tool", messageID: "m1", id: "c4" }
    // external_directory fires first in V2, then shell; one decision covers both.
    const ext = evaluate(hooks, { action: "external_directory", resources: ["/Users/x/.aws/credentials"], source: src })
    await hooks["permission:evaluate"](ext as never)
    expect(ext.effect).toBe("deny")
    const sh = evaluate(hooks, { resources: ["cat ~/.aws/credentials"], source: src })
    await hooks["permission:evaluate"](sh as never)
    expect(sh.effect).toBe("deny")
    expect(String(sh.message)).toContain("paired decision:")
  })

  test("allow for an escalated action is still classified", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    await shellCall(hooks, "c5", "env | grep TOKEN")
    const ev = evaluate(hooks, {
      effect: "allow",
      source: { type: "tool", messageID: "m1", id: "c5" },
      resources: ["env", "grep TOKEN"],
    })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("deny")
  })

  test("allow for a non-escalated action is left alone", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    const ev = evaluate(hooks, { action: "read", effect: "allow", resources: ["src/a.ts"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("allow")
    expect(ev.message).toBeUndefined()
  })

  test("dryRun classifies but never changes the evaluation", async () => {
    const { hooks, cleanup } = await setup({ ...OPTS, dryRun: true })
    cleanups.push(cleanup)
    await shellCall(hooks, "c6", "rm -rf /")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c6" }, resources: ["rm -rf /"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("ask")
    expect(ev.message).toBeUndefined()
  })

  test("disabled plugin leaves everything untouched", async () => {
    const { hooks, cleanup } = await setup({ ...OPTS, enabled: false })
    cleanups.push(cleanup)
    await shellCall(hooks, "c7", "rm -rf /")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c7" }, resources: ["rm -rf /"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("ask")
  })

  test("classifier error degrades to pause (unattended fail-safe)", async () => {
    const { hooks, cleanup } = await setup()
    cleanups.push(cleanup)
    // "npm install lodash" hits no static rule; the unreachable backend fails.
    await shellCall(hooks, "c8", "npm install lodash")
    const ev = evaluate(hooks, { source: { type: "tool", messageID: "m1", id: "c8" }, resources: ["npm install lodash"] })
    await hooks["permission:evaluate"](ev as never)
    expect(ev.effect).toBe("ask")
    expect(String(ev.message)).toContain("auto-jev paused: classifier error")
  }, 15000)
})
