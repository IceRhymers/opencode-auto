import { describe, expect, test } from "bun:test"
import {
  applyDecision,
  callIDOf,
  canonicalAction,
  evaluationToPermission,
  shouldClassify,
  type EvaluationLike,
} from "../src/adapter.ts"

const ev = (over: Partial<EvaluationLike>): EvaluationLike => ({
  action: "shell",
  resources: [],
  effect: "ask",
  ...over,
})

describe("canonicalAction", () => {
  test("maps V2 names to the internal vocabulary", () => {
    expect(canonicalAction("shell")).toBe("bash")
    expect(canonicalAction("subagent")).toBe("task")
    expect(canonicalAction("edit")).toBe("edit")
    expect(canonicalAction("external_directory")).toBe("external_directory")
  })
})

describe("callIDOf", () => {
  test("reads the id from a tool source", () => {
    expect(callIDOf(ev({ source: { type: "tool", messageID: "m", id: "c1" } }))).toBe("c1")
  })
  test("undefined without a tool source", () => {
    expect(callIDOf(ev({}))).toBeUndefined()
    expect(callIDOf(ev({ source: { type: "other", id: "c1" } }))).toBeUndefined()
  })
})

describe("shouldClassify", () => {
  const escalate = new Set(["bash", "edit", "webfetch", "external_directory"])

  test("ask is always classified", () => {
    expect(shouldClassify("ask", "shell", escalate)).toBe(true)
    expect(shouldClassify("ask", "read", escalate)).toBe(true)
  })

  test("allow is classified only for escalated actions", () => {
    expect(shouldClassify("allow", "shell", escalate)).toBe(true)
    expect(shouldClassify("allow", "edit", escalate)).toBe(true)
    expect(shouldClassify("allow", "read", escalate)).toBe(false)
    expect(shouldClassify("allow", "grep", escalate)).toBe(false)
  })

  test("deny is never classified", () => {
    expect(shouldClassify("deny", "shell", escalate)).toBe(false)
  })
})

describe("evaluationToPermission", () => {
  test("a captured command judges the call as bash, even external_directory", () => {
    const p = evaluationToPermission(
      ev({ action: "external_directory", resources: ["/Users/x/.zshrc"], metadata: {} }),
      "echo hi >> ~/.zshrc",
    )
    expect(p.permission).toBe("bash")
    expect(p.metadata?.command).toBe("echo hi >> ~/.zshrc")
    expect(p.patterns).toEqual(["/Users/x/.zshrc"])
  })

  test("shell without a command stays bash with scanner resources", () => {
    const p = evaluationToPermission(ev({ action: "shell", resources: ["git status"] }))
    expect(p.permission).toBe("bash")
    expect(p.patterns).toEqual(["git status"])
    expect(p.metadata?.command).toBeUndefined()
  })

  test("edit metadata (filepath + diff) passes through", () => {
    const p = evaluationToPermission(
      ev({ action: "edit", resources: ["src/a.ts"], metadata: { filepath: "src/a.ts", diff: "@@ -1 +1 @@\n-old\n+new" } }),
    )
    expect(p.permission).toBe("edit")
    expect(p.metadata?.filepath).toBe("src/a.ts")
    expect(p.metadata?.diff).toContain("-old")
  })
})

describe("applyDecision", () => {
  const mode = "allow-ask-deny" as const

  test("allow sets effect allow", () => {
    const e = ev({ effect: "ask" })
    applyDecision(e, { action: "allow", reason: "read-only command chain" }, { mode, dryRun: false })
    expect(e.effect).toBe("allow")
    expect(e.message).toBeUndefined()
  })

  test("allow suppressed in allow-ask mode", () => {
    const e = ev({ effect: "ask" })
    applyDecision(e, { action: "allow", reason: "x" }, { mode: "allow-ask", dryRun: false })
    expect(e.effect).toBe("ask")
  })

  test("block denies with the reason as the message", () => {
    const e = ev({ effect: "ask" })
    applyDecision(e, { action: "block", reason: "auto-jev blocked (danger); do not retry" }, { mode, dryRun: false })
    expect(e.effect).toBe("deny")
    expect(e.message).toBe("auto-jev blocked (danger); do not retry")
  })

  test("deny only applies in allow-ask-deny mode, with prefixed reason", () => {
    const e = ev({ effect: "ask" })
    applyDecision(e, { action: "deny", reason: "hard-deny rule" }, { mode, dryRun: false })
    expect(e.effect).toBe("deny")
    expect(e.message).toBe("auto-jev denied: hard-deny rule")

    const e2 = ev({ effect: "ask" })
    applyDecision(e2, { action: "deny", reason: "hard-deny rule" }, { mode: "allow-ask", dryRun: false })
    expect(e2.effect).toBe("ask")
  })

  test("ask and pause stay at the prompt with a message", () => {
    const e = ev({ effect: "allow" })
    applyDecision(e, { action: "ask", reason: "uncertain" }, { mode, dryRun: false })
    expect(e.effect).toBe("ask")
    expect(e.message).toBe("auto-jev: uncertain")

    const p = ev({ effect: "allow" })
    applyDecision(p, { action: "pause", reason: "low confidence" }, { mode, dryRun: false })
    expect(p.effect).toBe("ask")
    expect(p.message).toBe("auto-jev paused: low confidence")
  })

  test("dryRun never touches the evaluation", () => {
    const e = ev({ effect: "ask" })
    applyDecision(e, { action: "allow", reason: "x" }, { mode, dryRun: true })
    expect(e.effect).toBe("ask")
    expect(e.message).toBeUndefined()

    const b = ev({ effect: "allow" })
    applyDecision(b, { action: "block", reason: "y" }, { mode, dryRun: true })
    expect(b.effect).toBe("allow")
  })
})
