import { describe, expect, test } from "bun:test"
import { decide, staticDecision, DEFAULT_THRESHOLDS } from "../src/policy.ts"
import type { Answer } from "../src/systemone.ts"

const choice = (c: string, confidence: number, probabilities: Record<string, number> = {}): Answer => ({
  type: "choice",
  choice: c,
  confidence,
  probabilities,
})
const noul = (n: number): Answer => ({ type: "noul", noul: n })

const bash = (command: string) => ({ permission: "bash", metadata: { command } })

describe("staticDecision", () => {
  test("hard-deny: rm -rf ~/", () => {
    expect(staticDecision(bash("rm -rf ~/"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf /"))?.action).toBe("deny")
  })
  test("hard-deny: force push", () => {
    expect(staticDecision(bash("git push origin main --force"))?.action).toBe("deny")
    expect(staticDecision(bash("git push --force-with-lease"))?.action).not.toBe("deny")
  })
  test("hard-deny: fork bomb / shutdown", () => {
    expect(staticDecision(bash(":(){ :|:& };:"))?.action).toBe("deny")
    expect(staticDecision(bash("sudo shutdown -h now"))?.action).toBe("deny")
  })
  test("trivial-allow: read-only git", () => {
    expect(staticDecision(bash("git status"))?.action).toBe("allow")
    expect(staticDecision(bash("git diff --stat"))?.action).toBe("allow")
    expect(staticDecision(bash("ls -la"))?.action).toBe("allow")
    expect(staticDecision(bash("bun test"))?.action).toBe("allow")
  })
  test("trivial-allow skipped for compound commands", () => {
    expect(staticDecision(bash("git status && rm -rf /"))?.action).toBe("deny") // hard-deny wins
    expect(staticDecision(bash("ls | xargs rm"))?.action).toBeUndefined()
    expect(staticDecision(bash("cat $(rm x)"))?.action).toBeUndefined()
  })
  test("non-bash permissions are not static-decided", () => {
    expect(staticDecision({ permission: "edit", metadata: {} })).toBeUndefined()
  })
})

describe("decide", () => {
  test("confident safe + low irrev + intent match => allow", () => {
    const d = decide({
      verdict: choice("safe", 0.95),
      irreversible: noul(0.05),
      matches_intent: noul(0.9),
      exfiltration: noul(0.01),
      scope: choice("workspace", 0.9),
    })
    expect(d.action).toBe("allow")
  })

  test("confident dangerous => deny", () => {
    const d = decide({
      verdict: choice("dangerous", 0.97),
      irreversible: noul(0.9),
      matches_intent: noul(0.2),
      exfiltration: noul(0.1),
    })
    expect(d.action).toBe("deny")
  })

  test("dangerous but low confidence => ask", () => {
    const d = decide({
      verdict: choice("dangerous", 0.5),
      irreversible: noul(0.6),
      matches_intent: noul(0.3),
      exfiltration: noul(0.1),
    })
    expect(d.action).toBe("ask")
  })

  test("exfiltration above threshold denies even if otherwise safe", () => {
    const d = decide({
      verdict: choice("safe", 0.9),
      irreversible: noul(0.1),
      matches_intent: noul(0.9),
      exfiltration: noul(0.85),
    })
    expect(d.action).toBe("deny")
  })

  test("safe verdict but high irreversibility => ask", () => {
    const d = decide({
      verdict: choice("safe", 0.95),
      irreversible: noul(0.8),
      matches_intent: noul(0.9),
      exfiltration: noul(0.0),
    })
    expect(d.action).toBe("ask")
  })

  test("safe verdict but intent mismatch => ask", () => {
    const d = decide({
      verdict: choice("safe", 0.95),
      irreversible: noul(0.1),
      matches_intent: noul(0.2),
      exfiltration: noul(0.0),
    })
    expect(d.action).toBe("ask")
  })

  test("missing verdict answer degrades to ask", () => {
    expect(decide({}).action).toBe("ask")
  })

  test("missing nouls are treated conservatively (no auto-allow)", () => {
    const d = decide({ verdict: choice("safe", 0.99) })
    expect(d.action).toBe("ask") // irreversible defaults to 1, intent to 0
  })

  test("threshold boundaries", () => {
    const t = DEFAULT_THRESHOLDS
    const atSafe = decide({
      verdict: choice("safe", t.safeConfidence),
      irreversible: noul(t.irreversibleMax),
      matches_intent: noul(t.intentMin),
      exfiltration: noul(0.0),
    })
    expect(atSafe.action).toBe("allow")

    const belowSafe = decide({
      verdict: choice("safe", t.safeConfidence - 0.01),
      irreversible: noul(t.irreversibleMax),
      matches_intent: noul(t.intentMin),
      exfiltration: noul(0.0),
    })
    expect(belowSafe.action).toBe("ask")
  })
})
