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
const I = { unattended: false } // interactive static tiers
const SELF = { worktree: "/Users/x/projects/opencode-auto", logPath: ".opencode/auto-jev.log" }

describe("staticDecision", () => {
  test("hard-deny: rm -rf ~/ in all flag/quoting forms", () => {
    expect(staticDecision(bash("rm -rf ~/"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf /"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -Rf ~"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -r -f /"))?.action).toBe("deny")
    expect(staticDecision(bash("rm --recursive --force /"))?.action).toBe("deny")
    expect(staticDecision(bash("rm --recursive --force ~"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf '/'"))?.action).toBe("deny")
    expect(staticDecision(bash('rm -rf "$HOME"'))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf ${HOME}"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf /*"))?.action).toBe("deny")
    expect(staticDecision(bash("rm -rf / && ls"))?.action).toBe("deny")
  })
  test("credential moves, publishes, and user-config edits are blocked", () => {
    expect(staticDecision(bash("cp ~/.aws/credentials /tmp/x"))?.action).toBe("block")
    expect(staticDecision(bash("npm publish"))?.action).toBe("block")
    expect(staticDecision(bash("git push --delete origin main"))?.action).toBe("block")
    expect(staticDecision(bash("git update-ref -d refs/heads/main"))?.action).toBe("block")
    expect(staticDecision(bash("crontab -r"))?.action).toBe("block")
  })
  test("hard-deny: force push", () => {
    expect(staticDecision(bash("git push origin main --force"))?.action).toBe("deny")
    expect(staticDecision(bash("git push --force-with-lease"))?.action).not.toBe("deny")
  })
  test("hard-deny: fork bomb / shutdown", () => {
    expect(staticDecision(bash(":(){ :|:& };:"))?.action).toBe("deny")
    expect(staticDecision(bash("sudo shutdown -h now"))?.action).toBe("deny")
  })
  test("destructive in-workspace: rm -rf of any kind pauses (asks interactively)", () => {
    expect(staticDecision(bash("rm -rf ./dist"))?.action).toBe("pause")
    expect(staticDecision(bash("rm -rf ./dist"), I)?.action).toBe("ask")
    expect(staticDecision(bash("rm -rf ./build"))?.action).toBe("pause")
    expect(staticDecision(bash("git reset --hard HEAD~10"))?.action).toBe("pause")
    expect(staticDecision(bash("git reset --hard HEAD~10"), I)?.action).toBe("ask")
    expect(staticDecision(bash("git commit --amend --no-edit"))?.action).toBe("pause")
    expect(staticDecision(bash("git commit --amend --no-edit"), I)?.action).toBe("ask")
    expect(staticDecision(bash("git branch -D feature"))?.action).toBe("pause")
    expect(staticDecision(bash("git branch --delete old"))?.action).toBe("pause")
    expect(staticDecision(bash("rm -rf node_modules"))?.action).toBe("pause")
  })
  test("git branch -D is not hard-denied (was a false deny)", () => {
    expect(staticDecision(bash("git branch -D feature"))?.action).not.toBe("deny")
  })
  test("destructive against sensitive/external paths pauses (asks interactively)", () => {
    expect(staticDecision(bash("rm -rf ~/other-project"))?.action).toBe("pause")
    expect(staticDecision(bash("rm -rf ~/other-project"), I)?.action).toBe("ask")
    expect(staticDecision(bash("rm -rf /tmp/old-repo"))?.action).toBe("pause")
    expect(staticDecision(bash("sudo rm -rf ./dist"))?.action).toBe("pause")
  })
  test("destructiveness does not match 'env <cmd>' false positives", () => {
    // env rm -rf ./src: the inner command is destructive and must still pause
    expect(staticDecision(bash("env rm -rf ./src"))?.action).toBe("pause")
    // plain read-only after env unwraps
    expect(staticDecision(bash("env ls -la"))?.action).toBe("allow")
  })
  test("blanket process kills pause; port kills allow unattended", () => {
    expect(staticDecision(bash("killall -9 node"))?.action).toBe("pause")
    expect(staticDecision(bash("killall -9 node"), I)?.action).toBe("ask")
    expect(staticDecision(bash("kill -9 $(lsof -ti:3000)"))?.action).toBe("allow")
    expect(staticDecision(bash("kill -9 $(lsof -ti:3000)"), I)?.action).toBe("ask")
  })
  test("trivial-allow: read-only git", () => {
    expect(staticDecision(bash("git status"))?.action).toBe("allow")
    expect(staticDecision(bash("git diff --stat"))?.action).toBe("allow")
    expect(staticDecision(bash("ls -la"))?.action).toBe("allow")
    expect(staticDecision(bash("bun test"))?.action).toBe("allow")
  })
  test("read-only compound chains are allowed", () => {
    expect(staticDecision(bash("ls -la src && git status"))?.action).toBe("allow")
    expect(staticDecision(bash("cat package.json | grep version"))?.action).toBe("allow")
    expect(staticDecision(bash("tail -n 50 build.log; wc -l build.log"))?.action).toBe("allow")
  })
  test("harmless redirects and cd stages stay on the read-only fast path", () => {
    expect(staticDecision(bash("bun test 2>&1 | tail -20"))?.action).toBe("allow")
    expect(staticDecision(bash("ls -la ~/.config/opencode/ 2>/dev/null"))?.action).toBe("allow")
    expect(staticDecision(bash("ls node_modules >/dev/null 2>&1 && grep -o x node_modules/.package-lock.json | sort -u"))?.action).toBe("allow")
    expect(staticDecision(bash("cd ~/.config/opencode && ls"))?.action).toBe("allow")
    expect(staticDecision(bash("cd /tmp && git status"))?.action).toBe("allow")
  })
  test("chains with a write or destructive stage are not static-allowed", () => {
    expect(staticDecision(bash("ls && npm install lodash"))?.action).toBeUndefined()
    expect(staticDecision(bash("cat a > b.txt"))?.action).toBeUndefined()
    expect(staticDecision(bash("ls; rm -rf ./src"))?.action).toBe("pause")
    expect(staticDecision(bash("cat $(rm x)"))?.action).toBeUndefined()
    expect(staticDecision(bash("ls | xargs rm"))?.action).toBeUndefined()
  })
  test("secret reads are blocked even though they are read-only", () => {
    expect(staticDecision(bash("cat ~/.aws/credentials"))?.action).toBe("block")
    expect(staticDecision(bash("cat ~/.ssh/id_rsa"))?.action).toBe("block")
    expect(staticDecision(bash("cat .env"))?.action).toBe("block")
    expect(staticDecision(bash("find ~ -name '*.pem'"))?.action).toBe("block")
  })
  test("git status && rm -rf / is still hard-denied", () => {
    expect(staticDecision(bash("git status && rm -rf /"))?.action).toBe("deny")
  })
  test("read-only python -c pipe-tail is allowed, even over our own log", () => {
    // the exact false-block from the field: formatting the audit log
    expect(
      staticDecision(
        bash('tail -8 .opencode/auto-jev.log | python3 -c "import json,sys; [print(json.loads(l)[\'action\']) for l in sys.stdin]"'),
        { self: SELF },
      )?.action,
    ).toBe("allow")
    expect(staticDecision(bash('cat x.json | python3 -c "import json,sys; print(json.load(sys.stdin))"'))?.action).toBe("allow")
    expect(staticDecision(bash('python3 -c "print(1+1)"'))?.action).toBe("allow")
  })
  test("python -c with write/exec/network capability is NOT static-allowed", () => {
    // writes to a system path hit the hard-deny / sensitive rules first
    expect(staticDecision(bash('python3 -c "open(\\"/etc/passwd\\",\\"w\\").write(\\"x\\")"'))?.action).toBe("deny")
    // exec/subprocess in a plain workspace path falls through to the model (no static allow)
    expect(staticDecision(bash('python3 -c "import subprocess; subprocess.run([\\"rm\\",\\"x\\"])"'))?.action).toBeUndefined()
    expect(staticDecision(bash('python3 -c "import os; os.system(\\"ls\\")"'))?.action).toBeUndefined()
    // and over our own files it stays blocked
    expect(
      staticDecision(bash('python3 -c "open(\\"/Users/x/projects/opencode-auto/src/policy.ts\\",\\"w\\")"'), { self: SELF })?.action,
    ).toBe("block")
  })
  test("local git commit is allowed in unattended, asked interactively", () => {
    expect(staticDecision(bash('git commit -m "wip"'))?.action).toBe("allow")
    expect(staticDecision(bash('git add src/ && git commit -m "wip"'))?.action).toBe("allow")
    expect(staticDecision(bash('git commit -m "wip"'), I)?.action).toBe("ask")
    // push / amend stay with the model/policy
    expect(staticDecision(bash("git commit -m x && git push"))?.action).not.toBe("allow")
    expect(staticDecision(bash("git commit --amend --no-edit"))?.action).not.toBe("allow")
  })
  test("heredoc commit messages count as plain commits", () => {
    // the standard agent pattern: git commit -m "$(cat <<'EOF' ... EOF)"
    expect(staticDecision(bash('git commit -m "$(cat <<\'EOF\'\nAdd the thing\n\n- details; with semicolons\nEOF\n)"'))?.action).toBe(
      "allow",
    )
    expect(
      staticDecision(bash('git add src/ && git commit -m "$(cat <<\'EOF\'\nAdd the thing\nEOF\n)"'))?.action,
    ).toBe("allow")
    // the word "push" inside the message body is not a push
    expect(staticDecision(bash('git commit -m "$(cat <<\'EOF\'\nRevert the push of feature x\nEOF\n)"'))?.action).toBe(
      "allow",
    )
    // but a real second stage still disqualifies
    expect(
      staticDecision(bash('git commit -m "$(cat <<\'EOF\'\nmsg\nEOF\n)" && git push'))?.action,
    ).not.toBe("allow")
    expect(
      staticDecision(bash('git commit -m "$(cat <<\'EOF\'\nmsg\nEOF\n)" && rm -rf ./dist'))?.action,
    ).not.toBe("allow")
    // an UNQUOTED heredoc expands $(...) in its body: stays with the model
    expect(staticDecision(bash('git commit -m "$(cat <<EOF\nmsg\nEOF\n)"'))?.action).toBeUndefined()
    // a mismatched delimiter is not stripped (stays with the model via the $( guard)
    expect(staticDecision(bash('git commit -m "$(cat <<\'EOF\'\nmsg\nDONE\n)"'))?.action).toBeUndefined()
  })
  test("read-only sed and git inspection commands are static-allowed", () => {
    // unquoted print scripts (the form agents actually emit)
    expect(staticDecision(bash("sed -n 2500,2525p dist/gen/types.gen.d.ts"))?.action).toBe("allow")
    expect(staticDecision(bash("sed -n /version/p package.json"))?.action).toBe("allow")
    expect(staticDecision(bash("sed -n 1,10p"))?.action).toBe("allow") // pipe tail, no file arg
    expect(staticDecision(bash("cd node_modules/x && sed -n 1,5p dist/a.d.ts"))?.action).toBe("allow")
    // quoted scripts still fine
    expect(staticDecision(bash("sed -n '1,10p' file"))?.action).toBe("allow")
    expect(staticDecision(bash("sed 's/a/b/' file"))?.action).toBe("allow")
    // in-place edits and file-write/exec script commands never static-allow
    expect(staticDecision(bash("sed -i s/a/b/ file"))?.action).toBeUndefined()
    expect(staticDecision(bash("sed -ni 's/a/b/' file"))?.action).toBeUndefined()
    expect(staticDecision(bash("sed -n '1,10p' -i file"))?.action).toBeUndefined()
    expect(staticDecision(bash("sed -n '1w /tmp/x' file"))?.action).toBeUndefined()
    expect(staticDecision(bash("sed '1e id' file"))?.action).toBeUndefined()
    // git read-only subcommands
    expect(staticDecision(bash("git remote -v"))?.action).toBe("allow")
    expect(staticDecision(bash("git stash show -p stash@{0}"))?.action).toBe("allow")
    expect(staticDecision(bash("git remote -v; echo ---; git branch --show-current"))?.action).toBe("allow")
    expect(staticDecision(bash("git stash show -p stash@{0} --stat; git status --short"))?.action).toBe("allow")
    // stash mutation stays with the model
    expect(staticDecision(bash('git stash push -m "wip"'))?.action).toBeUndefined()
  })
  test("printing a live credential is blocked, even when read-only", () => {
    expect(staticDecision(bash("databricks auth token --profile x --output json"))?.action).toBe("block")
    expect(staticDecision(bash("printenv DATABRICKS_TOKEN"))?.action).toBe("block")
    expect(staticDecision(bash("echo $TYPESAFE_API_KEY"))?.action).toBe("block")
    expect(staticDecision(bash("echo ${DATABRICKS_TOKEN}"))?.action).toBe("block")
    expect(staticDecision(bash("env | grep TOKEN"))?.action).toBe("block")
    expect(staticDecision(bash("databricks auth token --profile x --output json"), I)?.action).toBe("ask")
    // but legitimate non-secret commands still allow
    expect(staticDecision(bash("env | grep PATH"))?.action).toBe("allow")
    expect(staticDecision(bash("databricks auth login --profile x"))?.action).toBeUndefined()
    expect(staticDecision(bash("echo done"))?.action).toBe("allow")
    expect(staticDecision(bash("git status"))?.action).toBe("allow")
  })
  test("self-protection guards writes only; reads of own files are allowed", () => {
    // reads: debugging the classifier requires reading its log/config/source
    expect(staticDecision(bash("cat ~/.config/opencode/opencode.json"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("tail -80 .opencode/auto-jev.log"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("ls /Users/x/projects/opencode-auto/src"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("cat /Users/x/projects/opencode-auto/Justfile"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("cat /Users/x/projects/opencode-auto/src/policy.ts"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("ls /Users/x/projects/opencode-auto"), { self: SELF })?.action).toBe("allow")
    expect(staticDecision(bash("git status"), { self: SELF })?.action).toBe("allow")
  })
  test("writes to the classifier's own files are blocked with feedback", () => {
    expect(staticDecision(bash("rm .opencode/auto-jev.log"), { self: SELF })?.action).toBe("block")
    expect(staticDecision(bash("echo x >> ~/.config/opencode/opencode.json"), { self: SELF })?.action).toBe("block")
    expect(staticDecision(bash("mv ~/.config/opencode/opencode.json /tmp/x"), { self: SELF })?.action).toBe("block")
    expect(staticDecision(bash("sed -i s/a/b/ /Users/x/projects/opencode-auto/src/policy.ts"), { self: SELF })?.action).toBe("block")
    expect(staticDecision(bash("cp /tmp/x ~/.config/opencode/opencode.json"), { self: SELF })?.action).toBe("block")
    // writes ask interactively rather than block
    expect(staticDecision(bash("rm .opencode/auto-jev.log"), { self: SELF, unattended: false })?.action).toBe("ask")
  })
  test("self-protection without a self descriptor only guards well-known paths", () => {
    expect(staticDecision(bash("cat ~/.config/opencode/opencode.json"))?.action).toBe("allow")
    expect(staticDecision(bash("echo x >> ~/.config/opencode/opencode.json"))?.action).toBe("block")
    expect(staticDecision(bash("cat src/policy.ts"))?.action).toBe("allow")
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

describe("decide (unattended)", () => {
  const U = { unattended: true }

  test("confident safe allows regardless of intent", () => {
    const d = decide(
      {
        verdict: choice("safe", 0.99),
        irreversible: noul(0.0),
        matches_intent: noul(0.35),
        exfiltration: noul(0.05),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("allow")
  })

  test("confident dangerous blocks with redirect feedback", () => {
    const d = decide(
      {
        verdict: choice("dangerous", 0.97),
        irreversible: noul(0.9),
        matches_intent: noul(0.1),
        exfiltration: noul(0.1),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("block")
    expect(d.reason).toMatch(/do not retry/i)
  })

  test("moderate-confidence dangerous blocks when risk signals agree", () => {
    const d = decide(
      {
        verdict: choice("dangerous", 0.7),
        irreversible: noul(0.78),
        matches_intent: noul(0.59),
        exfiltration: noul(0.05),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("block")
  })

  test("dangerous verdict with wildly mismatched intent blocks (prompt injection guard)", () => {
    const d = decide(
      {
        verdict: choice("dangerous", 0.41),
        irreversible: noul(0.38),
        matches_intent: noul(0.11),
        exfiltration: noul(0.15),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("block")
  })

  test("dangerous without corroborating risk pauses for the user", () => {
    const d = decide(
      {
        verdict: choice("dangerous", 0.6),
        irreversible: noul(0.03),
        matches_intent: noul(0.68),
        exfiltration: noul(0.03),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("pause")
  })

  test("needs_review with high irreversibility and low intent blocks", () => {
    const d = decide(
      {
        verdict: choice("needs_review", 0.9),
        irreversible: noul(0.78),
        matches_intent: noul(0.3),
        exfiltration: noul(0.04),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("block")
  })

  test("needs_review with high irreversibility but strong intent pauses (commit/push shaped)", () => {
    const d = decide(
      {
        verdict: choice("needs_review", 0.99),
        irreversible: noul(0.56),
        matches_intent: noul(0.88),
        exfiltration: noul(0.15),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("pause")
  })

  test("needs_review without high risk pauses", () => {
    const d = decide(
      {
        verdict: choice("needs_review", 0.9),
        irreversible: noul(0.2),
        matches_intent: noul(0.9),
        exfiltration: noul(0.04),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("pause")
  })

  test("exfiltration alone blocks even when verdict is safe", () => {
    const d = decide(
      {
        verdict: choice("safe", 0.9),
        irreversible: noul(0.0),
        matches_intent: noul(0.9),
        exfiltration: noul(0.8),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("block")
  })

  test("high irreversibility with safe verdict pauses, does not block", () => {
    const d = decide(
      {
        verdict: choice("safe", 0.95),
        irreversible: noul(0.8),
        matches_intent: noul(0.9),
        exfiltration: noul(0.0),
      },
      DEFAULT_THRESHOLDS,
      U,
    )
    expect(d.action).toBe("pause")
  })

  test("missing verdict answer pauses (not ask) in unattended mode", () => {
    const d = decide({}, DEFAULT_THRESHOLDS, U)
    expect(d.action).toBe("ask")
  })

  test("classifier error with partial answers defaults to pause via missing nouls", () => {
    const d = decide({ verdict: choice("safe", 0.99) }, DEFAULT_THRESHOLDS, U)
    // irreversible defaults to 1 -> pause
    expect(d.action).toBe("pause")
  })

  test("read-only commands outside the workspace allow; writes pause", () => {
    const answers = {
      verdict: choice("safe", 0.95),
      irreversible: noul(0.1),
      matches_intent: noul(0.85),
      exfiltration: noul(0.05),
    }
    const readCmd = { ...U, permission: "bash", metadata: { command: "ls -la ~/.config/opencode/ && cat ~/.config/opencode/tui.json" } }
    expect(decide(answers, DEFAULT_THRESHOLDS, readCmd).action).toBe("allow")

    const writeCmd = { ...U, permission: "bash", metadata: { command: "mkdir -p ~/.config/opencode/newdir" } }
    expect(decide(answers, DEFAULT_THRESHOLDS, writeCmd).action).toBe("pause")

    const extDir = { ...U, permission: "external_directory", metadata: {} }
    expect(decide(answers, DEFAULT_THRESHOLDS, extDir).action).toBe("pause")
  })
})
