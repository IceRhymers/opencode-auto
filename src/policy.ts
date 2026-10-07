/**
 * Decision policy: static fast-path rules + threshold logic over the SystemOne
 * answers. Pure functions, fully unit-tested. The plugin feeds it a permission
 * and the classifier's answers; it returns a Decision.
 *
 * Decision levels form a ladder:
 *   allow  -> execute without prompting
 *   ask    -> leave the normal OpenCode approval prompt (interactive profile)
 *   block  -> reject with feedback; the agent reads the reason and redirects
 *             to a safer approach (unattended profile only)
 *   pause  -> leave the prompt; the run stalls until the user returns
 *             (unattended profile only)
 */
import type { Answer } from "./systemone.js"

export type Decision =
  | { action: "allow"; reason: string }
  | { action: "ask"; reason: string }
  | { action: "deny"; reason: string }
  | { action: "block"; reason: string }
  | { action: "pause"; reason: string }

export type Tier = "allow" | "ask" | "block" | "pause"

export type Thresholds = {
  /** confidence on verdict=safe required to auto-allow */
  safeConfidence: number
  /** max irreversible probability tolerated for auto-allow */
  irreversibleMax: number
  /** min matches_intent probability for auto-allow */
  intentMin: number
  /** confidence on verdict=dangerous required to auto-deny */
  dangerousConfidence: number
  /** exfiltration probability above this auto-denies */
  exfiltrationMax: number
}

/** The paths the classifier itself depends on. */
export type SelfPaths = { worktree: string; logPath: string }

export const DEFAULT_THRESHOLDS: Thresholds = {
  // Tuned against eval/corpus.ts via the live endpoint. safeConfidence 0.80
  // recovers genuinely-safe read-only calls that sit at 0.75-0.84 confidence;
  // dangerousConfidence stays strict at 0.90 because auto-deny must be
  // conservative (uncertain dangerous degrades to ask for a human).
  safeConfidence: 0.8,
  irreversibleMax: 0.3,
  intentMin: 0.6,
  dangerousConfidence: 0.9,
  exfiltrationMax: 0.8,
}

/** Paths that are sensitive no matter the state of the session. */
const SENSITIVE_PATHS: RegExp[] = [
  /\/etc\/(passwd|shadow|sudoers)/,
  /~/,
  /\$HOME\b/,
  /(^|\s|["'(])\/etc\//,
  /(^|\s|["'(])\/(usr|bin|sbin|System|Library|var)\//,
  /(^|\s|["'(])\/boot\b/,
  /(^|\s|["'(])\/dev\//,
  /(^|\s|["'(])\/System\//,
  /\.(ssh|aws|gnupg|kube|docker)\b/,
  /\.env\b/,
  /(^|\s|["'(])\/[a-zA-Z0-9_.-]/, // absolute path outside home (macOS/Linux)
]

/** Reading any of these is itself a risk (secrets), independent of writes. */
const SECRET_READ: RegExp[] = [
  /\.(ssh|aws|gnupg|kube|docker)\b/,
  /\.env\b/,
  /\/etc\/(passwd|shadow|sudoers)/,
  /\.(pem|key|p12|pfx)\b/,
  /\bid_(rsa|ed25519|ecdsa|dsa)\b/,
]

/** Where a destructive command lands. */
type Target = "root" | "sensitive" | "external" | "workspace"

export function destructiveness(cmd: string): { level: "none" | "possible" | "destructive"; target: Target } {
  let destructive = false
  let target: Target = "workspace"

  // rm with any recursive/force flag combination, short or long form. \brm handles "sudo rm".
  if (/\brm\s+-[a-zA-Z]*[rf]/.test(cmd)) destructive = true
  if (/\brm\s+--(recursive|force)\b/.test(cmd)) destructive = true
  if (/\brm\s+(-[a-zA-Z]+\s+)+/.test(cmd)) {
    // split short flags: every flag letter group must consist of rf-letters only,
    // and both r and f must appear across groups (rm -r -f /)
    const groups = cmd.match(/\brm\s+((?:-[a-zA-Z]+\s+)+)/)
    if (groups) {
      const letters = groups[1].replace(/[-\s]/g, "")
      if (/^[rf]+$/.test(letters) && /r/.test(letters) && /f/.test(letters)) destructive = true
    }
  }

  // git branch deletion, both spellings
  if (/\bgit\s+branch\b[^|;&]*(\s-[a-zA-Z]*[dD][a-zA-Z]*|--delete)/.test(cmd)) destructive = true

  // git reset --hard
  if (/\bgit\s+reset\b[^|;&]*\s--hard\b/.test(cmd)) destructive = true

  if (!destructive) return { level: "none", target: "workspace" }

  // rm of / or ~ in any flag/quoting form. Covers -rf, -r -f, --recursive
  // --force, extra spaces, and quoted targets.
  const rmOfRoot =
    /\brm\s+(?:-{1,2}[a-zA-Z-]+\s+)*["']?\s*~?\s*\/["']?\s*([;&|]|$)/.test(cmd) ||
    /\brm\s+(?:-{1,2}[a-zA-Z-]+\s+)*["']?\s*~\s*\/?\s*["']?\s*([;&|]|$)/.test(cmd)
  if (/\brm\b/.test(cmd) && rmOfRoot) return { level: "destructive", target: "root" }
  // $HOME / ${HOME} as the rm target is home; also anything resolving to /*
  if (/\brm\s+(?:-{1,2}[a-zA-Z-]+\s+)*["']?\s*\$\{?HOME\}?["']?\s*([;&|]|$)/.test(cmd)) return { level: "destructive", target: "root" }
  if (/\brm\s+(?:-{1,2}[a-zA-Z-]+\s+)*["']?\s*\/\*/.test(cmd)) return { level: "destructive", target: "root" }

  if (/\bsudo\b/.test(cmd)) target = "sensitive"
  else if (SENSITIVE_PATHS.some((re) => re.test(cmd))) target = "sensitive"
  return { level: "destructive", target }
}

function classifyKill(cmd: string): "killall" | "port" | "ordinary" | "none" {
  // kill -9 $(lsof -ti:PORT): free a dev server, routine in long sessions
  if (/\bkill(all)?\s+(-[a-zA-Z0-9]+\s+)*\$\(lsof\s+-ti:\d+\)/.test(cmd)) return "port"
  // blanket kill of every process with a name (killall -9 node, pkill -9 python)
  if (/\b(killall|pkill)\s+(-[a-zA-Z0-9]+\s+)+[a-zA-Z]/.test(cmd)) return "killall"
  if (/\bkill(all|pkill)?\b/.test(cmd)) return "ordinary"
  return "none"
}

/** Commands that are always denied without consulting the model. */
const HARD_DENY: RegExp[] = [
  /\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+"?~?\/?"\s*([;&|]|$)/, // rm -rf / or ~/
  /\bmkfs\b/,
  /\bdd\s+.*of=\/dev\//,
  /:\(\)\{\s*:\|:&\s*\};:/, // fork bomb
  /\bshutdown\b|\breboot\b|\bhalt\b/,
  /\bgit\s+push\b[^|]*\s--force(?!-with-lease)/,
  /\/etc\/(passwd|shadow|sudoers)/,
]

/** Read-only commands that are always allowed without the model. */
const TRIVIAL_ALLOW: RegExp[] = [
  /^(git\s+(status|diff|log|show|branch|rev-parse|blame|fetch|describe|tag|stash\s+list|worktree\s+list))\b/,
  /^(ls|pwd|echo|cat|head|tail|wc|which|whoami|date|env|file|stat|du|df|rg|grep|sort|uniq|cut|tr)\b/,
  /^find\b(?!.*\s-(delete|exec|ok)\b)/,
  /^sed\s+(-[a-zA-Z]*\s+)*(['"])[^'"]*\2(?!.*\s-i\b)/,
  /^awk\b/,
  /^(bun|npm|pnpm|yarn)\s+(test|run\s+test|run\s+(build|typecheck|lint|check))\b/,
  /^(tsc|bun\s+x\s+tsc|bunx\s+tsc|npx\s+tsc)\b.*--noEmit/,
  /^(python3?|uv)\s+(-m\s+)?(pytest|unittest|ruff\s+check|mypy)\b/,
  /^(go\s+(test|build|vet)|cargo\s+(test|build|check)|make(\s+\w+)?|just\s+\w+)\b/,
  /^(docker\s+(ps|logs|images)|kubectl\s+get)\b/,
  /^(node|deno|bun|python3?|pip3?|uv|ruby|go|rustc|cargo|java|javac)\s+(-v|--version|version)\s*$/,
]

function bashCommand(p: { permission: string; metadata?: Record<string, unknown> }): string {
  return typeof p.metadata?.command === "string" ? p.metadata.command.trim() : ""
}

/**
 * True when the command references the classifier's own project: its install
 * entry points, config home, source tree, or audit log. READS of these are
 * fine (debugging the classifier requires them); only WRITE-shaped commands
 * are blocked (see selfWrite below).
 */
export function isSelfTargeting(cmd: string, self?: SelfPaths): boolean {
  if (/~\/\.config\/opencode\/opencode\.jsonc?/.test(cmd)) return true
  if (/opencode-auto\/(src|Justfile|install\.py)/.test(cmd)) return true
  if (!self) return false
  const w = self.worktree.replace(/\/$/, "")
  return cmd.includes(`${w}/src`) || cmd.includes(`${w}/Justfile`) || cmd.includes(`${w}/install.py`) || cmd.includes(self.logPath)
}

/**
 * Write-shaped commands aimed at the classifier's own files: explicit writes
 * (rm/mv/cp-into/chmod), in-place edits, redirects into the file, and running
 * the installer (which mutates opencode.json). Read-only chains are never
 * blocked by self-protection, even when they read the log or the config.
 */
function selfWrite(cmd: string, self?: SelfPaths): boolean {
  if (!isSelfTargeting(cmd, self)) return false
  if (/\$\(|`/.test(cmd)) return true // substitution may execute anything
  if (readOnlyChain(cmd)) return false
  const stages = cmd
    .split(/&&|\|\||;|\|/)
    .map((s) => s.trim())
    .filter(Boolean)
  // Leading-token write tools (a match must start the stage, so "grep ...
  // opencode.json" or "tail .../install.log" is not a write), in-place edit
  // flags, and redirects.
  const LEAD_WRITE =
    /^(sudo\s+)?(rm|mv|cp|chmod|chown|chgrp|touch|ln|mkdir|rmdir|tee|patch|truncate|shred|dd|install|rsync|scp|git|vim?|nvim|nano|emacs|code|open|python3?|uv|just|make|npm|pnpm|yarn|bun|deno)\b/
  const IN_PLACE = /\b(sed|perl|awk)\b[^|;&]*\s-i\b|\b(sed|perl)\b[^|;&]*\s-i\./
  return stages.some((s) => LEAD_WRITE.test(s) || IN_PLACE.test(s) || /(^|\s)>>?\s*[^\s&|]/.test(s))
}

/**
 * True when every pipeline/list stage in the command is individually
 * read-only. Command substitution ($(...) / `...`) is excluded: its contents
 * are executed and can't be statically classified as read-only.
 *
 * Harmless redirections (stderr merge, /dev/null sinks) are ignored; a
 * redirect to a real file disqualifies. A `cd <path>` stage is allowed: it
 * only sets the location for the following stages, which are still
 * classified on their own.
 */
export function readOnlyChain(cmd: string): boolean {
  if (/\$\(|`/.test(cmd)) return false
  const stages = cmd
    .split(/&&|\|\||;|\|/)
    .map((s) => s.trim())
    .filter((s) => s && !/^(true|false)$/.test(s))
  if (!stages.length) return false
  return stages.every((stage) => {
    // strip no-op redirections: 2>&1, N>/dev/null, &>/dev/null
    const s = stage
      .replace(/\d*>&\d+/g, "")
      .replace(/&?>>?\s*\/dev\/null\b/g, "")
      .trim()
    if (/[<>]/.test(s)) return false // any remaining redirection writes
    if (/^cd\b/.test(s)) return true // pure location change; other stages are checked
    if (/^(curl|wget)\b/.test(s)) {
      // only a plain GET: safe flags, a URL, no data/output/upload flags
      if (/\s(-X|--request)\s*(POST|PUT|DELETE|PATCH)\b/i.test(s)) return false
      if (/\s(-d|--data|--data-binary|--data-raw|-T|--upload-file|-F|--form|-o|--output|-O|--remote-name)\b/.test(s)) return false
      if (/\s--?(url)\b/.test(s) === false && !/https?:\/\//.test(s)) return false
      return /^[\w\s:./?&=%@+~,'-]*$/.test(s)
    }
    return TRIVIAL_ALLOW.some((re) => re.test(s))
  })
}

/** Static rules short-circuit the model. Returns undefined when no rule hits. */
export function staticDecision(
  p: { permission: string; metadata?: Record<string, unknown> },
  opts?: { cwd?: string; self?: SelfPaths; unattended?: boolean },
): Decision | undefined {
  if (p.permission !== "bash") return undefined
  const cmd = bashCommand(p)
  if (!cmd) return undefined

  const interactive = opts?.unattended === false

  for (const re of HARD_DENY) {
    if (re.test(cmd)) return { action: "deny", reason: `hard-deny rule: ${re.source}` }
  }

  // Self-protection blocks WRITES to the classifier's own files (config,
  // source, audit log, installer). Reads fall through to the normal rules,
  // so debugging the classifier (tail the log, grep the config) is allowed.
  if (selfWrite(cmd, opts?.self)) {
    return interactive
      ? { action: "ask", reason: "writes to the classifier's own config/source/log; confirm" }
      : {
          action: "block",
          reason:
            "auto-jev blocked (writes to the classifier's own config/source/log); do not retry. Configure opencode-auto directly or ask the user.",
        }
  }

  // env <cmd>: the command after env still runs; classify it too. An allow
  // here is impossible because env itself is in TRIVIAL_ALLOW, so any rule
  // below that matches the inner command decides.
  const inner = cmd.replace(/^env\s+/, "")
  if (inner !== cmd) {
    const d = staticDecision({ permission: "bash", metadata: { command: inner } }, opts)
    if (d && d.action !== "allow") return d
  }

  const kill = classifyKill(cmd)
  if (kill === "killall") return { action: interactive ? "ask" : "pause", reason: "kills every process with a given name" }
  if (kill === "port") return { action: interactive ? "ask" : "allow", reason: "frees a dev server by port" }
  if (kill === "ordinary") return { action: interactive ? "ask" : "pause", reason: "kills a process by id" }

  // Writes/deletes aimed at obvious secret stores, shared refs, or user-level
  // system config are never model-decided.
  if (/\bcp\b[^|;&]*~\/\.(aws|ssh|gnupg)/.test(cmd) || /\bcp\b[^|;&]*\.(pem|key|p12|pfx)\b/.test(cmd)) {
    return interactive
      ? { action: "ask", reason: "copies credentials; confirm" }
      : { action: "block", reason: "copies credentials; the agent should not move secrets around" }
  }
  if (/\b(npm|yarn|pnpm|bun)\s+publish\b|\bgit\s+push\b[^|]*\s--delete\b|\bgit\s+update-ref\s+-d\b/.test(cmd)) {
    return { action: interactive ? "ask" : "block", reason: "publishes or deletes shared refs; needs the user" }
  }
  if (/\b(crontab\s+-r|launchctl\s+(un)load|defaults\s+delete)\b/.test(cmd)) {
    return { action: interactive ? "ask" : "block", reason: "alters user-level system config" }
  }

  // Deleting the dependency dir is always worth a human glance even when it
  // lands "inside" the project.
  if (/\brm\s+-[a-zA-Z]*[rf]/.test(cmd) && /(^|\s)\.?\/?node_modules\/?\s*([;&|]|$)/.test(cmd)) {
    return { action: interactive ? "ask" : "pause", reason: "removes node_modules (clean reinstall); confirm" }
  }
  if (/\brm\s+-[a-zA-Z]*[rf]/.test(cmd) && /(^|\s)\.?\/?(dist|build|out|coverage|target)\/?\s*([;&|]|$)/.test(cmd)) {
    // rm -rf of a conventional build-output directory only, in-workspace.
    // Deleting it is destructive to anything not yet rebuilt, so it pauses
    // in both profiles; the agent can rebuild after confirmation.
    if (/\bsudo\b/.test(cmd)) return { action: interactive ? "ask" : "pause", reason: "destructive command under sudo" }
    return { action: interactive ? "ask" : "pause", reason: "removes a build output directory (rm -rf dist/build/...); confirm" }
  }

  const d = destructiveness(cmd)
  if (d.level === "destructive") {
    if (d.target === "root") return { action: "deny", reason: "rm -rf of filesystem root or home" }
    if (d.target === "sensitive") {
      return { action: interactive ? "ask" : "pause", reason: "destructive command touches a sensitive path" }
    }
    return { action: interactive ? "ask" : "pause", reason: "destructive in-workspace change (rm -rf / git branch -D / git reset --hard)" }
  }

  if (readOnlyChain(cmd)) {
    // Reads that expose secrets are never static-allowed, even though the
    // command itself is read-only. Interactive keeps it at the prompt.
    if (SECRET_READ.some((re) => re.test(cmd))) {
      return interactive
        ? { action: "ask", reason: "reads secrets or credentials; confirm exposure" }
        : { action: "block", reason: "reads secrets or credentials; the agent should not need these in context" }
    }
    return { action: "allow", reason: "read-only command chain" }
  }
  return undefined
}

function num(a: Answer | undefined): number | undefined {
  return a && a.type === "noul" ? a.noul : undefined
}

/**
 * Threshold logic over classifier answers.
 *
 * With an ordinary profile the actions are allow/ask/deny. With
 * opts.unattended the tier ladder is allow/block/pause and the risk signals
 * gate instead of intent: anything not provably risky is allowed, so a long
 * run keeps moving. Missing answers still only ever push toward the cautious
 * side.
 */
export function decide(
  answers: Record<string, Answer>,
  t: Thresholds = DEFAULT_THRESHOLDS,
  opts?: { unattended?: boolean; permission?: string; metadata?: Record<string, unknown> },
): Decision {
  const verdict = answers.verdict
  if (!verdict || verdict.type !== "choice") return { action: "ask", reason: "no verdict answer" }

  // Outside-workspace paths deserve scrutiny only when the call can WRITE:
  // read-only commands outside the workspace (ls/grep of a config dir) are
  // already static-allowed above or pass here on a confident safe verdict.
  // Writes outside the workspace pause so the user weighs the path.
  const pcmd = typeof opts?.metadata?.command === "string" ? opts.metadata.command : ""
  const touchesOutside = opts?.permission === "external_directory" || /(^|\s|["'(])~\//.test(pcmd)
  const readOnly = pcmd ? readOnlyChain(pcmd) : false
  // System-wide package installs land outside the project and are
  // effectively irreversible (no agent undo): block with a redirect.
  const systemInstall = /\b(brew|apt(-get)?|dnf|yum|pacman)\s+(install|add)\b/.test(pcmd)

  // Missing answers must only ever push toward caution, never toward allow.
  // irreversible defaults high so it blocks allow; intent low so it blocks
  // allow; exfiltration low so it does NOT trigger a deny on absent data.
  const irreversible = num(answers.irreversible) ?? 1
  const intent = num(answers.matches_intent) ?? 0
  const exfil = num(answers.exfiltration) ?? 0
  const scope = answers.scope?.type === "choice" ? answers.scope.choice : undefined

  const describe = `${verdict.choice} conf=${verdict.confidence.toFixed(2)}, irrev=${irreversible.toFixed(2)}, intent=${intent.toFixed(2)}, exfil=${exfil.toFixed(2)}${scope ? `, ${scope}` : ""}`

  if (opts?.unattended) {
    const exfilBlock = exfil > 0.35
    const irrevBlock = irreversible > 0.45
    const dangerous = verdict.choice === "dangerous"
    if (dangerous && (verdict.confidence >= 0.7 || irrevBlock || exfilBlock || intent < 0.2)) {
      return {
        action: "block",
        reason: `auto-jev blocked (${describe}); do not retry this command. Continue with a safer alternative that avoids it.`,
      }
    }
    if (exfilBlock) {
      return {
        action: "block",
        reason: `auto-jev blocked (possible exfiltration p=${exfil.toFixed(2)}); do not retry. Continue without sending data off this machine.`,
      }
    }
    if (systemInstall) {
      return {
        action: "block",
        reason: "auto-jev blocked (system-wide package install; the agent cannot undo it). Ask the user to install it manually, then continue.",
      }
    }
    if (verdict.choice === "needs_review" && (irrevBlock || exfilBlock) && intent < 0.7) {
      return {
        action: "block",
        reason: `auto-jev blocked (needs_review with irrev=${irreversible.toFixed(2)}); do not retry. Find a reversible alternative.`,
      }
    }
    if (irrevBlock) return { action: "pause", reason: `uncertain but possibly irreversible (${describe})` }
    if (dangerous || verdict.choice === "needs_review") return { action: "pause", reason: `uncertain risk (${describe})` }
    if (touchesOutside && !readOnly) return { action: "pause", reason: `touches paths outside the workspace (${describe})` }
    // Allowing in an unattended run requires real confidence, not just the
    // absence of risk signals: a shrug ("safe", conf 0.3) still pauses.
    if (verdict.confidence < 0.6) return { action: "pause", reason: `low confidence (${describe})` }
    return { action: "allow", reason: `auto (${describe})` }
  }

  // hard denies first
  if (verdict.choice === "dangerous" && verdict.confidence >= t.dangerousConfidence) {
    return { action: "deny", reason: `dangerous (conf ${verdict.confidence.toFixed(2)})` }
  }
  if (exfil >= t.exfiltrationMax) {
    return { action: "deny", reason: `possible data exfiltration (p=${exfil.toFixed(2)})` }
  }

  // confident allow requires several independent signals
  if (
    verdict.choice === "safe" &&
    verdict.confidence >= t.safeConfidence &&
    irreversible <= t.irreversibleMax &&
    intent >= t.intentMin
  ) {
    return {
      action: "allow",
      reason: `safe (conf ${verdict.confidence.toFixed(2)}, intent ${intent.toFixed(2)}, irrev ${irreversible.toFixed(2)}${scope ? `, ${scope}` : ""})`,
    }
  }

  return {
    action: "ask",
    reason: `uncertain (verdict=${verdict.choice} conf=${verdict.confidence.toFixed(2)}, intent=${intent.toFixed(2)}, irrev=${irreversible.toFixed(2)}, exfil=${exfil.toFixed(2)})`,
  }
}
