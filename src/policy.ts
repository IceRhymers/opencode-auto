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

/** Risk gates for the unattended tier ladder (tuned via eval/sweep.ts). */
export type UnattendedGates = {
  /** exfiltration probability above this blocks — only with an upload-shaped sink */
  exfilBlock: number
  /** irreversible probability above this pauses (or corroborates a block) */
  irrevBlock: number
  /** confidence on verdict=dangerous required to block outright */
  dangerousConf: number
  /** needs_review + risk blocks only when intent is below this */
  needsReviewIntent: number
  /** min safe-verdict confidence to auto-allow */
  allowMinConf: number
}

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
  /** unattended-profile gates */
  unattended: UnattendedGates
}

/** The paths the classifier itself depends on. */
export type SelfPaths = { worktree: string; logPath: string }

export const DEFAULT_UNATTENDED_GATES: UnattendedGates = {
  exfilBlock: 0.35,
  // 0.55: both OpenJev and ai-decide cluster clearly-reversible routine
  // actions (npm install, touch, sed -i on tracked files) at 0.46-0.53,
  // while genuinely irreversible ones score far higher; 0.45 sat inside
  // the routine cluster (see eval caches + sweep).
  irrevBlock: 0.55,
  dangerousConf: 0.7,
  needsReviewIntent: 0.7,
  allowMinConf: 0.6,
}

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
  unattended: DEFAULT_UNATTENDED_GATES,
}

/** Read-only tools: no shell command, so the static path judges the paths. */
export const READ_ONLY_TOOLS = new Set(["read", "glob", "grep", "list"])

/** Matches a .env-style path segment, but not "process.env" or "$X.env". */
const ENV_FILE = /(?<![\w$])\.env(?:rc|\.[\w-]+)?\b/

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
  ENV_FILE,
  /(^|\s|["'(])\/[a-zA-Z0-9_.-]/, // absolute path outside home (macOS/Linux)
]

/** Reading any of these exposes a secret; blocked even when read-only. */
export const SECRET_READ: RegExp[] = [
  /\.(ssh|aws|gnupg|kube|docker)\b/,
  ENV_FILE,
  /\/etc\/(passwd|shadow|sudoers)/,
  /\.(pem|key|p12|pfx)\b/,
  /\bid_(rsa|ed25519|ecdsa|dsa)\b/,
]

/** Block feedback for secret reads (shared by the shell and read-tool paths). */
export const SECRET_READ_BLOCK =
  "auto-jev blocked (reads a secret or credential file); do not retry. The agent should not need secret values in context — list keys only (cut -d= -f1 .env) or ask the user."

/**
 * Credential config files: reading them exposes logins, but agents routinely
 * need to inspect (not print) them to debug auth. Paused, not blocked.
 */
export const VAULT_READ: RegExp[] = [
  /(?<!\w)\.databrickscfg\b/,
  /(?<!\w)\.netrc\b/,
  /(?<!\w)\.git-credentials\b/,
  /(?<!\w)\.npmrc\b/,
  /(?<!\w)\.pypirc\b/,
  /(?<!\w)\.pgpass\b/,
]

/**
 * Key-only / redacted views of a .env file: sed with a script that strips
 * everything after `=` (empty or `<redacted>` replacement), or `cut -d= -f1`.
 * Values never reach the agent's context, so these are allowed even though
 * the path is sensitive.
 */
const REDACTED_ENV: RegExp[] = [
  /\bsed\s+(?:-[a-zA-Z]+\s+)*["']s\/=[^/]*\/(?:=?<redacted>)?\/["']/,
  /\bcut\s+(?:-\S+\s+)*-d["']?=["']?\s+(?:-\S+\s+)*-f1(?:\s|$)/,
]

/** True when the command exposes a live credential to the agent's context.
 * Assignments (export NAME=$(...)) are NOT prints; bare dumps and explicit
 * prints are. */
function printsCredential(cmd: string): boolean {
  if (/\bdatabricks\s+auth\s+token\b/.test(cmd)) return true
  if (/\bdatabricks\s+secrets\s+get-secret\b/.test(cmd)) return true
  // env | grep TOKEN (and friends): a filter stage hunting for a secret name
  if (
    /\b(?:printenv|env|set)\b[^|]*\|[^|]*\b(?:grep|egrep|fgrep|rg|awk|sed)\b[^|;&]*\b[A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIAL)/.test(
      cmd,
    )
  ) {
    return true
  }
  // echo/cat/printf of a secret-looking variable
  if (/\b(?:echo|printf|cat|xargs|read)\b[^|;&]*\$\{?[A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD)[A-Z0-9_]*\}?/.test(cmd)) {
    return true
  }
  if (/\$\((?:printenv|cat)\b[^)]*\b[A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD)[A-Z0-9_]*\b/.test(cmd)) return true
  if (/\bprintenv\s+[A-Z0-9_]*(?:TOKEN|API_KEY|SECRET|PASSWORD|CREDENTIALS)/.test(cmd)) return true
  if (/\b(?:export|declare)\s+-p\b/.test(cmd)) return true
  // Bare env/printenv/set/export/declare dump every variable. Allowed only
  // when a later stage filters the output (grep family); the keyword rule
  // above still blocks secret-hunting filters.
  const stages = splitStages(cmd)
  const FILTER = /\b(?:grep|egrep|fgrep|rg|awk|sed|jq)\b/
  for (let i = 0; i < stages.length; i++) {
    if (!/^(?:env|printenv|set|export|declare)$/.test(stages[i])) continue
    if (stages.slice(i + 1).some((s) => FILTER.test(s))) continue
    return true
  }
  return false
}

/**
 * Upload-shaped sinks: the command can move local content to a remote. Exfil
 * blocks are gated on one of these being present (a high exfil score on a
 * command with no sink can at most pause).
 */
export function hasExfilSink(cmd: string): boolean {
  if (/\bcurl\b[^|;&]*\s(?:-d\b|--data(?:-[\w]+)?\b|-F\b|--form\b|-T\b|--upload-file\b)/.test(cmd)) return true
  if (/\bwget\b[^|;&]*\s--post-(?:data|file)\b/.test(cmd)) return true
  if (/\b(?:scp|rsync)\b[^|;&]*\s[\w.-]+:/.test(cmd)) return true
  if (/\bnc\b[^|;&]*\s[\w.-]+\s+\d+/.test(cmd)) return true
  if (/\bgit\s+push\b/.test(cmd)) return true
  if (/\baws\s+s3\s+cp\b[^|;&]*\bs3:\/\//.test(cmd)) return true
  if (/\bdatabricks\s+fs\s+cp\b[^|;&]*\bdbfs:/.test(cmd)) return true
  if (/\bdatabricks\s+api\s+post\b[^|;&]*\s--json\s+@/.test(cmd)) return true
  return false
}

/** Sinks whose destination is the user's own workspace by construction. */
function sinkToDesignated(cmd: string): boolean {
  return /\bdatabricks\s+fs\s+cp\b[^|;&]*\bdbfs:/.test(cmd) || /\bdatabricks\s+api\s+(?:post|put|patch)\b/.test(cmd)
}

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

/** OpenCode's session temp dir ($TMPDIR/opencode), both /var and /private/var. */
export function tmpdirPrefixes(extra?: string[]): string[] {
  const roots = extra ?? ([process.env.TMPDIR, "/tmp", "/var/tmp"].filter(Boolean) as string[])
  const out: string[] = []
  for (const r of roots) {
    const clean = r.replace(/\/+$/, "")
    if (!clean) continue
    const dir = clean.endsWith("/opencode") ? clean : `${clean}/opencode`
    out.push(dir)
    if (!dir.startsWith("/private/")) out.push(`/private${dir}`)
  }
  // longest first: /var/... is a substring of /private/var/...
  return [...new Set(out)].sort((a, b) => b.length - a.length)
}

/** macOS per-user temp dirs, independent of the current $TMPDIR. */
const MACOS_TMPDIR = /(?:\/private)?\/var\/folders\/[\w+-]+\/[\w+-]+\/T\/opencode(?=\/|\s|$|["'])/g

/**
 * Rewrite environment-specific absolute prefixes to stable tokens so rules
 * don't treat the project's own worktree or the session temp dir as
 * "outside the workspace" sensitive paths.
 */
export function normalizeEnvPrefixes(cmd: string, opts?: { cwd?: string; tempdir?: string[] }): string {
  let out = cmd
  for (const p of tmpdirPrefixes(opts?.tempdir)) {
    out = out.split(p).join("$OPENCODE_TMP")
  }
  out = out.replace(MACOS_TMPDIR, "$OPENCODE_TMP")
  const cwd = opts?.cwd?.replace(/\/+$/, "")
  if (cwd && cwd !== "/") {
    out = out.replace(new RegExp(`${escapeRegExp(cwd)}(?=/|\\s|$|["'])`, "g"), ".")
  }
  return out
}

/**
 * Replace heredoc bodies with a placeholder line, returning the bodies keyed
 * by delimiter. Only QUOTED delimiters ('TAG' / "TAG") are extracted: their
 * bodies are literal text (no shell expansion), and leaving them in would
 * break stage splitting (they can contain `;`, `|`, and `&&`). The operator
 * line and the closing delimiter stay so the shape is preserved.
 */
export function extractHeredocs(cmd: string): { cmd: string; bodies: Map<string, string> } {
  const bodies = new Map<string, string>()
  const lines = cmd.split("\n")
  const out: string[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]
    out.push(line)
    const m = line.match(/<<-?\s*(['"])([A-Za-z_][A-Za-z0-9_]*)\1\s*$/)
    if (!m) {
      i++
      continue
    }
    const tag = m[2]
    const dash = /<<-/.test(line)
    const bodyLines: string[] = []
    let j = i + 1
    let closed = false
    for (; j < lines.length; j++) {
      const l = lines[j]
      const stripped = dash ? l.replace(/^\t+/, "") : l
      if (stripped === tag) {
        closed = true
        break
      }
      bodyLines.push(l)
    }
    if (closed) {
      if (!bodies.has(tag)) bodies.set(tag, bodyLines.join("\n"))
      out.push("bodyplaceholder")
      out.push(tag)
    } else {
      // unterminated: leave the text in place for the model/rules
      out.push(...bodyLines)
    }
    i = j + 1
  }
  return { cmd: out.join("\n"), bodies }
}

/** Where a destructive command lands. */
type Target = "root" | "sensitive" | "external" | "workspace"

export function destructiveness(cmd: string): { level: "none" | "possible" | "destructive"; target: Target } {
  let destructive = false
  let target: Target = "workspace"

  // Recursive rm (with any flag combination, short or long form). rm -f
  // alone (no recursion) is left to the model: single-file force removal is
  // routine in build/output cleanup.
  if (/\brm\s+-[a-zA-Z]*[rR]/.test(cmd)) destructive = true
  if (/\brm\s+--recursive\b/.test(cmd)) destructive = true
  if (/\brm\s+(-[a-zA-Z]+\s+)+/.test(cmd)) {
    // split short flags: every flag letter group must consist of rf-letters
    // only, and r must appear across groups (rm -r -f /)
    const groups = cmd.match(/\brm\s+((?:-[a-zA-Z]+\s+)+)/)
    if (groups) {
      const letters = groups[1].replace(/[-\s]/g, "")
      if (/^[rf]+$/.test(letters) && /r/.test(letters)) destructive = true
    }
  }

  // git branch deletion, both spellings
  if (/\bgit\s+branch\b[^|;&]*(\s-[a-zA-Z]*[dD][a-zA-Z]*|--delete)/.test(cmd)) destructive = true

  // git reset --hard
  if (/\bgit\s+reset\b[^|;&]*\s--hard\b/.test(cmd)) destructive = true

  // git commit --amend rewrites the tip commit; whether it was already pushed
  // is unknowable here, so it gets the same treatment as reset --hard
  if (/\bgit\s+commit\b[^|;&]*\s--amend\b/.test(cmd)) destructive = true

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

/**
 * Replace `$(cat <<'TAG' ... TAG)` heredoc substitutions with a placeholder.
 * This is how agents build multi-line git commit messages, and the body
 * breaks both the $(...) guard and stage splitting (it can contain `;`).
 * Only QUOTED delimiters ('TAG' / "TAG") are stripped: a quoted heredoc body
 * is literal text, inert inside the quoted -m argument. An unquoted heredoc
 * would expand $(...) in its body, so it is left for the model.
 */
export function stripCatHeredocs(cmd: string): string {
  return cmd.replace(
    /\$\(\s*cat\s+<<-?\s*(['"])(\w+)\1\s*\n[\s\S]*?\n\t*(\w+)\s*\)/g,
    (m, _q, open, close) => (open === close ? "MSG" : m),
  )
}

/**
 * True for a plain `git commit` (optionally with `git add` of workspace files
 * before it in the same command). False when the command pushes, amends, or
 * does anything beyond committing — those stay with the model/policy. A
 * multi-line message via `git commit -m "$(cat <<'EOF' ... EOF)"` still
 * counts as plain: the heredoc is stripped first.
 */
export function isPlainGitCommit(cmd: string): boolean {
  cmd = stripCatHeredocs(cmd)
  if (/\$\(|`/.test(cmd)) return false
  const stages = splitStages(cmd)
  if (!stages.some((s) => /^git\s+commit\b/.test(s))) return false
  // no pipes: a piped commit is unusual enough to leave with the model
  if (cmd.includes("|")) return false
  return stages.every((s) => {
    if (/^git\s+add\b/.test(s)) return true
    if (/^git\s+commit\b/.test(s)) {
      // history-rewriting or publishing flags disqualify
      if (/--amend\b|\bpush\b/.test(s)) return false
      return true
    }
    if (/^(git\s+(status|diff|log)|echo\b|true|false)\b/.test(s)) return true
    return false
  })
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
  /^(git\s+(status|diff|log|show|branch|rev-parse|blame|fetch|describe|tag|remote|stash\s+(list|show)|worktree\s+list|ls-files))\b/,
  /^(ls|pwd|echo|cat|head|tail|wc|which|whoami|date|env|file|stat|du|df|rg|grep|sort|uniq|cut|tr|paste|column|nl|diff|cmp|comm|shasum|basename|dirname|realpath)\b/,
  /^find\b(?!.*\s-(delete|exec|ok)\b)/,
  // sed: quoted or unquoted-print scripts, never in-place. The flag class
  // excludes i so `-ni`/`-i.bak` can't sneak in-place edits past the
  // whitespace-anchored lookahead, and quoted scripts reject w/W/e commands
  // (file writes / exec; s///e is GNU-only and left as a known gap).
  /^sed\s+(-[a-hj-zA-Z]*\s+)*(['"])((?:(?![wWe]\s)[^'"])*)\2(?!.*\s-i\b)/,
  /^sed\s+(-[a-hj-zA-Z]*\s+)*([0-9$.,]+|\/[^/\s]+\/)p(\s|$)(?!.*\s-i\b)/,
  /^awk\b/,
  /^(bun|npm|pnpm|yarn)\s+(test|run\s+test|run\s+(build|typecheck|lint|check))\b/,
  /^(tsc|bun\s+x\s+tsc|bunx\s+tsc|npx\s+tsc)\b.*--noEmit/,
  /^(python3?|uv)\s+(-m\s+)?(pytest|unittest|ruff\s+check|mypy)\b/,
  /^(go\s+(test|build|vet)|cargo\s+(test|build|check)|make(\s+\w+)?|just\s+\w+)\b/,
  /^(docker\s+(ps|logs|images)|kubectl\s+get)\b/,
  /^(node|deno|bun|python3?|pip3?|uv|ruby|go|rustc|cargo|java|javac)\s+(-v|--version|version)\s*$/,
  /^tree\b/,
  /^jq\b/,
]

/**
 * Read-only Databricks CLI verbs. Secret-printing subcommands are excluded
 * explicitly: `auth token`, `secrets get-secret`, `postgres
 * generate-database-credential`, and the free-form `api` passthrough.
 */
const DATABRICKS_RO =
  /^databricks\s+(?!(?:auth\s+token|secrets\s+get-secret|postgres\s+generate-database-credential|api)\b)(?:[\w-]+\s+)*(?:list|get|ls|validate|summary|profiles)\b/

/** awk is a full interpreter: reject stages with exec/write/read-env features. */
const AWK_DANGEROUS = /\bsystem\s*\(|\bgetline\b|\b(?:print|printf)\s[^|;]*>\s*[^>]|ENVIRON/

/** Dangerous capabilities inside a python snippet (checked as words). */
const PY_DANGEROUS: RegExp[] = [
  /\b(subprocess|os\.system|os\.popen|pty|socket|requests|urllib|shutil)\b/,
  /\b(exec|eval|compile|__import__)\s*\(/,
  /\bos\.(remove|unlink|rmdir|makedirs|mkdir|rename|replace|chmod|chown|remove|removedirs)\b/,
  /\bpathlib\b[^;&]*\b(write_text|write_bytes|unlink|mkdir|rename)\b/,
  /\b(sys\.argv|input)\s*\(/, // argv reference is fine, but input() blocks; keep conservative
]

/**
 * open() is a write only with a write/append/exclusive/update mode (or a
 * .write( call). A non-literal mode stays conservative and counts as a write.
 */
function pythonOpenWrites(script: string): boolean {
  // .write( outside sys.stdout/sys.stderr is a write
  if (script.replace(/sys\.std(?:out|err)\.write\s*\(/g, "").includes(".write(")) return true
  const calls = script.match(/\bopen\s*\([^)]*\)/g) ?? []
  for (const call of calls) {
    const inner = call.slice(call.indexOf("(") + 1, call.lastIndexOf(")"))
    const comma = inner.indexOf(",")
    if (comma < 0) continue
    const second = inner.slice(comma + 1).trim()
    if (/^["']rb?["']$/.test(second)) continue // open(f, "r") / "rb"
    if (/^encoding\s*=/.test(second)) continue // open(f, encoding="utf-8")
    return true // write/append/update mode or a non-literal mode: conservative
  }
  return false
}

function pythonScriptReadOnly(script: string): boolean {
  if (!script) return false
  if (PY_DANGEROUS.some((re) => re.test(script))) return false
  return !pythonOpenWrites(script)
}

/**
 * True when a python stage is confined to reading and printing — the common
 * "format this log/output" pipe-tail, or a quoted heredoc whose body was
 * extracted (see extractHeredocs). Conservative: any write/exec/network/
 * file-mutation token disqualifies it.
 */
export function pythonReadOnlySnippet(stage: string, bodies?: Map<string, string>): boolean {
  const c = stage.match(/^(?:python3?|python)\s+-c\s+(["'])([\s\S]*)\1\s*$/)
  if (c) return pythonScriptReadOnly(c[2])
  const h = stage.match(/^(?:python3?|python)(?:\s+-)?\s+<<-?(['"])([A-Za-z_]\w*)\1\s*\nbodyplaceholder\n\2\s*$/)
  if (h && bodies) {
    const body = bodies.get(h[2])
    return body !== undefined && pythonScriptReadOnly(body)
  }
  return false
}

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

/** Static-decision options shared by the recursive helpers. */
export type StaticOpts = {
  self?: SelfPaths
  /** false in the interactive profile: static blocks/pauses become asks */
  unattended?: boolean
  /** project worktree, used to recognize absolute paths inside it */
  cwd?: string
  /** extra temp-dir roots (defaults: $TMPDIR, /tmp, /var/tmp) */
  tempdir?: string[]
}

/**
 * Write-shaped commands aimed at the classifier's own files: explicit writes
 * (rm/mv/cp-into/chmod), in-place edits, redirects into the file, and running
 * the installer (which mutates opencode.json). Read-only chains are never
 * blocked by self-protection, even when they read the log or the config.
 */
function selfWrite(cmd: string, self: SelfPaths | undefined, bodies: Map<string, string>, raw: string): boolean {
  if (!isSelfTargeting(raw, self)) return false
  if (/\$\(|`/.test(raw)) return true // substitution may execute anything
  if (readOnlyChain(cmd, bodies)) return false
  const stages = splitStages(cmd)
  // Leading-token write tools (a match must start the stage, so "grep ...
  // opencode.json" or "tail .../install.log" is not a write), in-place edit
  // flags, and redirects. A python stage is a write only if it isn't a
  // recognized read-only snippet (pythonReadOnlySnippet): python can do
  // anything, so an unrecognized script targeting our files stays blocked.
  const LEAD_WRITE =
    /^(sudo\s+)?(rm|mv|cp|chmod|chown|chgrp|touch|ln|mkdir|rmdir|tee|patch|truncate|shred|dd|install|rsync|scp|git|vim?|nvim|nano|emacs|code|open|uv|just|make|npm|pnpm|yarn|bun|deno)\b/
  const IN_PLACE = /\b(sed|perl|awk)\b[^|;&]*\s-i\b|\b(sed|perl)\b[^|;&]*\s-i\./
  return stages.some(
    (s) =>
      LEAD_WRITE.test(s) ||
      IN_PLACE.test(s) ||
      /(^|\s)>>?\s*[^\s&|]/.test(s) ||
      (/^(sudo\s+)?python3?\b/.test(s) && !pythonReadOnlySnippet(s, bodies)),
  )
}

/**
 * Split a command into stages on &&, ||, ;, and | — but NOT inside single or
 * double quotes. A python/node `-c "…;…"` script keeps its semicolons.
 */
export function splitStages(cmd: string): string[] {
  const stages: string[] = []
  let cur = ""
  let quote: string | undefined
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]
    if (quote) {
      cur += c
      if (c === quote) quote = undefined
      continue
    }
    if (c === '"' || c === "'") {
      quote = c
      cur += c
      continue
    }
    if (c === "&" && cmd[i + 1] === "&") {
      stages.push(cur)
      cur = ""
      i++
      continue
    }
    if (c === "|" ) {
      if (cmd[i + 1] === "|") {
        stages.push(cur)
        cur = ""
        i++
        continue
      }
      stages.push(cur)
      cur = ""
      continue
    }
    if (c === ";") {
      stages.push(cur)
      cur = ""
      continue
    }
    cur += c
  }
  if (cur.trim()) stages.push(cur)
  return stages.map((s) => s.trim()).filter(Boolean)
}

/** Remove single/double-quoted spans so their contents can't trip syntax checks. */
function stripQuoted(s: string): string {
  return s.replace(/'[^']*'|"[^"]*"/g, '""')
}

/**
 * True when every pipeline/list stage in the command is individually
 * read-only. Command substitution ($(...) / `...`) is excluded: its contents
 * are executed and can't be statically classified as read-only.
 *
 * Harmless redirections (stderr merge, /dev/null sinks) are ignored; a
 * redirect to a real file disqualifies. Redirection-looking characters
 * INSIDE quotes (a sed replacement like '<redacted>') are not redirects. A
 * `cd <path>` stage is allowed: it only sets the location for the following
 * stages, which are still classified on their own.
 */
export function readOnlyChain(cmd: string, bodies?: Map<string, string>, opts?: StaticOpts): boolean {
  if (/\$\(|`/.test(cmd)) return false
  const stages = splitStages(cmd).filter((s) => !/^(true|false)$/.test(s))
  if (!stages.length) return false
  return stages.every((stage) => {
    // strip no-op redirections: 2>&1, N>/dev/null, &>/dev/null; heredoc
    // operators are not writes (their bodies were extracted already)
    const s = stage
      .replace(/\d*>&\d+/g, "")
      .replace(/&?>>?\s*\/dev\/null\b/g, "")
      .replace(/<<-?\s*['"]?\w+['"]?/g, "")
      .trim()
    if (/[<>]/.test(stripQuoted(s))) return false // any remaining redirect writes
    if (/^cd\b/.test(s)) return true // pure location change; other stages are checked
    if (/^(curl|wget)\b/.test(s)) {
      // only a plain GET: safe flags, a URL, no data/output/upload flags
      if (/\s(-X|--request)\s*(POST|PUT|DELETE|PATCH)\b/i.test(s)) return false
      if (/\s(-d|--data|--data-binary|--data-raw|-T|--upload-file|-F|--form|-o|--output|-O|--remote-name)\b/.test(s)) return false
      if (/\s--?(url)\b/.test(s) === false && !/https?:\/\//.test(s)) return false
      return /^[\w\s:./?&=%@+~,'-]*$/.test(s)
    }
    // python3 -c "…" or a quoted heredoc used as a read-only formatter/parser
    // at the end of a pipe. Only stdin/stdout/json/re/sys/os-path/textwrap/
    // collections — any file-write, subprocess, or shell capability fails it.
    if (/^(?:python3?|python)\b/.test(s)) {
      return pythonReadOnlySnippet(stage, bodies) || TRIVIAL_ALLOW.some((re) => re.test(s))
    }
    // awk: full interpreter — only the print-only subset is trivially read-only
    if (/^awk\b/.test(s)) return !AWK_DANGEROUS.test(stage)
    // jq filters that touch the process environment are not read-only
    if (/^jq\b/.test(s) && /(?:\$ENV\b|\benv\b)/.test(stage)) return false
    // tree -o writes its output to a file
    if (/^tree\b/.test(s) && /\s-o\s*\S/.test(s)) return false
    // sort -o writes in place; uniq IN OUT writes OUT
    if (/^sort\b/.test(s) && /\s-o\b/.test(s)) return false
    if (/^uniq\b/.test(s)) {
      const args = s.split(/\s+/).filter((a) => !a.startsWith("-"))
      if (args.length > 2) return false // uniq + input + output
    }
    // xargs [-0] <cmd>: classify the inner command the way `env <cmd>` is handled
    if (/^xargs\s/.test(s)) {
      const inner = s.replace(/^xargs\s+(?:-[a-zA-Z0-9]+\s+)*/, "")
      if (!inner || inner === s) return false
      const d = staticDecision({ permission: "bash", metadata: { command: inner } }, opts)
      return d?.action === "allow"
    }
    if (DATABRICKS_RO.test(s)) return true
    return TRIVIAL_ALLOW.some((re) => re.test(s))
  })
}

/** Static rules short-circuit the model. Returns undefined when no rule hits. */
export function staticDecision(
  p: { permission: string; metadata?: Record<string, unknown> },
  opts?: StaticOpts,
): Decision | undefined {
  if (p.permission !== "bash") return undefined
  const raw = bashCommand(p)
  if (!raw) return undefined

  const interactive = opts?.unattended === false

  // Heredoc bodies are literal text; extract them so they can't break stage
  // splitting or trip pattern rules, and so python heredocs can be judged.
  const { cmd, bodies } = extractHeredocs(raw)

  for (const re of HARD_DENY) {
    if (re.test(cmd)) return { action: "deny", reason: `hard-deny rule: ${re.source}` }
  }

  // Self-protection blocks WRITES to the classifier's own files (config,
  // source, audit log, installer). Reads fall through to the normal rules,
  // so debugging the classifier (tail the log, grep the config) is allowed.
  if (selfWrite(cmd, opts?.self, bodies, raw)) {
    return interactive
      ? { action: "ask", reason: "writes to the classifier's own config/source/log; confirm" }
      : {
          action: "block",
          reason:
            "auto-jev blocked (writes to the classifier's own config/source/log); do not retry. The read tool and grep/tail on the log are allowed; configure opencode-auto directly or ask the user.",
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

  // Printing a live token/secret into the agent's context is exposure even
  // when nothing is written to disk. Block it before any allow path; the
  // classifier mints its own tokens out-of-process. Assignments into a
  // variable (export NAME=$(...)) are not prints.
  if (printsCredential(cmd)) {
    return interactive
      ? { action: "ask", reason: "prints a live credential into the agent context; confirm exposure" }
      : { action: "block", reason: "auto-jev blocked (prints a live credential); do not retry. Assign it to a variable instead of printing it; the agent never needs raw tokens in context." }
  }

  // Local git commits are reversible (git reset) and central to dev work, so
  // unattended mode lets them through. Only a plain commit: anything that
  // publishes (push), rewrites history (--amend of pushed work), or stages
  // outside the tree stays with the model. Interactive keeps the prompt.
  if (isPlainGitCommit(cmd)) {
    return interactive
      ? { action: "ask", reason: "git commit; confirm" }
      : { action: "allow", reason: "local git commit (reversible with git reset)" }
  }

  // Writes/deletes aimed at obvious secret stores, shared refs, or user-level
  // system config are never model-decided.
  if (/\bcp\b[^|;&]*~\/\.(aws|ssh|gnupg)/.test(cmd) || /\bcp\b[^|;&]*\.(pem|key|p12|pfx)\b/.test(cmd)) {
    return interactive
      ? { action: "ask", reason: "copies credentials; confirm" }
      : { action: "block", reason: "auto-jev blocked (copies a credential file); do not retry. Reference credentials in place instead of copying them." }
  }
  if (/\b(npm|yarn|pnpm|bun)\s+publish\b|\bgit\s+push\b[^|]*\s--delete\b|\bgit\s+update-ref\s+-d\b/.test(cmd)) {
    return interactive
      ? { action: "ask", reason: "publishes or deletes shared refs; needs the user" }
      : { action: "block", reason: "auto-jev blocked (publishes a package or deletes a shared ref); do not retry. Leave publishing to the user and continue with local work." }
  }
  if (/\b(crontab\s+-r|launchctl\s+(un)load|defaults\s+delete)\b/.test(cmd)) {
    return interactive
      ? { action: "ask", reason: "alters user-level system config" }
      : { action: "block", reason: "auto-jev blocked (alters user-level system config: crontab/launchctl/defaults); do not retry. Ask the user to make this change." }
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

  // Destructiveness is judged with the workspace and session temp dir
  // normalized away: an absolute path inside either is not "outside".
  const d = destructiveness(normalizeEnvPrefixes(cmd, opts))
  if (d.level === "destructive") {
    if (d.target === "root") return { action: "deny", reason: "rm -rf of filesystem root or home" }
    if (d.target === "sensitive") {
      return { action: interactive ? "ask" : "pause", reason: "destructive command touches a sensitive path" }
    }
    return { action: interactive ? "ask" : "pause", reason: "destructive in-workspace change (rm -rf / git branch -D / git reset --hard / git commit --amend)" }
  }

  // A secret store plus an upload-shaped sink is exfiltration by shape, not
  // by reading: never let the model wave it through.
  if (hasExfilSink(cmd) && SECRET_READ.some((re) => re.test(raw))) {
    return interactive
      ? { action: "ask", reason: "uploads a credential/secret file; confirm" }
      : { action: "block", reason: "auto-jev blocked (uploads a credential/secret file); do not retry. Keep secrets local." }
  }

  if (readOnlyChain(cmd, bodies, opts)) {
    // Key-only or fully redacted views of a .env file expose nothing.
    const redactedEnv = ENV_FILE.test(raw) && REDACTED_ENV.some((re) => re.test(raw))
    const otherSecret = SECRET_READ.some((re) => re !== ENV_FILE && re.test(raw))
    // Reads that expose secrets are never static-allowed, even though the
    // command itself is read-only. Interactive keeps it at the prompt.
    if (!redactedEnv && (otherSecret || ENV_FILE.test(raw))) {
      return interactive
        ? { action: "ask", reason: "reads secrets or credentials; confirm exposure" }
        : { action: "block", reason: SECRET_READ_BLOCK }
    }
    // Credential config files pause: inspection is legitimate, exposure isn't.
    if (VAULT_READ.some((re) => re.test(raw))) {
      return interactive
        ? { action: "ask", reason: "reads a credential config file; confirm" }
        : { action: "pause", reason: "reads a credential config file; confirm" }
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
  opts?: { unattended?: boolean; permission?: string; metadata?: Record<string, unknown>; cwd?: string },
): Decision {
  const verdict = answers.verdict
  if (!verdict || verdict.type !== "choice") return { action: "ask", reason: "no verdict answer" }

  // Outside-workspace paths deserve scrutiny only when the call can WRITE:
  // read-only commands outside the workspace (ls/grep of a config dir) are
  // already static-allowed above or pass here on a confident safe verdict.
  // Writes outside the workspace pause so the user weighs the path.
  const pcmd = typeof opts?.metadata?.command === "string" ? opts.metadata.command : ""
  const ncmd = normalizeEnvPrefixes(pcmd, { cwd: opts?.cwd })
  const touchesOutside = opts?.permission === "external_directory" || /(^|\s|["'(])~\//.test(ncmd)
  const extracted = pcmd ? extractHeredocs(pcmd) : undefined
  const readOnly = extracted ? readOnlyChain(extracted.cmd, extracted.bodies) : false
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
    const g = t.unattended ?? DEFAULT_UNATTENDED_GATES
    // Exfil blocks only with an upload-shaped sink to a destination that
    // isn't the user's own: a high exfil score on a command with no way to
    // send anything out is model noise, so it can at most pause.
    const sink = extracted ? hasExfilSink(extracted.cmd) : false
    const designated = sink && sinkToDesignated(pcmd)
    const exfilBlock = exfil > g.exfilBlock && sink && !designated
    const irrevBlock = irreversible > g.irrevBlock
    const dangerous = verdict.choice === "dangerous"
    if (dangerous && (verdict.confidence >= g.dangerousConf || irrevBlock || exfilBlock || intent < 0.2)) {
      return {
        action: "block",
        reason: `auto-jev blocked (${describe}); do not retry this command. Continue with a safer alternative that avoids it.`,
      }
    }
    if (exfilBlock) {
      return {
        action: "block",
        reason: `auto-jev blocked (possible exfiltration: ${describe}); do not retry. Continue without sending data off this machine.`,
      }
    }
    if (systemInstall) {
      return {
        action: "block",
        reason: "auto-jev blocked (system-wide package install; the agent cannot undo it). Ask the user to install it manually, then continue.",
      }
    }
    if (verdict.choice === "needs_review" && (irrevBlock || exfilBlock) && intent < g.needsReviewIntent) {
      return {
        action: "block",
        reason: `auto-jev blocked (needs_review with irrev=${irreversible.toFixed(2)}); do not retry. Find a reversible alternative.`,
      }
    }
    if (irrevBlock) return { action: "pause", reason: `uncertain but possibly irreversible (${describe})` }
    if (dangerous || verdict.choice === "needs_review") return { action: "pause", reason: `uncertain risk (${describe})` }
    // High exfil score but nothing that can send data out (or only a sink to
    // the user's own destination): pause at most.
    if (exfil > g.exfilBlock && !designated) return { action: "pause", reason: `possibly transmits data (${describe})` }
    if (touchesOutside && !readOnly) return { action: "pause", reason: `touches paths outside the workspace (${describe})` }
    // Allowing in an unattended run requires real confidence, not just the
    // absence of risk signals: a shrug ("safe", conf 0.3) still pauses.
    if (verdict.confidence < g.allowMinConf) return { action: "pause", reason: `low confidence (${describe})` }
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
