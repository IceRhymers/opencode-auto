/**
 * Per-session ledger of resources the agent created: scratch tables, git
 * branches, files in the session temp dir. Fed to the classifier as
 * action.created_this_session so "drop the table I just made" reads as
 * cleanup, not destruction. Built by scanning completed shell commands;
 * best-effort, regex-based, capped.
 */
const MAX_ENTRIES = 50

const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")

export type Ledger = {
  record(command: string | undefined): void
  summary(): string | undefined
}

export function createLedger(tmpPrefixes: string[]): Ledger {
  const tables = new Set<string>()
  const branches = new Set<string>()
  const tmpPaths = new Set<string>()
  const tmpRes = tmpPrefixes.map((p) => new RegExp(`${escapeRegExp(p)}/\\S+`, "g"))

  const add = (set: Set<string>, v: string | undefined) => {
    if (v && set.size < MAX_ENTRIES) set.add(v.replace(/[;"'`]+$/, ""))
  }

  return {
    record(command: string | undefined) {
      if (!command) return
      for (const m of command.matchAll(/\bCREATE\s+(?:OR\s+REPLACE\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([\w.`-]+)/gi)) add(tables, m[1])
      for (const m of command.matchAll(/\.saveAsTable\s*\(\s*["'`]([^"'`]+)["'`]/g)) add(tables, m[1])
      for (const m of command.matchAll(/\b(?:INTO|OVERWRITE)\s+TABLE\s+([\w.`-]+)/gi)) add(tables, m[1])
      for (const m of command.matchAll(/\bgit\s+(?:checkout|switch)\s+(?:-b|-c)\s+(\S+)/g)) add(branches, m[1])
      for (const re of tmpRes) {
        for (const m of command.matchAll(re)) add(tmpPaths, m[0].replace(/[*]+$/, ""))
      }
    },
    summary(): string | undefined {
      const parts: string[] = []
      const list = (set: Set<string>) => [...set].slice(0, 10).join(", ")
      if (tables.size) parts.push(`tables created by the agent: ${list(tables)}`)
      if (branches.size) parts.push(`branches created by the agent: ${list(branches)}`)
      if (tmpPaths.size) parts.push(`session temp files: ${list(tmpPaths)}`)
      return parts.length ? parts.join("; ") : undefined
    },
  }
}
