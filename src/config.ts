/**
 * Plugin configuration, resolved from env vars and plugin options (opencode.json
 * `[name, options]`). Env vars win so a developer can point at a different
 * gateway without editing config.
 */
import { DEFAULT_THRESHOLDS, type Thresholds } from "./policy.js"

export type Mode = "allow-ask-deny" | "allow-ask" | "allow-deny"

export type Config = {
  enabled: boolean
  dryRun: boolean
  mode: Mode
  host: string
  profile: string
  model: string
  contextMessages: number
  timeoutMs: number
  thresholds: Thresholds
  /** permissions to escalate to "ask" so the classifier sees them */
  escalate: string[]
  logPath: string
}

const num = (v: unknown, d: number) => {
  const n = Number(v)
  return Number.isFinite(n) && n >= 0 ? n : d
}
const bool = (v: unknown, d: boolean) => (v === undefined ? d : v === true || v === "true" || v === "1")

export function resolveConfig(opts: Record<string, unknown> = {}): Config {
  const env = process.env
  const t = (opts.thresholds ?? {}) as Partial<Thresholds>
  return {
    enabled: bool(opts.enabled ?? env.AUTO_JEV_ENABLED, true),
    dryRun: bool(opts.dryRun ?? env.AUTO_JEV_DRY_RUN, false),
    mode: (opts.mode as Mode) ?? "allow-ask-deny",
    host:
      env.DATABRICKS_HOST ??
      (opts.host as string) ??
      "https://fevm-tanner-wendland.cloud.databricks.com",
    profile: env.DATABRICKS_CONFIG_PROFILE ?? (opts.profile as string) ?? "fevm-west",
    model: (opts.model as string) ?? "system.ai.openjev-qwen35-4b",
    contextMessages: num(opts.contextMessages, 3),
    timeoutMs: num(opts.timeoutMs, 3000),
    thresholds: {
      safeConfidence: num(t.safeConfidence, DEFAULT_THRESHOLDS.safeConfidence),
      irreversibleMax: num(t.irreversibleMax, DEFAULT_THRESHOLDS.irreversibleMax),
      intentMin: num(t.intentMin, DEFAULT_THRESHOLDS.intentMin),
      dangerousConfidence: num(t.dangerousConfidence, DEFAULT_THRESHOLDS.dangerousConfidence),
      exfiltrationMax: num(t.exfiltrationMax, DEFAULT_THRESHOLDS.exfiltrationMax),
    },
    escalate: Array.isArray(opts.escalate)
      ? (opts.escalate as string[])
      : ["bash", "edit", "webfetch", "external_directory"],
    logPath: (opts.logPath as string) ?? ".opencode/auto-jev.log",
  }
}
