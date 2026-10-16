/**
 * Plugin configuration, resolved from plugin options (the entry's `options`
 * object in the opencode.json(c) `plugins` array, or a V1 `[name, options]`
 * tuple) and env vars. Explicit options win over env so a stray shell var
 * can't hijack a deliberate install.
 *
 * The classifier backend is bring-your-own:
 *   - "systemone": the native TypeSafe SystemOne API
 *     (https://api.typesafe.ai/v1/systemone), authenticated with an API key
 *     from an env var (default TYPESAFE_API_KEY).
 *   - "databricks": a Databricks AI Gateway path
 *     (https://<host>/ai-gateway/typesafe/v1/systemone), authenticated with a
 *     Databricks token (DATABRICKS_TOKEN or an OAuth CLI profile).
 *   - "ai-decide": the Databricks AI Decide function API (beta)
 *     (https://<host>/api/2.0/ai-functions/ai-decide), same auth as
 *     "databricks". Explicit opt-in only: it is never auto-detected from
 *     host/profile/env, and it has no selectable model.
 * `url` overrides the endpoint outright for any SystemOne-compatible server.
 */
import { DEFAULT_THRESHOLDS, type Thresholds } from "./policy.js"

export type Profile = "interactive" | "unattended"

export type Mode = "allow-ask-deny" | "allow-ask" | "allow-deny"

export type Provider = "systemone" | "databricks" | "ai-decide"

export const DEFAULT_URLS: Record<Provider, string> = {
  systemone: "https://api.typesafe.ai/v1/systemone",
  databricks: "/ai-gateway/typesafe/v1/systemone", // joined to the host
  "ai-decide": "/api/2.0/ai-functions/ai-decide", // joined to the host
}

export const DEFAULT_MODELS: Record<Provider, string> = {
  systemone: "jev-latest",
  databricks: "system.ai.openjev-qwen35-4b",
  // ai-decide has no selectable model; this is a label (the requested function
  // API version) used for logs and the eval cache file name.
  "ai-decide": "v1.0",
}

export type BackendConfig =
  | {
      provider: "systemone"
      url: string
      model: string
      /** env var holding the TypeSafe API key (the key itself never enters config) */
      apiKeyEnv: string
    }
  | {
      provider: "databricks" | "ai-decide"
      url: string
      model: string
      host?: string
      profile?: string
    }

export type Config = {
  enabled: boolean
  dryRun: boolean
  /** interactive: allow/ask/deny against the TUI prompt. unattended: allow
   *  unless risky; block+redirect clear danger; pause the run when uncertain. */
  mode_profile: Profile
  mode: Mode
  backend?: BackendConfig
  /** why there is no backend (set when backend is undefined) */
  unconfigured?: string
  contextMessages: number
  timeoutMs: number
  thresholds: Thresholds
  /** actions classified even when V2 resolves "allow" (internal names:
   *  "bash" covers V2's "shell", "task" covers "subagent") */
  escalate: string[]
  logPath: string
  /** circuit breaker (unattended profile) */
  maxConsecutiveBlocks: number
  maxBlocksPerSession: number
}

const num = (v: unknown, d: number) => {
  const n = Number(v)
  return Number.isFinite(n) && n >= 0 ? n : d
}
const bool = (v: unknown, d: boolean) => (v === undefined ? d : v === true || v === "true" || v === "1")

function str(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined
}

export function detectProvider(
  opts: Record<string, unknown>,
  env: Record<string, string | undefined>,
): Provider | undefined {
  const explicit = str(opts.provider ?? env.AUTO_JEV_PROVIDER)
  if (explicit === "systemone" || explicit === "databricks" || explicit === "ai-decide") return explicit

  // Explicit install-time options are the strongest signal: a profile or host
  // baked into opencode.json means "this install uses databricks", even if the
  // shell happens to export a TypeSafe key.
  if (str(opts.profile) || str(opts.host)) return "databricks"

  const apiKeyEnv = str(opts.apiKeyEnv) ?? "TYPESAFE_API_KEY"
  if (str(env[apiKeyEnv])) return "systemone"
  if (str(env.DATABRICKS_TOKEN) || str(env.DATABRICKS_HOST) || str(env.DATABRICKS_CONFIG_PROFILE)) {
    return "databricks"
  }
  return undefined
}

export function resolveBackend(
  opts: Record<string, unknown>,
  env: Record<string, string | undefined>,
): { backend: BackendConfig; unconfigured?: undefined } | { backend?: undefined; unconfigured: string } {
  const provider = detectProvider(opts, env)
  const urlOverride = str(opts.url ?? env.AUTO_JEV_URL)
  const modelOpt = str(opts.model ?? env.AUTO_JEV_MODEL)
  const apiKeyEnv = str(opts.apiKeyEnv) ?? "TYPESAFE_API_KEY"

  if (!provider) {
    return {
      unconfigured:
        "no classifier backend configured: export TYPESAFE_API_KEY (native SystemOne) or set a databricks " +
        "profile/host (options or DATABRICKS_* env)",
    }
  }

  if (provider === "systemone") {
    if (urlOverride) return { backend: { provider, url: urlOverride, model: modelOpt ?? DEFAULT_MODELS.systemone, apiKeyEnv } }
    return {
      backend: { provider, url: DEFAULT_URLS.systemone, model: modelOpt ?? DEFAULT_MODELS.systemone, apiKeyEnv },
    }
  }

  // databricks-style backends (ai-gateway, ai-decide) share host/profile/url
  // resolution and auth; they differ only in the fixed path and default model.
  // ai-decide reaches this branch only when explicitly named (detectProvider).
  const host = str(opts.host ?? env.DATABRICKS_HOST)
  const profile = str(opts.profile ?? env.DATABRICKS_CONFIG_PROFILE)
  const model = modelOpt ?? DEFAULT_MODELS[provider]
  if (urlOverride) {
    return { backend: { provider, url: urlOverride, model, host, profile } }
  }
  if (host) {
    return { backend: { provider, url: host.replace(/\/+$/, "") + DEFAULT_URLS[provider], model, host, profile } }
  }
  // Host resolved later from the CLI profile (backend.resolveDatabricksHost).
  if (profile) {
    return { backend: { provider, url: "", model, profile } }
  }
  if (str(env.DATABRICKS_TOKEN)) {
    return {
      unconfigured:
        "DATABRICKS_TOKEN is set but no host: also export DATABRICKS_HOST or set the host/url plugin options",
    }
  }
  return {
    unconfigured:
      "databricks provider needs a host or profile: set the host/profile plugin options, " +
      "DATABRICKS_HOST, or DATABRICKS_CONFIG_PROFILE",
  }
}

export function resolveConfig(opts: Record<string, unknown> = {}): Config {
  const env = process.env
  const t = (opts.thresholds ?? {}) as Partial<Thresholds>
  const runProfile = (env.AUTO_JEV_PROFILE ?? opts.runProfile) as Profile | undefined
  const { backend, unconfigured } = resolveBackend(opts, env)
  return {
    enabled: bool(opts.enabled ?? env.AUTO_JEV_ENABLED, true),
    dryRun: bool(opts.dryRun ?? env.AUTO_JEV_DRY_RUN, false),
    mode_profile: runProfile === "interactive" ? "interactive" : "unattended",
    mode: (opts.mode as Mode) ?? "allow-ask-deny",
    backend,
    unconfigured,
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
    maxConsecutiveBlocks: num(opts.maxConsecutiveBlocks, 2),
    maxBlocksPerSession: num(opts.maxBlocksPerSession, 4),
  }
}
