/**
 * Wires a resolved BackendConfig to a concrete SystemOne client + auth.
 * Shared by the plugin (index.ts) and the eval runner so both hit the same
 * URL/auth resolution. Also resolves a databricks host from a CLI profile
 * when the config gave only a profile name.
 */
import type { PluginInput } from "@opencode-ai/plugin"
import { createAuth, type Auth, type AuthSource } from "./auth.js"
import { createSystemOne, type SystemOne } from "./systemone.js"
import { DEFAULT_URLS, type BackendConfig } from "./config.js"

type BunShell = PluginInput["$"]

export type Backend = {
  provider: "systemone" | "databricks"
  url: string
  model: string
  auth: Auth
  client: SystemOne
}

/** Best-effort: find the workspace host for a CLI profile. */
async function resolveDatabricksHost(profile: string | undefined, $: BunShell): Promise<string | undefined> {
  if (!profile) return undefined
  // `databricks auth env --profile X` prints the host the CLI would use.
  try {
    const res = await $`databricks auth env --profile ${profile} --output json`.quiet().nothrow()
    if (res.exitCode === 0) {
      const data = JSON.parse(res.stdout.toString())
      const host = data?.env?.DATABRICKS_HOST ?? data?.host
      if (typeof host === "string" && host) return host.replace(/\/+$/, "")
    }
  } catch {
    // fall through to ~/.databrickscfg
  }
  // Fallback: parse the profile's host line out of ~/.databrickscfg.
  try {
    const home = process.env.HOME ?? ""
    const text = await Bun.file(`${home}/.databrickscfg`).text()
    let section: string | undefined
    for (const raw of text.split("\n")) {
      const line = raw.trim()
      const m = line.match(/^\[(.+)\]$/)
      if (m) {
        section = m[1]
        continue
      }
      if (section === profile) {
        const kv = line.match(/^host\s*=\s*(\S+)/)
        if (kv) return kv[1].replace(/\/+$/, "")
      }
    }
  } catch {
    // no file — leave unresolved
  }
  return undefined
}

function databricksAuthSource(cfg: Extract<BackendConfig, { provider: "databricks" }>): AuthSource {
  // A user-exported token wins: it's the explicit "bring your own key" path.
  if (process.env.DATABRICKS_TOKEN) return { kind: "databricksToken" }
  return { kind: "cliProfile", profile: cfg.profile, host: cfg.host }
}

export async function createBackend(cfg: BackendConfig, $: BunShell): Promise<Backend> {
  if (cfg.provider === "systemone") {
    const auth = createAuth({ kind: "apiKeyEnv", envName: cfg.apiKeyEnv }, $)
    return {
      provider: "systemone",
      url: cfg.url,
      model: cfg.model,
      auth,
      client: createSystemOne({ url: cfg.url, model: cfg.model }, () => auth.token()),
    }
  }

  // databricks: a url override wins; else host + gateway path; else resolve
  // the host from the CLI profile.
  let url = cfg.url
  if (!url) {
    const host = cfg.host ?? (await resolveDatabricksHost(cfg.profile, $))
    if (!host) {
      throw new Error(
        `could not resolve a databricks host for profile ${cfg.profile ?? "(none)"}: ` +
          "set the host/url plugin option or DATABRICKS_HOST",
      )
    }
    url = host.replace(/\/+$/, "") + DEFAULT_URLS.databricks
  }
  const auth = createAuth(databricksAuthSource(cfg), $)
  return {
    provider: "databricks",
    url,
    model: cfg.model,
    auth,
    client: createSystemOne({ url, model: cfg.model }, () => auth.token()),
  }
}
