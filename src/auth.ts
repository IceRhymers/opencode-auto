/**
 * Databricks auth for the SystemOne endpoint.
 *
 * Mints a token via the Databricks CLI (`databricks auth token`), which
 * refreshes OAuth access tokens silently from its cached session. We cache the
 * token and refresh it before expiry. A browser login is attempted at most
 * once per process when no valid session exists.
 */
import type { PluginInput } from "@opencode-ai/plugin"

type BunShell = PluginInput["$"]

const REFRESH_SKEW_MS = 5 * 60 * 1000
const FALLBACK_TTL_MS = 50 * 60 * 1000

type Cached = { token: string; expiresAt: number }

export type AuthConfig = {
  host: string
  profile: string
}

function jwtExpiryMs(token: string): number | undefined {
  const parts = token.split(".")
  if (parts.length < 2) return undefined
  try {
    const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
    if (typeof payload.exp === "number") return payload.exp * 1000
  } catch {
    // not a JWT
  }
  return undefined
}

function parseToken(stdout: string): Cached {
  const data = JSON.parse(stdout)
  const token = data.access_token
  if (typeof token !== "string" || token.length === 0) {
    throw new Error("databricks auth token returned no access_token")
  }
  let expiresAt = 0
  if (typeof data.expiry === "string") {
    const parsed = Date.parse(data.expiry)
    if (!Number.isNaN(parsed)) expiresAt = parsed
  }
  if (expiresAt === 0) expiresAt = jwtExpiryMs(token) ?? Date.now() + FALLBACK_TTL_MS
  return { token, expiresAt }
}

export function createAuth(cfg: AuthConfig, $: BunShell) {
  let cached: Cached | undefined
  let inflight: Promise<Cached> | undefined
  let loginAttempted = false

  async function runToken() {
    const res = await $`databricks auth token --host ${cfg.host} --profile ${cfg.profile} --output json`
      .quiet()
      .nothrow()
    return {
      ok: res.exitCode === 0,
      stdout: res.stdout.toString(),
      stderr: res.stderr.toString(),
    }
  }

  async function mint(): Promise<Cached> {
    let res = await runToken()
    if (!res.ok && !loginAttempted) {
      loginAttempted = true
      await $`databricks auth login --host ${cfg.host} --profile ${cfg.profile}`.quiet().nothrow()
      res = await runToken()
    }
    if (!res.ok) {
      throw new Error(
        `databricks auth token failed. Run: databricks auth login --host ${cfg.host} --profile ${cfg.profile}\n${res.stderr}`,
      )
    }
    return parseToken(res.stdout)
  }

  return {
    /** Warm the cache (optional; called at init). Never throws. */
    async warmup() {
      try {
        await this.token()
      } catch {
        // per-request path will surface the error
      }
    },
    async token(): Promise<string> {
      if (cached && Date.now() < cached.expiresAt - REFRESH_SKEW_MS) return cached.token
      if (!inflight) {
        inflight = mint().finally(() => {
          inflight = undefined
        })
      }
      cached = await inflight
      return cached.token
    },
  }
}

export type Auth = ReturnType<typeof createAuth>
