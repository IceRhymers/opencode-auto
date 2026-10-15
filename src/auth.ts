/**
 * Token providers for the classifier backend.
 *
 * Three sources, picked by createAuth from the resolved backend config:
 *   - apiKeyEnv:    read a TypeSafe API key from an env var (re-read every
 *                   call, so rotating the key needs no restart)
 *   - databricksToken: a token the user exported themselves (DATABRICKS_TOKEN)
 *   - cliProfile:   mint via the Databricks CLI (`databricks auth token`),
 *                   which refreshes OAuth access tokens silently from its
 *                   cached session; a browser login is attempted at most once
 *                   per process when no valid session exists
 *
 * All expose the same { warmup, token } shape the HTTP client expects.
 */
import type { $ } from "bun"

type BunShell = typeof $

const REFRESH_SKEW_MS = 5 * 60 * 1000
const FALLBACK_TTL_MS = 50 * 60 * 1000

type Cached = { token: string; expiresAt: number }

export type AuthSource =
  | { kind: "apiKeyEnv"; envName: string }
  | { kind: "databricksToken" }
  | { kind: "cliProfile"; profile?: string; host?: string }

export type Auth = {
  /** human-readable source for logs, never contains the token */
  describe: string
  /** Warm the cache (optional; called at init). Never throws. */
  warmup(): Promise<void>
  token(): Promise<string>
}

/** TypeSafe API key (or any bearer token) held in an environment variable. */
export function createApiKeyAuth(envName: string): Auth {
  return {
    describe: `env:${envName}`,
    async warmup() {
      // nothing to warm: the key is read per call below
    },
    async token() {
      const key = process.env[envName]
      if (!key) {
        throw new Error(
          `${envName} is not set. Export it (export ${envName}=...) or switch to the databricks provider ` +
            "(host/profile options or DATABRICKS_* env).",
        )
      }
      return key
    },
  }
}

/** A Databricks token the user supplied via DATABRICKS_TOKEN (PAT or OAuth). */
export function createDatabricksTokenAuth(): Auth {
  return {
    describe: "env:DATABRICKS_TOKEN",
    async warmup() {},
    async token() {
      const token = process.env.DATABRICKS_TOKEN
      if (!token) {
        throw new Error(
          "DATABRICKS_TOKEN is not set (it was at startup?). Export it again or configure a CLI profile.",
        )
      }
      return token
    },
  }
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

/** OAuth token minted by the Databricks CLI from a profile's cached session. */
export function createCliAuth(src: { profile?: string; host?: string }, $: BunShell): Auth {
  const args: string[] = []
  if (src.host) args.push("--host", src.host)
  if (src.profile) args.push("--profile", src.profile)
  const target = src.profile ? `profile ${src.profile}` : (src.host ?? "default profile")
  const describe = src.profile ? `cli-profile:${src.profile}` : "cli-default"

  let cached: Cached | undefined
  let inflight: Promise<Cached> | undefined
  let loginAttempted = false

  async function runToken() {
    const res = await $`databricks auth token ${{ raw: args.join(" ") }} --output json`.quiet().nothrow()
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
      await $`databricks auth login ${{ raw: args.join(" ") }}`.quiet().nothrow()
      res = await runToken()
    }
    if (!res.ok) {
      throw new Error(
        `databricks auth token failed for ${target}. Run: databricks auth login ${args.join(" ")}\n${res.stderr}`,
      )
    }
    return parseToken(res.stdout)
  }

  return {
    describe,
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

export function createAuth(source: AuthSource, $: BunShell): Auth {
  switch (source.kind) {
    case "apiKeyEnv":
      return createApiKeyAuth(source.envName)
    case "databricksToken":
      return createDatabricksTokenAuth()
    case "cliProfile":
      return createCliAuth(source, $)
  }
}
