/**
 * Print the resolved classifier backend (provider, URL, model, auth source)
 * for the current env + given options, and make one cheap authenticated probe
 * request. Usage:
 *   bun run src/whoami.ts [--provider P] [--profile X] [--host H] [--url U] [--model M]
 * Exits non-zero when no backend can be configured.
 */
import { resolveBackend } from "./config.js"
import { createBackend } from "./backend.js"

const arg = (name: string): string | undefined => {
  const i = process.argv.indexOf(`--${name}`)
  return i >= 0 ? process.argv[i + 1] : undefined
}
const OPTS: Record<string, unknown> = {
  ...(arg("provider") ? { provider: arg("provider") } : {}),
  ...(arg("profile") ? { profile: arg("profile") } : {}),
  ...(arg("host") ? { host: arg("host") } : {}),
  ...(arg("url") ? { url: arg("url") } : {}),
  ...(arg("model") ? { model: arg("model") } : {}),
  ...(arg("api-key-env") ? { apiKeyEnv: arg("api-key-env") } : {}),
}

const { backend, unconfigured } = resolveBackend(OPTS, process.env)
if (!backend) {
  console.error(`not configured: ${unconfigured}`)
  process.exit(1)
}

try {
  const $ = (await import("bun")).$
  const b = await createBackend(backend, $)
  console.log(`provider: ${b.provider}`)
  console.log(`url:      ${b.url}`)
  console.log(`model:    ${b.model}`)
  console.log(`auth:     ${b.auth.describe}`)
  // cheap authenticated probe: an empty-ish ask with a trivial question
  const res = await b.client.ask(
    { ping: true },
    { ok: { type: "noul", instructions: "Reply 1." } },
  )
  console.log(`probe:    ok (model=${res.model})`)
} catch (e) {
  console.error(`probe failed: ${e instanceof Error ? e.message : String(e)}`)
  process.exit(1)
}
