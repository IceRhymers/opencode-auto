/**
 * opencode-auto — auto mode powered by TypeSafe SystemOne (OpenJev) via
 * Databricks AI Gateway.
 *
 * Only permission requests ("permission.asked" events) are classified. Explicit
 * allow/deny rules in the user's opencode.json still apply first and are never
 * seen by this plugin. The `config` hook escalates bash/edit/webfetch/
 * external_directory to "ask" so the classifier actually gets traffic. Each
 * permission.asked is classified and the plugin replies "once"/"reject" via the
 * v1 permission API, or stays silent to leave the normal TUI prompt in place.
 */
import type { Plugin } from "@opencode-ai/plugin"
import { resolveConfig } from "./config.js"
import { createAuth } from "./auth.js"
import { createSystemOne } from "./systemone.js"
import { createClassifier } from "./classifier.js"
import { recentUserMessages } from "./context.js"

type PermissionAsked = {
  id: string
  sessionID: string
  permission: string
  patterns?: string[]
  metadata?: Record<string, unknown>
  always?: string[]
  tool?: { messageID?: string; callID?: string }
}

export const AutoJev: Plugin = async ({ client, $, directory, worktree }, options) => {
  const cfg = resolveConfig(options)

  const log = async (
    level: "debug" | "info" | "warn" | "error",
    message: string,
    extra?: Record<string, unknown>,
  ) => {
    try {
      await client.app.log({ body: { service: "auto-jev", level, message, extra } })
    } catch {
      // logging must never break the hook
    }
  }

  const auth = createAuth({ host: cfg.host, profile: cfg.profile }, $)
  const systemone = createSystemOne(
    { host: cfg.host, model: cfg.model, timeoutMs: cfg.timeoutMs },
    () => auth.token(),
  )
  const classify = createClassifier({
    systemone,
    config: cfg,
    getUserMessages: (sessionID) =>
      recentUserMessages(client as never, sessionID, cfg.contextMessages),
    worktree,
  })

  const audit = async (line: Record<string, unknown>) => {
    try {
      const file = Bun.file(`${directory}/${cfg.logPath}`)
      const prev = (await file.exists()) ? await file.text() : ""
      await Bun.write(file, prev + JSON.stringify({ t: Date.now(), ...line }) + "\n")
    } catch {
      // ignore
    }
  }

  await log("info", "auto-jev initialized", {
    enabled: cfg.enabled,
    dryRun: cfg.dryRun,
    mode: cfg.mode,
    model: cfg.model,
    host: cfg.host,
    profile: cfg.profile,
  })
  if (cfg.enabled) await auth.warmup()

  return {
    config: async (input) => {
      if (!cfg.enabled) return
      const perm = (input as { permission?: unknown }).permission
      // Escalate chosen tools to "ask" so the classifier sees them. Never touch
      // explicit "deny" rules, and never loosen anything already stricter.
      const escalate = (key: string) => {
        const cur = (perm as Record<string, unknown> | undefined)?.[key]
        if (cur === "deny") return
        if (typeof cur === "object" && cur !== null) return // granular rules: leave alone
        ;(input as Record<string, Record<string, unknown>>).permission![key] = "ask"
      }
      if (perm && typeof perm === "object") {
        for (const key of cfg.escalate) escalate(key)
      }
    },

    event: async ({ event }) => {
      const e = event as unknown as { type: string; properties?: PermissionAsked }
      if (e.type !== "permission.asked" || !e.properties) return
      if (!cfg.enabled) return
      const p = e.properties

      const result = await classify({
        sessionID: p.sessionID,
        permission: p.permission,
        patterns: p.patterns,
        metadata: p.metadata,
      })

      await audit({
        permission: p.permission,
        command: p.metadata?.command,
        patterns: p.patterns,
        ...result,
      })
      await log(result.action === "deny" ? "warn" : "info", `auto-jev ${result.action}`, {
        permission: p.permission,
        command: p.metadata?.command,
        action: result.action,
        reason: result.reason,
        source: result.source,
        latencyMs: result.latencyMs,
        usage: result.usage,
      })

      if (cfg.dryRun) return // observe only; leave the TUI prompt

      // Decide whether to answer the permission request.
      let response: "once" | "reject" | undefined
      if (result.action === "allow" && cfg.mode !== "allow-ask") response = "once"
      else if (result.action === "deny" && cfg.mode === "allow-ask-deny") response = "reject"
      // "ask" => stay silent; normal prompt shows
      if (!response) return

      try {
        await client.postSessionIdPermissionsPermissionId({
          path: { id: p.sessionID, permissionID: p.id },
          body: { response },
        })
      } catch (err) {
        await log("error", "permission reply failed", { error: String(err) })
      }
    },
  }
}

export default AutoJev
