/**
 * opencode-auto — auto mode powered by TypeSafe SystemOne (OpenJev) via
 * Databricks AI Gateway.
 *
 * Only permission requests ("permission.asked" events) are classified. Explicit
 * allow/deny rules in the user's opencode.json still apply first and are never
 * seen by this plugin. The `config` hook escalates bash/edit/webfetch/
 * external_directory to "ask" so the classifier actually gets traffic.
 *
 * Two profiles:
 *   interactive (default) — allow/ask/deny. Anything uncertain stays at the
 *     normal TUI prompt.
 *   unattended — for long runs with nobody at the keyboard. Non-risky calls
 *     go through; clear-cut danger is rejected with feedback so the agent can
 *     redirect to a safer approach; uncertain-risky calls pause the run at the
 *     prompt until the user returns. A per-session circuit breaker escalates
 *     block -> pause when the agent keeps insisting.
 *
 * Blocks use the v2 /permission/{requestID}/reply endpoint, which carries a
 * `message` the agent sees (PermissionV1.CorrectedError) and therefore keeps
 * the loop going. Falls back to the v1 reply when the endpoint is missing.
 */
import type { Plugin } from "@opencode-ai/plugin"
import { resolveConfig } from "./config.js"
import { createAuth } from "./auth.js"
import { createSystemOne } from "./systemone.js"
import { createClassifier } from "./classifier.js"
import { createBreaker } from "./breaker.js"
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

export const AutoJev: Plugin = async ({ client, $, directory, worktree, serverUrl }, options) => {
  const cfg = resolveConfig(options)
  const unattended = cfg.mode_profile === "unattended"

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
  const breaker = createBreaker({
    consecutiveBlocks: cfg.maxConsecutiveBlocks,
    maxBlocksPerSession: cfg.maxBlocksPerSession,
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

  /** Non-fatal TUI toast; no-op in headless `opencode run`. */
  const toast = async (variant: "success" | "warning" | "error" | "info", message: string) => {
    try {
      await (client as unknown as {
        tui?: { showToast?: (o: { body: { title: string; message: string; variant: string } }) => Promise<unknown> }
      }).tui?.showToast?.({ body: { title: "auto-jev", message, variant } })
    } catch {
      // headless or TUI unavailable
    }
  }

  await log("info", "auto-jev initialized", {
    enabled: cfg.enabled,
    dryRun: cfg.dryRun,
    runProfile: cfg.mode_profile,
    mode: cfg.mode,
    model: cfg.model,
    host: cfg.host,
    profile: cfg.profile,
  })
  if (cfg.enabled) await auth.warmup()

  /**
   * Reject with feedback via the v2 endpoint so the agent reads the reason and
   * redirects (loop continues). Returns false when the endpoint is unavailable
   * so the caller can fall back to the v1 reply (loop stops).
   */
  const rejectWithFeedback = async (sessionID: string, permissionID: string, message: string): Promise<boolean> => {
    if (!serverUrl) return false
    try {
      const res = await fetch(new URL(`/permission/${encodeURIComponent(permissionID)}/reply`, serverUrl), {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-opencode-directory": encodeURIComponent(directory),
        },
        body: JSON.stringify({ reply: "reject", message }),
      })
      if (!res.ok) {
        await log("warn", "v2 permission reply failed", { status: res.status })
        return false
      }
      return true
    } catch (err) {
      await log("warn", "v2 permission reply error", { error: String(err) })
      return false
    }
  }

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

      // Circuit breaker: in unattended mode a session that keeps getting
      // blocked escalates from block (redirect the agent) to pause (wait for
      // the human). Allows reset the consecutive counter.
      let final = result
      if (unattended) {
        if (result.action === "block" && breaker.tripped(p.sessionID)) {
          final = {
            action: "pause",
            reason: `${result.reason} — repeated blocked calls in this session; pausing for the user`,
            source: result.source,
            latencyMs: result.latencyMs,
            usage: result.usage,
          }
        }
        if (final.action === "allow") breaker.allow(p.sessionID)
        else if (final.action === "block") breaker.block(p.sessionID)
      }

      await audit({
        permission: p.permission,
        command: p.metadata?.command,
        patterns: p.patterns,
        ...final,
        ...(final !== result ? { escalatedFrom: result.action } : {}),
      })
      await log(final.action === "deny" || final.action === "block" ? "warn" : "info", `auto-jev ${final.action}`, {
        permission: p.permission,
        command: p.metadata?.command,
        action: final.action,
        reason: final.reason,
        source: final.source,
        latencyMs: final.latencyMs,
        usage: final.usage,
      })

      if (cfg.dryRun) return // observe only; leave the TUI prompt

      const label = String(p.metadata?.command ?? p.patterns?.[0] ?? p.permission)

      if (final.action === "allow" && cfg.mode !== "allow-ask") {
        try {
          await client.postSessionIdPermissionsPermissionId({
            path: { id: p.sessionID, permissionID: p.id },
            body: { response: "once" },
          })
          await toast("success", `auto-allowed: ${label.slice(0, 60)}`)
        } catch (err) {
          await log("error", "permission reply failed", { error: String(err) })
        }
        return
      }

      if (final.action === "block") {
        const ok = await rejectWithFeedback(p.sessionID, p.id, final.reason)
        if (ok) {
          await toast("warning", `auto-blocked: ${label.slice(0, 60)}`)
          return
        }
        // v2 endpoint unavailable: a v1 reject would stop the loop, which is
        // indistinguishable from "pause". Pause honestly instead.
        await log("warn", "falling back to pause (no feedback channel)")
        return
      }

      if (final.action === "deny" && cfg.mode === "allow-ask-deny") {
        try {
          await client.postSessionIdPermissionsPermissionId({
            path: { id: p.sessionID, permissionID: p.id },
            body: { response: "reject" },
          })
          await toast("error", `auto-denied: ${label.slice(0, 60)}`)
        } catch (err) {
          await log("error", "permission reply failed", { error: String(err) })
        }
        return
      }

      // "ask" / "pause" / anything else: stay silent; the normal prompt shows.
      if (final.action === "pause") await toast("warning", `paused for review: ${label.slice(0, 60)}`)
    },
  }
}

export default AutoJev
