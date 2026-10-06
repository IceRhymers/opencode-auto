/**
 * opencode-auto — auto mode powered by TypeSafe SystemOne (OpenJev) via
 * Databricks AI Gateway.
 *
 * Design:
 *  - Only permission requests ("permission.asked" events) are classified. The
 *    user's explicit allow/deny rules in opencode.json still apply first and
 *    are never seen by this plugin.
 *  - The `config` hook can optionally escalate permissions (bash/edit/webfetch
 *    /external_directory) to "ask" so the classifier actually gets traffic.
 *  - Each permission.asked event is classified; the plugin replies
 *    "once"/"reject" via the v1 permission API, or stays silent to leave the
 *    normal TUI prompt in place.
 *
 * This file currently contains the spike: it logs every permission.asked
 * event with full shape so we can validate interception + reply path. The
 * classifier is wired in on top of this skeleton.
 */
import type { Plugin } from "@opencode-ai/plugin"

const SPIKE_LOG = ".opencode/auto-jev.spike.log"

/** permission.asked is emitted by opencode >=1.x but missing from the 1.18.3
 * SDK's Event union, so we declare its shape locally. */
type PermissionAskedEvent = {
  id: string
  sessionID: string
  permission: string
  patterns?: string[]
  metadata?: Record<string, unknown>
  always?: string[]
  tool?: { messageID?: string; callID?: string }
}

export const AutoJev: Plugin = async ({ client, directory }) => {
  const log = async (service: string, level: "debug" | "info" | "warn" | "error", message: string, extra?: Record<string, unknown>) => {
    try {
      await client.app.log({ body: { service, level, message, extra } })
    } catch {
      // logging must never break the hook
    }
  }

  await log("auto-jev", "info", "plugin initialized", { directory })

  return {
    // Spike-only: log the permission config surface so we can see what the
    // plugin is allowed to mutate. Real escalation rules come in step 5.
    config: async (input) => {
      await log("auto-jev", "info", "config hook fired", {
        permission: (input as { permission?: unknown }).permission,
      })
    },

    event: async ({ event }) => {
      const e = event as unknown as { type: string; properties?: PermissionAskedEvent }
      if (e.type !== "permission.asked" || !e.properties) return
      const p = e.properties
      await log("auto-jev", "info", "permission.asked", p as unknown as Record<string, unknown>)

      // Append a JSON line for offline inspection (spike artifact).
      try {
        const file = Bun.file(`${directory}/${SPIKE_LOG}`)
        const prev = (await file.exists()) ? await file.text() : ""
        await Bun.write(file, prev + JSON.stringify({ t: Date.now(), ...p }) + "\n")
      } catch (e) {
        await log("auto-jev", "warn", "spike log write failed", { error: String(e) })
      }

      // Spike policy: auto-approve obviously safe requests to prove the reply
      // path works; leave everything else to the TUI.
      const command = String(p.metadata?.command ?? "")
      const SAFE = /^(git status|git diff|git log|ls |pwd|bun test)/
      const t0 = Date.now()
      if (p.permission === "bash" && SAFE.test(command)) {
        try {
          await client.postSessionIdPermissionsPermissionId({
            path: { id: String(p.sessionID), permissionID: String(p.id) },
            body: { response: "once" },
          })
          await log("auto-jev", "info", "spike auto-allowed", { command, ms: Date.now() - t0 })
        } catch (e) {
          await log("auto-jev", "error", "spike reply failed", { error: String(e) })
        }
      }
    },
  }
}

export default AutoJev
