/**
 * opencode-auto — auto mode powered by a SystemOne-compatible classifier
 * (native TypeSafe SystemOne, OpenJev via a Databricks AI Gateway, or the
 * Databricks AI Decide function API).
 *
 * OpenCode V2 plugin. Classification happens in the permission "evaluate"
 * hook, which runs inline before any prompt is published and can rewrite the
 * decision (effect + message). All "ask" evaluations are classified, plus
 * "allow" evaluations for escalated actions (shell/edit/webfetch/
 * external_directory): V2 defaults allow those, and re-checking them here
 * mirrors the V1 config hook that forced them to "ask". Explicit deny rules
 * are resolved by OpenCode before the hook and never reach us.
 *
 * Decision mapping:
 *   allow -> effect "allow"         (unless mode is "allow-ask")
 *   deny  -> effect "deny" + reason (only when mode is "allow-ask-deny")
 *   block -> effect "deny" + reason; the agent reads the reason as a tool
 *            error and redirects, so the loop keeps going
 *   ask / pause -> effect "ask" + reason; the prompt shows it and waits
 * dryRun classifies and logs but never touches the evaluation (observe-only).
 *
 * Two profiles:
 *   interactive — allow/ask/deny. Anything uncertain stays at the prompt.
 *   unattended (default) — non-risky calls go through; clear-cut danger is
 *     blocked with feedback; uncertain-risky calls pause the run at the
 *     prompt. A per-session circuit breaker escalates block -> pause when the
 *     agent keeps insisting.
 *
 * One shell call raises two permission asserts (external_directory, then
 * shell). The full command line isn't on either assert — it's captured from
 * tool.execute.before keyed by call id, and the first assert's decision is
 * cached so the second inherits it (no double classification).
 *
 * When no backend can be configured the plugin stays inactive and leaves
 * every evaluation untouched.
 */
import { Plugin } from "@opencode/plugin"
import { $ } from "bun"
import { resolveConfig } from "./config.js"
import { createBackend, type Backend } from "./backend.js"
import { createClassifier, type ClassifyResult } from "./classifier.js"
import { createBreaker } from "./breaker.js"
import { recentUserMessages, type MessagesClient } from "./context.js"
import {
  applyDecision,
  callIDOf,
  canonicalAction,
  evaluationToPermission,
  shouldClassify,
  type EvaluationLike,
} from "./adapter.js"

/** Shell call inputs captured at execute.before (full command line). */
const CALL_TTL_MS = 60_000
/** Decisions shared between the two asserts of one shell call. */
const PAIR_TTL_MS = 15_000

export default Plugin.define({
  id: "opencode-auto",
  async setup(ctx) {
    const cfg = resolveConfig({ ...ctx.options })
    const unattended = cfg.mode_profile === "unattended"
    const worktree: string = ctx.location.project.directory

    const log = (level: "debug" | "info" | "warn" | "error", message: string, extra?: Record<string, unknown>) => {
      try {
        console.error(`[auto-jev] ${level}: ${message}${extra ? " " + JSON.stringify(extra) : ""}`)
      } catch {
        // logging must never break the hook
      }
    }

    // Resolve the classifier backend (native SystemOne or databricks). When
    // it can't be configured the plugin disables itself cleanly: evaluate
    // returns immediately and OpenCode's own decisions stand.
    let backend: Backend | undefined
    let backendErr: string | undefined = cfg.unconfigured
    if (cfg.backend) {
      try {
        backend = await createBackend(cfg.backend, $, { timeoutMs: cfg.timeoutMs })
      } catch (e) {
        backendErr = e instanceof Error ? e.message : String(e)
      }
    }
    const active = cfg.enabled && backend !== undefined

    const classify = backend
      ? createClassifier({
          systemone: backend.client,
          config: cfg,
          getUserMessages: (sessionID) =>
            recentUserMessages(ctx.session as unknown as MessagesClient, sessionID, cfg.contextMessages),
          worktree,
        })
      : undefined
    const breaker = createBreaker({
      consecutiveBlocks: cfg.maxConsecutiveBlocks,
      maxBlocksPerSession: cfg.maxBlocksPerSession,
    })
    /** Escalated actions are classified even when V2 resolved "allow". */
    const escalate = new Set(cfg.escalate.map(canonicalAction))

    const audit = async (line: Record<string, unknown>) => {
      try {
        const file = Bun.file(`${worktree}/${cfg.logPath}`)
        const prev = (await file.exists()) ? await file.text() : ""
        await Bun.write(file, prev + JSON.stringify({ t: Date.now(), ...line }) + "\n")
      } catch {
        // ignore
      }
    }

    /** Full shell command lines by tool call id (from execute.before). */
    const calls = new Map<string, { command?: string; t: number }>()
    /** Final decisions by tool call id, shared by a shell call's asserts. */
    const pairs = new Map<string, { action: string; reason: string; t: number }>()

    const sweep = <V extends { t: number }>(map: Map<string, V>, ttl: number) => {
      const now = Date.now()
      for (const [k, v] of map) if (now - v.t > ttl) map.delete(k)
    }
    const pairGet = (callID: string | undefined) => {
      if (!callID) return undefined
      const e = pairs.get(callID)
      if (!e) return undefined
      if (Date.now() - e.t > PAIR_TTL_MS) {
        pairs.delete(callID)
        return undefined
      }
      return e
    }

    log("info", "auto-jev initialized", {
      enabled: cfg.enabled,
      active,
      dryRun: cfg.dryRun,
      runProfile: cfg.mode_profile,
      mode: cfg.mode,
      ...(backend
        ? { provider: backend.provider, url: backend.url, model: backend.model, auth: backend.auth.describe }
        : { unconfigured: backendErr }),
    })
    if (backendErr) log("warn", "auto-jev backend not configured; plugin inactive", { reason: backendErr })
    if (active && backend) await backend.auth.warmup()

    const registrations = [
      // Capture the full command line; the permission asserts only carry the
      // scanner's sub-command resources, which lose quoting and pipes.
      await ctx.tool.hook("execute.before", (ev) => {
        const input = ev.input as { command?: unknown } | undefined
        calls.set(ev.id, { command: typeof input?.command === "string" ? input.command : undefined, t: Date.now() })
        if (calls.size > 200) sweep(calls, CALL_TTL_MS)
      }),
      await ctx.tool.hook("execute.after", (ev) => {
        calls.delete(ev.id)
      }),

      await ctx.permission.hook("evaluate", async (ev) => {
        if (!active || !classify) return
        if (!shouldClassify(ev.effect, ev.action, escalate)) return

        const callID = callIDOf(ev)
        const action = canonicalAction(ev.action)

        // The shell call's two asserts (external_directory fires first, then
        // shell) share one classification via the pair cache.
        const paired = action === "bash" || action === "external_directory" ? pairGet(callID) : undefined
        let result: ClassifyResult
        let usedCommand: string | undefined
        if (paired) {
          result = { action: paired.action, reason: `paired decision: ${paired.reason}`, source: "static" } as ClassifyResult
        } else {
          usedCommand = callID ? calls.get(callID)?.command : undefined
          if (usedCommand === undefined && action === "bash") {
            // Fallback without execute.before data: the scanner's resources.
            // Quoting/pipes are lost, weakening the static rules.
            const joined = ev.resources.join("; ").trim()
            if (joined) usedCommand = joined
          }
          result = await classify({ sessionID: ev.sessionID, ...evaluationToPermission(ev, usedCommand) })
        }

        // Circuit breaker: in unattended mode a session that keeps getting
        // blocked escalates from block (redirect the agent) to pause (wait
        // for the human). Allows reset the consecutive counter.
        let final = result
        if (unattended) {
          if (result.action === "block" && breaker.tripped(ev.sessionID)) {
            final = {
              ...result,
              action: "pause",
              reason: `${result.reason} — repeated blocked calls in this session; pausing for the user`,
            }
          }
          if (final.action === "allow") breaker.allow(ev.sessionID)
          else if (final.action === "block") breaker.block(ev.sessionID)
        }

        // Record a command-based decision so the call's other assert
        // inherits it (see pairs above).
        if (!paired && usedCommand !== undefined && callID) {
          pairs.set(callID, { action: final.action, reason: final.reason, t: Date.now() })
          if (pairs.size > 200) sweep(pairs, PAIR_TTL_MS)
        }

        await audit({
          permission: action,
          command: usedCommand,
          patterns: ev.resources,
          ...final,
          ...(final !== result ? { escalatedFrom: result.action } : {}),
        })
        log(final.action === "deny" || final.action === "block" ? "warn" : "info", `auto-jev ${final.action}`, {
          permission: action,
          command: usedCommand,
          action: final.action,
          reason: final.reason,
          source: final.source,
          latencyMs: final.latencyMs,
          usage: final.usage,
        })

        applyDecision(ev, final, { mode: cfg.mode, dryRun: cfg.dryRun })
      }),
    ]

    return async () => {
      for (const r of registrations) {
        try {
          await r.dispose()
        } catch {
          // shutdown must not throw
        }
      }
    }
  },
})
