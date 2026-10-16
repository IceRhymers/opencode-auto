/**
 * Pure presentation of the toggle status for the TUI (src/tui.tsx): the
 * footer label and the toast shown after a toggle. Kept JSX-free so it can be
 * unit-tested without a terminal host.
 */
import type { AutoStatus } from "./rpc.js"

export type Tone = "on" | "off" | "unavailable"

export function indicator(s: AutoStatus): { tone: Tone; label: string } {
  if (!s.active) return { tone: "unavailable", label: "auto unavailable" }
  if (!s.enabled) return { tone: "off", label: "auto off" }
  return { tone: "on", label: `⏵⏵ auto · ${s.runProfile}${s.dryRun ? " · dry-run" : ""}` }
}

export function toast(s: AutoStatus): { message: string; variant: "success" | "info" | "warning" } {
  if (!s.active) {
    return { message: `Auto mode unavailable: ${s.reason ?? "no classifier backend configured"}`, variant: "warning" }
  }
  if (!s.enabled) return { message: "Auto mode off: permissions use OpenCode's normal prompts", variant: "info" }
  return { message: `Auto mode on (${s.runProfile}${s.dryRun ? ", dry-run" : ""})`, variant: "success" }
}
