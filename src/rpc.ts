/**
 * RPC surface shared by the server plugin (src/index.ts) and the TUI plugin
 * (src/tui.tsx). The TUI's toggle command and footer indicator talk to the
 * permission hook through this channel; the "changed" event keeps every
 * connected TUI in sync.
 *
 * Status fields:
 *   enabled   — the runtime toggle (persisted; config `enabled` is the default)
 *   active    — a classifier backend is configured, so enabling has an effect
 *   runProfile/dryRun — static config, surfaced for display
 *   reason    — why active is false (backend unconfigured)
 */
import { Rpc } from "@opencode/plugin"

const StatusSchema = {
  type: "object",
  properties: {
    enabled: { type: "boolean" },
    active: { type: "boolean" },
    runProfile: { type: "string" },
    dryRun: { type: "boolean" },
    reason: { type: "string" },
  },
  required: ["enabled", "active", "runProfile", "dryRun"],
  additionalProperties: false,
} as const

export type AutoStatus = {
  enabled: boolean
  active: boolean
  runProfile: string
  dryRun: boolean
  reason?: string
}

export const Auto = Rpc.define({
  id: "opencode-auto",
  methods: {
    status: {
      input: { type: "object", additionalProperties: false },
      output: StatusSchema,
    },
    set: {
      input: {
        type: "object",
        properties: { enabled: { type: "boolean" } },
        required: ["enabled"],
        additionalProperties: false,
      },
      output: StatusSchema,
    },
  },
  events: {
    changed: { schema: StatusSchema },
  },
})
