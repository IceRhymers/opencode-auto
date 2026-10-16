/**
 * Runtime on/off for the classifier. The TUI toggle flips it through the RPC
 * in src/rpc.ts; the permission evaluate hook consults it on every call.
 *
 * The value persists in plugin storage (durable, survives service restarts),
 * so the last choice wins over the config `enabled` option once it exists —
 * config `enabled` is only the starting default. Storage failures degrade to
 * an in-memory toggle: the hook must never break because persistence did.
 */

export type ToggleStorage = {
  get(key: string): Promise<unknown>
  set(key: string, value: unknown): Promise<void>
}

export type Toggle = {
  enabled(): boolean
  /** Flips the value, persists it, then runs onChange (e.g. cache clears). */
  set(enabled: boolean): Promise<void>
}

const KEY = "toggle"

export async function createToggle(
  storage: ToggleStorage,
  configDefault: boolean,
  onChange?: (enabled: boolean) => void | Promise<void>,
): Promise<Toggle> {
  let value = configDefault
  try {
    const saved = await storage.get(KEY)
    if (typeof saved === "object" && saved !== null && typeof (saved as { enabled?: unknown }).enabled === "boolean") {
      value = (saved as { enabled: boolean }).enabled
    }
  } catch {
    // fall back to the config default
  }
  return {
    enabled: () => value,
    set: async (enabled) => {
      if (enabled === value) return
      value = enabled
      try {
        await storage.set(KEY, { enabled })
      } catch {
        // keep the in-memory value
      }
      await onChange?.(enabled)
    },
  }
}
