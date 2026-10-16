import { describe, expect, test } from "bun:test"
import { createToggle } from "../src/toggle.ts"
import { indicator, toast } from "../src/indicator.ts"

const memory = (initial: Record<string, unknown> = {}) => {
  const data = { ...initial }
  return {
    data,
    get: async (key: string) => data[key],
    set: async (key: string, value: unknown) => {
      data[key] = value
    },
  }
}

describe("createToggle", () => {
  test("starts from the config default when nothing is stored", async () => {
    expect((await createToggle(memory(), true)).enabled()).toBe(true)
    expect((await createToggle(memory(), false)).enabled()).toBe(false)
  })

  test("a stored value wins over the config default", async () => {
    const t = await createToggle(memory({ toggle: { enabled: false } }), true)
    expect(t.enabled()).toBe(false)
  })

  test("ignores malformed stored values", async () => {
    const t = await createToggle(memory({ toggle: "off" }), true)
    expect(t.enabled()).toBe(true)
  })

  test("set persists and runs onChange only on a real change", async () => {
    const store = memory()
    const changes: boolean[] = []
    const t = await createToggle(store, true, (v) => {
      changes.push(v)
    })
    await t.set(true)
    expect(changes).toEqual([])
    await t.set(false)
    expect(t.enabled()).toBe(false)
    expect(store.data.toggle).toEqual({ enabled: false })
    expect(changes).toEqual([false])
  })

  test("storage failures degrade to an in-memory toggle", async () => {
    const broken = {
      get: async () => {
        throw new Error("down")
      },
      set: async () => {
        throw new Error("down")
      },
    }
    const t = await createToggle(broken, true)
    expect(t.enabled()).toBe(true)
    await t.set(false)
    expect(t.enabled()).toBe(false)
  })
})

describe("indicator", () => {
  const base = { enabled: true, active: true, runProfile: "unattended", dryRun: false }

  test("on shows the run profile", () => {
    expect(indicator(base)).toEqual({ tone: "on", label: "⏵⏵ auto · unattended" })
    expect(indicator({ ...base, dryRun: true }).label).toBe("⏵⏵ auto · unattended · dry-run")
  })

  test("off and unavailable", () => {
    expect(indicator({ ...base, enabled: false })).toEqual({ tone: "off", label: "auto off" })
    expect(indicator({ ...base, active: false, enabled: true }).tone).toBe("unavailable")
  })

  test("toast carries the unavailable reason", () => {
    const t = toast({ ...base, active: false, reason: "no key" })
    expect(t.variant).toBe("warning")
    expect(t.message).toContain("no key")
    expect(toast(base).variant).toBe("success")
    expect(toast({ ...base, enabled: false }).variant).toBe("info")
  })
})
