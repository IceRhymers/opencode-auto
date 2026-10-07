import { describe, expect, test } from "bun:test"
import { resolveBackend, detectProvider, resolveConfig } from "../src/config.ts"

/** resolveBackend/detectProvider take env explicitly, so tests are hermetic. */
const E = (over: Record<string, string> = {}): Record<string, string | undefined> => ({
  ...over,
})

describe("detectProvider", () => {
  test("explicit provider option wins over everything", () => {
    expect(detectProvider({ provider: "databricks" }, E({ TYPESAFE_API_KEY: "k" }))).toBe("databricks")
    expect(detectProvider({ provider: "systemone" }, E({ DATABRICKS_TOKEN: "t" }))).toBe("systemone")
  })
  test("explicit host/profile options mean databricks even if a TypeSafe key is set", () => {
    expect(detectProvider({ profile: "fevm-west" }, E({ TYPESAFE_API_KEY: "k" }))).toBe("databricks")
    expect(detectProvider({ host: "https://x.cloud.databricks.com" }, E({ TYPESAFE_API_KEY: "k" }))).toBe("databricks")
  })
  test("api key env var selects systemone", () => {
    expect(detectProvider({}, E({ TYPESAFE_API_KEY: "k" }))).toBe("systemone")
    expect(detectProvider({ apiKeyEnv: "MY_KEY" }, E({ MY_KEY: "k" }))).toBe("systemone")
  })
  test("databricks env vars select databricks", () => {
    expect(detectProvider({}, E({ DATABRICKS_TOKEN: "t" }))).toBe("databricks")
    expect(detectProvider({}, E({ DATABRICKS_HOST: "https://x" }))).toBe("databricks")
    expect(detectProvider({}, E({ DATABRICKS_CONFIG_PROFILE: "p" }))).toBe("databricks")
  })
  test("nothing configured -> undefined", () => {
    expect(detectProvider({}, E())).toBeUndefined()
  })
})

describe("resolveBackend", () => {
  test("systemone default url + model", () => {
    const r = resolveBackend({}, E({ TYPESAFE_API_KEY: "k" }))
    expect(r.backend).toMatchObject({
      provider: "systemone",
      url: "https://api.typesafe.ai/v1/systemone",
      model: "jev-latest",
      apiKeyEnv: "TYPESAFE_API_KEY",
    })
  })
  test("systemone url override wins", () => {
    const r = resolveBackend({ url: "https://proxy.example.com/systemone" }, E({ TYPESAFE_API_KEY: "k" }))
    expect(r.backend?.url).toBe("https://proxy.example.com/systemone")
  })
  test("databricks host + gateway path", () => {
    const r = resolveBackend({ host: "https://x.cloud.databricks.com/" }, E())
    expect(r.backend).toMatchObject({
      provider: "databricks",
      url: "https://x.cloud.databricks.com/ai-gateway/typesafe/v1/systemone",
      model: "system.ai.openjev-qwen35-4b",
    })
  })
  test("databricks profile-only leaves url empty for later resolution", () => {
    const r = resolveBackend({ profile: "fevm-west" }, E())
    expect(r.backend).toMatchObject({ provider: "databricks", profile: "fevm-west", url: "" })
  })
  test("databricks url override skips host resolution", () => {
    const r = resolveBackend({ provider: "databricks", url: "https://x/gw" }, E())
    expect(r.backend?.url).toBe("https://x/gw")
  })
  test("databricks token without host is unconfigured with a helpful message", () => {
    const r = resolveBackend({}, E({ DATABRICKS_TOKEN: "t" }))
    expect(r.backend).toBeUndefined()
    expect(r.unconfigured).toMatch(/DATABRICKS_HOST/)
  })
  test("nothing at all -> unconfigured", () => {
    const r = resolveBackend({}, E())
    expect(r.backend).toBeUndefined()
    expect(r.unconfigured).toMatch(/TYPESAFE_API_KEY/)
  })
  test("explicit provider + model override", () => {
    const r = resolveBackend({ provider: "systemone", model: "jev-1.13.0" }, E({ TYPESAFE_API_KEY: "k" }))
    expect(r.backend?.model).toBe("jev-1.13.0")
  })
})

describe("resolveConfig (backend wiring)", () => {
  test("unconfigured when no backend resolves", () => {
    // resolveConfig reads process.env; ensure a clean slate for these vars
    const saved = { ...process.env }
    delete process.env.TYPESAFE_API_KEY
    delete process.env.DATABRICKS_TOKEN
    delete process.env.DATABRICKS_HOST
    delete process.env.DATABRICKS_CONFIG_PROFILE
    try {
      const cfg = resolveConfig({})
      expect(cfg.backend).toBeUndefined()
      expect(cfg.unconfigured).toBeTruthy()
    } finally {
      process.env = saved
    }
  })
})
