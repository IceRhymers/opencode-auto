import { describe, expect, test } from "bun:test"
import { createAuth, createApiKeyAuth, createDatabricksTokenAuth, createCliAuth } from "../src/auth.ts"

type FakeRes = { exitCode: number; stdout: string; stderr: string }

/** Minimal fake of the plugin shell: records commands, returns canned results. */
function fakeShell(results: FakeRes[]) {
  const calls: string[] = []
  let i = 0
  const $ = (strings: TemplateStringsArray, ...values: unknown[]) => {
    // rebuild the command string (raw values are {raw} objects)
    let cmd = ""
    strings.forEach((s, j) => {
      cmd += s
      if (j < values.length) {
        const v = values[j] as { raw?: string }
        cmd += v && typeof v === "object" && "raw" in v ? v.raw : String(v)
      }
    })
    calls.push(cmd)
    const res = results[Math.min(i++, results.length - 1)]
    return {
      quiet: () => ({
        nothrow: async () => ({
          exitCode: res.exitCode,
          stdout: Buffer.from(res.stdout),
          stderr: Buffer.from(res.stderr),
        }),
      }),
    }
  }
  return { $: $ as never, calls }
}

const TOKEN_JSON = JSON.stringify({ access_token: "tok-abc", expiry: new Date(Date.now() + 3600e3).toISOString() })

describe("createApiKeyAuth", () => {
  test("returns the key from the env var", async () => {
    process.env.TEST_JEV_KEY = "secret-1"
    const a = createApiKeyAuth("TEST_JEV_KEY")
    expect(a.describe).toBe("env:TEST_JEV_KEY")
    expect(await a.token()).toBe("secret-1")
    delete process.env.TEST_JEV_KEY
  })
  test("re-reads on every call (rotation without restart)", async () => {
    process.env.TEST_JEV_KEY = "a"
    const a = createApiKeyAuth("TEST_JEV_KEY")
    expect(await a.token()).toBe("a")
    process.env.TEST_JEV_KEY = "b"
    expect(await a.token()).toBe("b")
    delete process.env.TEST_JEV_KEY
  })
  test("missing var throws with setup guidance", async () => {
    delete process.env.TEST_JEV_MISSING
    await expect(createApiKeyAuth("TEST_JEV_MISSING").token()).rejects.toThrow(/TEST_JEV_MISSING is not set/)
  })
})

describe("createDatabricksTokenAuth", () => {
  test("returns DATABRICKS_TOKEN", async () => {
    process.env.DATABRICKS_TOKEN = "pat-9"
    expect(await createDatabricksTokenAuth().token()).toBe("pat-9")
    delete process.env.DATABRICKS_TOKEN
  })
  test("missing token throws", async () => {
    delete process.env.DATABRICKS_TOKEN
    await expect(createDatabricksTokenAuth().token()).rejects.toThrow(/DATABRICKS_TOKEN is not set/)
  })
})

describe("createCliAuth", () => {
  test("mints a token via the CLI and caches it", async () => {
    const { $, calls } = fakeShell([{ exitCode: 0, stdout: TOKEN_JSON, stderr: "" }])
    const a = createCliAuth({ profile: "fevm-west" }, $)
    expect(a.describe).toBe("cli-profile:fevm-west")
    expect(await a.token()).toBe("tok-abc")
    expect(await a.token()).toBe("tok-abc") // cached: still one CLI call
    expect(calls.filter((c) => c.includes("auth token")).length).toBe(1)
    expect(calls[0]).toContain("--profile fevm-west")
  })
  test("passes --host when provided", async () => {
    const { $, calls } = fakeShell([{ exitCode: 0, stdout: TOKEN_JSON, stderr: "" }])
    const a = createCliAuth({ profile: "p", host: "https://x.cloud.databricks.com" }, $)
    await a.token()
    expect(calls[0]).toContain("--host https://x.cloud.databricks.com")
  })
  test("attempts login once when token fails, then retries", async () => {
    const { $, calls } = fakeShell([
      { exitCode: 1, stdout: "", stderr: "no session" },
      { exitCode: 0, stdout: "", stderr: "" }, // login
      { exitCode: 0, stdout: TOKEN_JSON, stderr: "" }, // retry
    ])
    const a = createCliAuth({ profile: "p" }, $)
    expect(await a.token()).toBe("tok-abc")
    expect(calls.some((c) => c.includes("auth login"))).toBe(true)
  })
  test("throws a helpful error when the CLI never yields a token", async () => {
    const { $ } = fakeShell([{ exitCode: 1, stdout: "", stderr: "boom" }])
    const a = createCliAuth({ profile: "p" }, $)
    await expect(a.token()).rejects.toThrow(/databricks auth token failed/)
  })
})

describe("createAuth dispatch", () => {
  test("routes to the right source", () => {
    process.env.K1 = "v"
    expect(createAuth({ kind: "apiKeyEnv", envName: "K1" }, undefined as never).describe).toBe("env:K1")
    expect(createAuth({ kind: "databricksToken" }, undefined as never).describe).toBe("env:DATABRICKS_TOKEN")
    expect(createAuth({ kind: "cliProfile", profile: "p" }, undefined as never).describe).toBe("cli-profile:p")
    delete process.env.K1
  })
})
