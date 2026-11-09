import { describe, expect, test } from "bun:test"
import { createLedger } from "../src/ledger.ts"

const TMP = "/private/var/folders/xx/T/opencode"

describe("createLedger", () => {
  test("empty ledger has no summary", () => {
    expect(createLedger([TMP]).summary()).toBeUndefined()
  })

  test("records tables, branches, and temp files from completed commands", () => {
    const l = createLedger([TMP])
    l.record("databricks api post /api/2.0/sql/statements --json '{\"statement\":\"CREATE OR REPLACE TABLE main.gold.floors_verify AS SELECT 1\"}'")
    l.record("python3 -c \"df.write.saveAsTable('main.scratch.t1')\"")
    l.record("git checkout -b fix/parser && git status")
    l.record(`npx marp deck.md -o ${TMP}/deck/slide.png`)
    l.record(undefined)
    const s = l.summary()!
    expect(s).toContain("main.gold.floors_verify")
    expect(s).toContain("main.scratch.t1")
    expect(s).toContain("fix/parser")
    expect(s).toContain(`${TMP}/deck/slide.png`)
  })

  test("CREATE OR REPLACE and IF NOT EXISTS forms", () => {
    const l = createLedger([])
    l.record("CREATE TABLE IF NOT EXISTS a.b.c (x INT)")
    expect(l.summary()).toContain("a.b.c")
  })
})
