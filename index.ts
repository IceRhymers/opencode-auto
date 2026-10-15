/**
 * Package entry point. OpenCode V2 resolves a plugin package directory by
 * looking for <dir>/server.* then <dir>/index.* — package.json "main" is not
 * consulted — so this shim re-exports the real plugin from src/.
 */
export { default } from "./src/index.ts"
