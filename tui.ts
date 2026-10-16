/**
 * TUI entry point. OpenCode loads a plugin directory's <dir>/tui.* beside
 * <dir>/index.* (see index.ts), so this shim re-exports the real TUI plugin.
 */
export { default } from "./src/tui.tsx"
