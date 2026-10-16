/**
 * TUI half of opencode-auto: a hotkey that toggles auto mode and a footer
 * indicator showing whether it is on. The permission hook lives in the
 * server plugin (src/index.ts); this side only talks to it over the RPC in
 * src/rpc.ts and follows its "changed" event, so every open TUI stays in sync.
 *
 * Default key: <leader>p (ctrl+x then p). Override with the `toggleKey`
 * plugin option. The command is also listed in the command palette (ctrl+p).
 */
import { Plugin } from "@opencode/plugin/tui"
import { createSignal, Show } from "solid-js"
import { indicator, toast, type Tone } from "./indicator.js"
import { Auto, type AutoStatus } from "./rpc.js"

const COMMAND = "opencode-auto.toggle"
const DEFAULT_KEY = "<leader>p"
const TITLE = "opencode-auto"

export default Plugin.define({
  id: "opencode-auto.tui",
  setup(context) {
    const auto = context.client.rpc(Auto)
    const [status, setStatus] = createSignal<AutoStatus>()

    const fetchStatus = () =>
      auto
        .status({})
        .then((s) => s as AutoStatus)
        .catch(() => undefined)

    // Hidden until the server plugin answers (e.g. not installed on a remote server).
    void fetchStatus().then(setStatus)
    const stop = auto.events.on("changed", (event) => {
      setStatus(event.data as AutoStatus)
    })

    const flip = async () => {
      const current = status() ?? (await fetchStatus())
      if (!current) {
        context.ui.toast.show({ title: TITLE, message: "Auto mode server plugin is not reachable", variant: "error" })
        return
      }
      try {
        const next = (await auto.set({ enabled: !current.enabled })) as AutoStatus
        setStatus(next)
        context.ui.toast.show({ title: TITLE, ...toast(next) })
      } catch (e) {
        context.ui.toast.show({
          title: TITLE,
          message: `Toggle failed: ${e instanceof Error ? e.message : String(e)}`,
          variant: "error",
        })
      }
    }

    const key = typeof context.options.toggleKey === "string" ? context.options.toggleKey : DEFAULT_KEY
    context.keymap.layer(() => ({
      mode: "global",
      commands: [
        {
          id: COMMAND,
          title: "Toggle auto mode",
          description: "Turn opencode-auto permission classification on or off",
          group: "Auto",
          bind: key,
          palette: true,
          run: () => flip(),
        },
      ],
      bindings: [COMMAND],
    }))

    const color = (tone: Tone) =>
      tone === "on"
        ? context.theme.text.feedback.success.base
        : tone === "off"
          ? context.theme.text.muted
          : context.theme.text.feedback.warning.base

    const Indicator = (props: { hint?: boolean }) => {
      const view = () => {
        const s = status()
        return s ? indicator(s) : undefined
      }
      const shortcut = () => (props.hint ? context.keymap.shortcuts(COMMAND)[0] : undefined)
      return (
        <Show when={view()}>
          <box flexDirection="row">
            <text fg={color(view()?.tone ?? "off")}>{view()?.label}</text>
            <Show when={shortcut()}>
              <text fg={context.theme.text.muted}>{` (${shortcut()} to toggle)`}</text>
            </Show>
          </box>
        </Show>
      )
    }

    const unslotPrompt = context.ui.slot({ append: "prompt.footer.status", render: () => <Indicator hint /> })
    const unslotHome = context.ui.slot({ append: "home.footer.status", render: () => <Indicator /> })

    return () => {
      stop()
      unslotPrompt()
      unslotHome()
    }
  },
})
