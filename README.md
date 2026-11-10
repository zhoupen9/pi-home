# pi-home

Versioned, non-secret part of my [`pi`](https://github.com/earendil-works/pi) home
directory (`~/.pi`). Everything here is meant to be symlinked, copied, or cloned
onto another machine.

## What is tracked

| Path | What it is |
|---|---|
| `agent/extensions/plan-build-mode.ts` | Local extension: `plan` / `readonly` / `build` modes with a kernel-enforced (`bwrap`) read-only workspace |
| `agent/settings.json` | Global pi settings (theme, default provider/model, thinking level, default tools) |
| `agent/models.json.example` | Provider template — copy to `agent/models.json` and add your key |
| `biome.json` | Formatter config used by the extension's tooling |

## What is deliberately NOT tracked

`.gitignore` excludes credentials and machine state: `agent/auth.json`,
`agent/models.json` (holds a live API key), `agent/models-store.json`,
`agent/trust.json`, `agent/sessions/` (full conversation transcripts),
`pi-acp/`, and the managed install (`agent/install/`, `agent/bin/` — `pi update`
owns those).

## Setup on a new machine

```sh
git clone git@github.com:zhoupen9/pi-home.git ~/.pi-home
# merge into an existing ~/.pi, or use it as the base of a fresh one:
cp -r ~/.pi-home/agent/extensions ~/.pi/agent/
cp    ~/.pi-home/agent/settings.json ~/.pi/agent/
cp    ~/.pi-home/agent/models.json.example ~/.pi/agent/models.json   # then add your key
```

## plan / readonly / build modes

`agent/extensions/plan-build-mode.ts` needs `bwrap` (bubblewrap) on Linux;
without it, the sandboxed modes fall back to a conservative shell-token
allowlist and say so in `/mode`.

| Mode | Enforcement | Denial behaviour |
|---|---|---|
| `/plan` | read-only workspace (kernel), private ephemeral `/tmp`, mutating tools disabled | planning feedback: do not retry, no grant is offered; only the user leaves via `/build` |
| `/readonly` | identical enforcement | recoverable fact: an exact retry asks you to approve a one-shot `workspace-write` / `unrestricted` grant |
| `/build` | none | — |

The mode also appears in the system prompt as a `<file_policy>` section, so the
agent cannot miss it; `Ctrl+Alt+P` toggles plan ↔ build, and `--plan` starts in
plan mode.
