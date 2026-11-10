/**
 * Plan / Read-only / Build Mode Extension (kernel-sandboxed)
 *
 * Three modes over TWO independent axes: does the agent intend to change
 * things (guidance), and may the machine change things (enforcement)? Mixing
 * those axes is what makes a read-only gate fight the planning mode, so they
 * are separate modes here:
 *
 *   /plan     PLAN      Guidance: explore and design, do not implement.
 *                       Enforcement: read-only workspace. NO ESCALATION — a
 *                       denied write is a planning signal ("put it in the
 *                       plan"), not a permission request. The only exit is
 *                       an explicit user switch (/build).
 *
 *   /readonly READ-ONLY Pure file-effect policy with no planning intent.
 *                       Same sandbox, but a denied command IS a recoverable
 *                       permission fact: retrying that exact command asks the
 *                       user for a one-shot strictly-wider grant
 *                       (workspace-write or danger-full-access).
 *
 *   /build    BUILD     Full access, nothing wrapped.
 *
 * Both sandboxed modes wrap every bash command in a `bwrap` read-only profile:
 *
 *   bwrap --ro-bind / / --dev /dev --unshare-pid --proc /proc \
 *         --die-with-parent --tmpfs /tmp --setenv TMPDIR /tmp \
 *         -- bash -c '<command>'
 *
 * Consequences: the command text is never inspected, so any shell syntax works
 * (`cd x && ...`, pipes, loops, `2>/dev/null`, `find -exec`, `git -C`, greps
 * for "rm"/"sudo", ...), and writes fail with the kernel's own EROFS
 * ("Read-only file system") whatever they look like — `rm`, `sed -i`,
 * redirections, an interpreter writing from inside, a wrapper binary.
 *
 * The private /tmp is deliberate: it keeps read-only *analysis* working (npm
 * and tsc caches, mkstemp, `git status` index refreshes) so the denials that
 * remain are workspace writes — i.e. implementation, which plan mode must
 * never turn into a permission prompt.
 *
 * File-modifying tools (edit, write, ...) are removed from the active tool set
 * and hard-blocked in both sandboxed modes, because those tools have no
 * filesystem fence of their own; a blocked mutation points at /build.
 *
 * If no `bwrap` is usable on this host, the sandboxed modes fail closed to a
 * conservative shell-token allowlist (quote aware, per simple command) and say
 * so in the prompt and in /mode. Set FALLBACK to "deny" to refuse bash instead.
 *
 * Usage:
 *   /plan        plan mode: read-only, no escalation, guidance to plan
 *   /readonly    read-only enforcement with one-shot escalation
 *   /build       full access
 *   /mode        show the current mode and the active enforcement backend
 *   Ctrl+Alt+P   toggle plan/read-only <-> build
 *   --plan       start pi in plan mode
 *
 * Install: put this file in ~/.pi/agent/extensions/ (global) or
 * .pi/extensions/ (project-local), then /reload or restart pi.
 *
 * Requires `bwrap` (bubblewrap) for enforced read-only mode. Linux only: macOS
 * would want `sandbox-exec`, Windows a restricted token; this extension keeps
 * the allowlist fallback on those platforms.
 */

import { spawnSync } from "node:child_process";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent, ToolResultEvent } from "@earendil-works/pi-coding-agent";
import { isBashToolResult, isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { Key } from "@earendil-works/pi-tui";

type Mode = "plan" | "readonly" | "build";

/** Both sandboxed modes enforce a read-only workspace; only plan mode withholds
 * escalation, because there its denials are about intent, not permission. */
function sandboxed(mode: Mode): boolean {
	return mode !== "build";
}

/** Escalation is a read-only POLICY affordance, never a planning one. */
function escalatable(mode: Mode): boolean {
	return mode === "readonly";
}

/** A granted file-effect mode for one bash call. */
type Grant = "read-only" | "workspace-write" | "danger-full-access";

/** What the fallback does when no kernel sandbox is usable. */
const FALLBACK: "allowlist" | "deny" = "allowlist";

/** Give sandboxed modes a private ephemeral /tmp (scratch space is not "the project"). */
const PRIVATE_TMP = true;

// Tool names that mutate state. Disabled from the active set and hard-blocked
// at tool_call time while in plan mode (defense in depth, in case a tool is
// called from stale context or registered dynamically).
const MUTATING_TOOLS = new Set<string>([
	"edit",
	"write",
	"write_file",
	"edit_file",
	"delete",
	"delete_file",
	"patch",
	"apply_patch",
	"create",
	"create_file",
	"update_file",
	"modify",
	"append",
	"prepend",
	"insert",
	"rename",
	"move",
	"mkdir",
	"rmdir",
	"unlink",
	"upload",
	"publish",
	"install",
	"uninstall",
	"commit",
	"push",
	"merge",
	"rebase",
	"apply",
]);

// ---------------------------------------------------------------------------
// Kernel sandbox (bwrap)
// ---------------------------------------------------------------------------

/** The read-only mount profile: everything read-only except the /dev sink. */
const BWRAP_RO_ARGS = [
	"--ro-bind",
	"/",
	"/",
	"--dev",
	"/dev",
	"--unshare-pid",
	"--proc",
	"/proc",
	"--die-with-parent",
];

/** bwrap's denial dialect: a blocked file effect is EROFS. */
const DENIAL_TEXT = /read-only file system/i;

export type SandboxState = { available: true } | { available: false; reason: string };

let sandboxState: SandboxState | undefined;

/**
 * Probe `bwrap` once by applying the real read-only profile to `true`. A
 * privileged or unprivileged install both work; a missing binary, a kernel
 * without unprivileged user namespaces, or a refusing helper all fail here.
 */
export function probeSandbox(cwd?: string): SandboxState {
	if (sandboxState !== undefined) return sandboxState;
	if (process.platform !== "linux") {
		sandboxState = { available: false, reason: `bwrap is Linux-only (platform: ${process.platform})` };
		return sandboxState;
	}
	try {
		const probe = spawnSync("bwrap", [...BWRAP_RO_ARGS, "--", "true"], {
			timeout: 5000,
			stdio: "ignore",
			...(cwd === undefined ? {} : { cwd }),
		});
		if (probe.error !== undefined) {
			sandboxState = { available: false, reason: probe.error.message };
		} else if (probe.status === 0) {
			sandboxState = { available: true };
		} else {
			sandboxState = {
				available: false,
				reason: `probe exited ${probe.status ?? probe.signal ?? "?"}`,
			};
		}
	} catch (error) {
		sandboxState = { available: false, reason: String(error) };
	}
	return sandboxState;
}

/** POSIX single-quote escaping for one shell word. */
function shQuote(word: string): string {
	return `'${word.replaceAll("'", `'\\''`)}'`;
}

/**
 * Build the wrapped command string for one grant. `read-only` gets the base
 * profile plus a private /tmp; `workspace-write` also binds the workspace root
 * (the bwrap spelling of the dsh workspace-write mode); `danger-full-access`
 * returns the command unchanged.
 */
export function sandboxCommand(command: string, cwd: string, grant: Grant): string {
	if (grant === "danger-full-access") return command;
	const args = [...BWRAP_RO_ARGS];
	// A private, ephemeral /tmp keeps read-only ANALYSIS tooling working (package
	// and compiler caches, mkstemp, `git status` index refreshes), so the denials
	// that remain are workspace writes. Skipped when the session itself lives
	// under /tmp, which the tmpfs would shadow.
	const underTmp = cwd === "/tmp" || cwd.startsWith("/tmp/");
	if (PRIVATE_TMP && !underTmp) args.push("--tmpfs", "/tmp", "--setenv", "TMPDIR", "/tmp");
	if (grant === "workspace-write" && cwd !== "/") args.push("--bind", shQuote(cwd), shQuote(cwd));
	return ["bwrap", ...args, "--", "bash", "-c", shQuote(command)].join(" ");
}

// ---------------------------------------------------------------------------
// Fallback gate: shell-token allowlist for hosts without a kernel sandbox.
//
// This is a best-effort net, not a boundary. It tokenizes with quote awareness
// and judges each simple command by its own words, so it does not deny a
// read-only command for *mentioning* a blocked word, nor for containing `>` in
// a quoted argument — the two failure modes of a raw regex scan.
// ---------------------------------------------------------------------------

type Token = { value: string; quoted: boolean; op: boolean };

const OPERATOR_CHARS = new Set([";", "&", "|", "(", ")", "<", ">"]);

/** Quote-aware split into words and operators (`2>` keeps its fd digit). */
export function tokenize(command: string): Token[] {
	const tokens: Token[] = [];
	let word = "";
	let quoted = false;
	let started = false;
	let quote: '"' | "'" | null = null;

	const flush = (): void => {
		if (!started) return;
		tokens.push({ value: word, quoted, op: false });
		word = "";
		quoted = false;
		started = false;
	};

	for (let i = 0; i < command.length; i++) {
		const ch = command[i] as string;
		if (quote !== null) {
			if (ch === quote) {
				quote = null;
				quoted = true;
			} else if (quote === '"' && ch === "\\" && i + 1 < command.length) {
				word += command[++i];
			} else {
				word += ch;
			}
			continue;
		}
		if (ch === '"' || ch === "'") {
			quote = ch;
			quoted = true;
			started = true;
			continue;
		}
		if (ch === "\\" && i + 1 < command.length) {
			word += command[++i];
			started = true;
			continue;
		}
		if (/\s/.test(ch)) {
			flush();
			continue;
		}
		if (OPERATOR_CHARS.has(ch)) {
			// `2>` / `2>>`: the fd digit is part of the redirection operator.
			let op = "";
			if (started && /^[0-9]+$/.test(word)) {
				op = word;
				word = "";
				quoted = false;
				started = false;
			} else {
				flush();
			}
			op += ch;
			while (i + 1 < command.length && OPERATOR_CHARS.has(command[i + 1] as string)) {
				op += command[++i];
			}
			tokens.push({ value: op, quoted: false, op: true });
			continue;
		}
		word += ch;
		started = true;
	}
	flush();
	return tokens;
}

const FORBIDDEN_COMMANDS = new Set([
	// filesystem / metadata writers
	"rm", "rmdir", "mv", "cp", "ln", "touch", "mkdir", "mkfifo", "mknod", "unlink",
	"chmod", "chown", "chgrp", "chattr", "setfacl", "truncate", "dd", "shred", "tee",
	"install", "rsync", "sync", "mount", "umount", "swapon", "swapoff",
	// privilege / process / system control
	"sudo", "su", "doas", "kill", "pkill", "killall", "reboot", "shutdown", "poweroff",
	"halt", "systemctl", "service", "systemd-run", "crontab", "at", "useradd", "usermod",
	"passwd", "chpasswd", "modprobe", "insmod", "rmmod", "sysctl",
	// package / build / toolchain writers
	"npm", "npx", "yarn", "pnpm", "bun", "pip", "pip3", "uv", "poetry", "conda",
	"apt", "apt-get", "dpkg", "dnf", "yum", "pacman", "brew", "cargo", "go", "make",
	"cmake", "ninja", "gradle", "mvn", "docker", "podman", "kubectl", "helm", "terraform",
	// interactive editors / pagers that own the terminal
	"vi", "vim", "nvim", "nano", "emacs", "code", "subl", "less", "more", "top", "htop",
	// arbitrary code / relocation wrappers
	"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "deno",
	"perl", "ruby", "php", "lua", "osascript", "eval",
]);

const WRAPPERS = new Set(["env", "command", "nohup", "time", "exec", "builtin", "xargs", "nice", "ionice"]);

const GIT_WRITE_SUBCOMMANDS = new Set([
	"add", "commit", "push", "pull", "fetch", "merge", "rebase", "reset", "checkout",
	"restore", "switch", "stash", "cherry-pick", "revert", "tag", "init", "clone",
	"apply", "am", "rm", "mv", "gc", "prune", "clean", "notes", "update-index",
	"write-tree", "commit-tree", "worktree", "submodule", "config", "branch",
	"filter-branch", "replace", "reflog",
]);

const NULLISH_TARGET = /^(\/dev\/(null|stdout|stderr|tty|fd\/[0-9]+)|&[0-9]+|-)$/;

function basename(word: string): string {
	const slash = word.lastIndexOf("/");
	return slash === -1 ? word : word.slice(slash + 1);
}

/** Judge one tokenized command line against the conservative fallback rules. */
export function fallbackAllows(command: string): { allowed: boolean; reason?: string } {
	const tokens = tokenize(command);

	// Redirections: any write target except the null sink is a mutation.
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i] as Token;
		if (!token.op || !token.value.includes(">")) continue;
		if (token.value.endsWith("&")) continue; // fd duplication: 2>&1
		if (token.value.startsWith("<<")) continue; // heredoc input
		const target = tokens[i + 1];
		if (target === undefined || !NULLISH_TARGET.test(target.value)) {
			return { allowed: false, reason: `redirection "${token.value} ${target?.value ?? ""}" writes a file` };
		}
	}

	// Each simple command is judged by its own argv, not by the whole line.
	let expectCommand = true;
	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i] as Token;
		if (token.op) {
			if (token.value !== "<" && !token.value.startsWith("<<")) expectCommand = true;
			continue;
		}
		if (!expectCommand) continue;
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token.value)) continue; // VAR=value prefix
		if (token.value === "!" || token.value === "{" || token.value === "}") continue;
		if (WRAPPERS.has(basename(token.value))) {
			// `env FOO=1 cmd`, `nice -n 5 cmd`, `xargs cmd`: keep looking.
			continue;
		}

		const command = basename(token.value);
		if (FORBIDDEN_COMMANDS.has(command)) {
			return { allowed: false, reason: `"${command}" can modify files or state` };
		}

		const args: string[] = [];
		for (let j = i + 1; j < tokens.length && !(tokens[j] as Token).op; j++) args.push((tokens[j] as Token).value);

		if (command === "git") {
			const sub = args.find((arg) => !arg.startsWith("-"));
			if (sub !== undefined && GIT_WRITE_SUBCOMMANDS.has(sub)) {
				if (sub === "branch" || sub === "config" || sub === "reflog" || sub === "worktree") {
					if (!args.some((arg) => /^(-[dDmMcC]|--(delete|move|copy|set|unset|add|remove|edit|prune))/.test(arg))) {
						expectCommand = false;
						continue;
					}
				}
				return { allowed: false, reason: `"git ${sub}" writes repository state` };
			}
			expectCommand = false;
			continue;
		}

		if (command === "find" && args.some((arg) => /^-(delete|exec|execdir|ok|okdir|fprint|fprint0|fprintf|fls)$/.test(arg))) {
			return { allowed: false, reason: '"find" with -exec/-delete/-fprint writes' };
		}
		if ((command === "sed" || command === "perl" || command === "ruby") && args.some((arg) => /^(-i|--in-place|-pi|-[a-zA-Z]*i[a-zA-Z]*$)/.test(arg))) {
			return { allowed: false, reason: `"${command} -i" edits files in place` };
		}
		if (command === "sort" && args.some((arg) => arg === "-o" || arg.startsWith("--output"))) {
			return { allowed: false, reason: '"sort -o" writes a file' };
		}
		if (command === "date" && args.some((arg) => arg === "-s" || arg.startsWith("--set"))) {
			return { allowed: false, reason: '"date -s" changes the clock' };
		}
		if (command === "awk" && tokens.some((t) => !t.op && /system\s*\(|print[f]?\s*[>|]|\|&/.test(t.value))) {
			return { allowed: false, reason: "awk program can write or spawn" };
		}
		expectCommand = false;
	}

	// A line that only assigns variables or is empty changes nothing.
	return { allowed: true };
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

const STATE_ENTRY = "plan-build-mode";
const MODE_CONTEXT = "plan-build-mode-context";

/** Per-call bookkeeping so a denial can be attributed to its command. */
interface WrappedCall {
	command: string;
	grant: Grant;
}

/** One denied command, remembered for the strictly-wider one-shot retry. */
interface DeniedCommand {
	command: string;
	grant: Grant;
}

const WIDER: Record<Grant, Grant[]> = {
	"read-only": ["workspace-write", "danger-full-access"],
	"workspace-write": ["danger-full-access"],
	"danger-full-access": [],
};

const GRANT_LABEL: Record<Grant, string> = {
	"read-only": "read-only (current)",
	"workspace-write": "allow once: write inside the workspace",
	"danger-full-access": "allow once: unrestricted",
};

export default function planBuildMode(pi: ExtensionAPI): void {
	let mode: Mode = "build";
	let toolsBeforePlan: string[] | undefined;

	/** Bash calls currently in flight, keyed by tool call id. */
	const wrappedCalls = new Map<string, WrappedCall>();
	/** Commands the sandbox denied, keyed by normalized command text. */
	const deniedCommands = new Map<string, DeniedCommand>();

	pi.registerFlag("plan", {
		description: "Start in plan mode (read-only)",
		type: "boolean",
		default: false,
	});

	function sandboxSummary(): string {
		const state = probeSandbox();
		if (state.available) return "read-only via bwrap";
		return FALLBACK === "deny"
			? `bash DISABLED (no sandbox: ${state.reason})`
			: `read-only via conservative allowlist (no sandbox: ${state.reason})`;
	}

	function updateStatus(ctx: ExtensionContext): void {
		if (mode === "build") {
			ctx.ui.setStatus("plan-build-mode", ctx.ui.theme.fg("success", "🔨 build"));
			return;
		}
		const state = probeSandbox();
		const backend = state.available ? "sandboxed" : "allowlist";
		const label = mode === "plan" ? `⏸ plan (${backend})` : `🔒 read-only (${backend})`;
		ctx.ui.setStatus("plan-build-mode", ctx.ui.theme.fg("warning", label));
	}

	function persist(): void {
		// The pre-plan active set rides along: after a reload or a resume into plan
		// mode, `toolsBeforePlan` is empty in the fresh instance, so re-capturing
		// `getActiveTools()` would record the ALREADY FILTERED set and `/build`
		// would never give the mutating tools back.
		pi.appendEntry(STATE_ENTRY, { mode, tools: toolsBeforePlan });
	}

	function applyPlanTools(): void {
		const active = toolsBeforePlan ?? pi.getActiveTools();
		toolsBeforePlan = active;
		pi.setActiveTools(active.filter((name) => !MUTATING_TOOLS.has(name)));
	}

	function applyBuildTools(): void {
		if (toolsBeforePlan !== undefined) {
			pi.setActiveTools(toolsBeforePlan);
			toolsBeforePlan = undefined;
		}
	}

	function setMode(next: Mode, ctx: ExtensionContext): void {
		if (mode === next) {
			ctx.ui.notify(`Already in ${mode} mode`, "info");
			return;
		}
		mode = next;
		deniedCommands.clear();
		const state = probeSandbox();
		if (!sandboxed(mode)) {
			applyBuildTools();
			ctx.ui.notify("Build mode: full access restored.", "info");
		} else {
			applyPlanTools();
			const what =
				mode === "plan"
					? "Plan mode: bash runs in a read-only workspace sandbox with a private /tmp. Writes are refused by the kernel; a denied write is planning feedback, not a permission request — /build is the only exit."
					: "Read-only mode: bash runs in a read-only workspace sandbox. A denied command can be retried once for a one-shot grant you approve.";
			ctx.ui.notify(
				state.available
					? what
					: `No sandbox available (${state.reason}); falling back to ${FALLBACK === "deny" ? "no bash" : "a conservative allowlist"}.`,
				state.available ? "warning" : "error",
			);
		}
		updateStatus(ctx);
		persist();
	}

	pi.registerCommand("plan", {
		description: "Plan mode: explore and design, no writes, no escalation prompts",
		handler: async (_args, ctx) => setMode("plan", ctx),
	});

	pi.registerCommand("readonly", {
		description: "Read-only enforcement: no writes, with one-shot escalation prompts",
		handler: async (_args, ctx) => setMode("readonly", ctx),
	});

	pi.registerCommand("build", {
		description: "Switch to build mode (full access)",
		handler: async (_args, ctx) => setMode("build", ctx),
	});

	pi.registerCommand("mode", {
		description: "Show current mode (plan/readonly/build) and its enforcement",
		handler: async (_args, ctx) => {
			if (mode === "build") {
				ctx.ui.notify("Current mode: build — full access", "info");
			} else {
				const escalation =
					mode === "plan"
						? "no escalation; denials are planning feedback, /build is the only exit"
						: "denied commands may be retried once for an approved one-shot grant";
				ctx.ui.notify(`Current mode: ${mode} — ${sandboxSummary()}; ${escalation}`, "info");
			}
		},
	});

	pi.registerShortcut(Key.ctrlAlt("p"), {
		description: "Toggle plan/build mode",
		handler: async (ctx) => setMode(mode === "build" ? "plan" : "build", ctx),
	});

	/**
	 * Ask the user for a strictly wider one-shot grant for a command the
	 * sandbox already denied. READ-ONLY MODE ONLY: plan mode never calls this,
	 * because turning a planning mistake into a permission prompt is exactly what
	 * makes the mode fight itself.
	 */
	async function resolveRetry(
		command: string,
		ctx: ExtensionContext,
	): Promise<{ grant: Grant } | { blocked: string }> {
		if (!escalatable(mode)) return { grant: "read-only" };
		const denied = deniedCommands.get(command);
		if (denied === undefined) return { grant: "read-only" };
		const wider = WIDER[denied.grant];
		if (wider.length === 0) return { grant: denied.grant };
		if (!ctx.hasUI) {
			return {
				blocked:
					"Read-only mode: this command needs a write grant, but no approval UI is available. Switch to build mode with /build.",
			};
		}
		deniedCommands.delete(command);
		const options = ["No — keep the workspace read-only", ...wider.map((grant) => GRANT_LABEL[grant])];
		const choice = await ctx.ui.select(
			`The read-only sandbox denied this command:\n\n  ${command.length > 300 ? `${command.slice(0, 300)}…` : command}\n\nGrant a one-shot write for this call?`,
			options,
		);
		const index = choice === undefined ? -1 : options.indexOf(choice) - 1;
		if (index < 0) {
			return {
				blocked:
					"Read-only mode: the user declined to grant write access for this command; it stays denied. Explain what is needed instead of working around it.",
			};
		}
		return { grant: wider[index] as Grant };
	}

	// Plan mode enforcement happens here: tools are blocked by name, bash is
	// wrapped in the read-only sandbox. In /readonly a previously denied command
	// offers the user a strictly wider one-shot grant; in /plan it never does.
	pi.on("tool_call", async (event: ToolCallEvent, ctx) => {
		if (!sandboxed(mode)) return;

		if (MUTATING_TOOLS.has(event.toolName)) {
			return {
				block: true,
				reason: `${mode === "plan" ? "Plan" : "Read-only"} mode: tool "${event.toolName}" is disabled. ${
					mode === "plan"
						? "Record the change as a step in the plan; the user switches to execution with /build."
						: "Switch to /build to make changes."
				}`,
			};
		}

		// PowerShell has no POSIX tokenizer to gate against, and there is no
		// sandbox on Windows either: fail closed instead of guessing.
		if (event.toolName === "powershell" && !probeSandbox(ctx.cwd).available) {
			return {
				block: true,
				reason: `${mode} mode: the powershell tool is unavailable while this host has no kernel sandbox. Switch to build mode with /build.`,
			};
		}

		if (!isToolCallEventType("bash", event)) return;

		const command = event.input.command;
		const sandbox = probeSandbox(ctx.cwd);

		if (sandbox.available) {
			// Plan mode: a write denial is planning feedback, so an exact retry stops
			// here instead of turning the mode into a series of permission prompts.
			if (!escalatable(mode) && deniedCommands.has(command)) {
				return {
					block: true,
					reason: "Plan mode: this exact command was already denied and writes stay denied while planning. Do not retry it and do not look for another write path — record it as a step in the plan and continue reading; the user leaves plan mode with /build.",
				};
			}
			const retry = await resolveRetry(command, ctx);
			if ("blocked" in retry) return { block: true, reason: retry.blocked };
			wrappedCalls.set(event.toolCallId, { command, grant: retry.grant });
			event.input.command = sandboxCommand(command, ctx.cwd, retry.grant);
			return;
		}

		// No kernel sandbox on this host: fall back to the token gate.
		if (FALLBACK === "deny") {
			return {
				block: true,
				reason: `${mode} mode: bash is disabled because no sandbox backend is usable (${sandbox.reason}). Switch to build mode with /build, or install bubblewrap.`,
			};
		}
		const verdict = fallbackAllows(command);
		if (!verdict.allowed) {
			return {
				block: true,
				reason: `${mode} mode: bash command blocked by the fallback allowlist (${verdict.reason ?? "not read-only"}). No kernel sandbox is available (${sandbox.reason}). Retry with read-only syntax, or switch to build mode with /build.`,
			};
		}
		return;
	});

	// Turn a kernel denial into an actionable result fact: remember the command
	// so an exact retry can offer the user a one-shot grant, and tell the model
	// what to do in this same turn.
	pi.on("tool_result", async (event: ToolResultEvent) => {
		const call = wrappedCalls.get(event.toolCallId);
		if (call === undefined) return;
		wrappedCalls.delete(event.toolCallId);
		if (!isBashToolResult(event)) return;

		// Do NOT require isError: a command such as `write > f; echo done` still exits
		// 0 after the kernel refused the write, and the bash tool marks a result as an
		// error only on a non-zero exit status. The backend's denial dialect is the
		// fact to match — the same rule the process sandbox documents.

		const text = event.content
			.filter((part): part is { type: "text"; text: string } => part.type === "text")
			.map((part) => part.text)
			.join("\n");
		if (!DENIAL_TEXT.test(text)) return;

		// Bounded: a denial is only remembered long enough for an exact retry.
		if (deniedCommands.size >= 32) {
			const oldest = deniedCommands.keys().next();
			if (!oldest.done) deniedCommands.delete(oldest.value);
		}
		deniedCommands.set(call.command, { command: call.command, grant: call.grant });
		const wider = WIDER[call.grant];
		const exitNote = event.isError
			? []
			: [
					"[sandbox: note — the shell still reported success because a later part of the command ran; the denied write did NOT happen]",
				];
		// The SAME kernel denial means two different things per mode, so the marker
		// must not be shared: in plan mode it is planning feedback (never an
		// invitation to ask for write access); in read-only mode it is a
		// recoverable permission fact.
		const hint = escalatable(mode)
			? wider.length === 0
				? "[sandbox: file access denied under danger-full-access mode — this is not a sandbox denial; read the error above]"
				: [
						`[sandbox: file access denied under ${call.grant} mode]`,
						...exitNote,
						`[sandbox: escalation available — retry this exact command once; it will ask the user for a one-shot ${wider.join(" or ")} grant]`,
					].join("\n")
			: [
					"[plan mode: the write did not happen and will not be retried automatically]",
					...exitNote,
					"[plan mode: a denied write is planning feedback, not a permission problem — record the step in the plan and keep exploring; do not retry it or find another write path. Only the user leaves plan mode, with /build]",
				].join("\n");

		return {
			content: [...event.content, { type: "text" as const, text: `\n${hint}` }],
		};
	});

	/**
	 * One authoritative line for the SYSTEM PROMPT. The detailed rules below ride a
	 * custom message, which is conversation content — a model can discount it or
	 * lose it in a long context. The system prompt is where a mode policy belongs,
	 * and it changes only when the mode changes, so the prefix stays cacheable.
	 */
	function policyNotice(): string {
		if (mode === "plan") {
			return "PLAN MODE - READ-ONLY. The workspace is write-protected by the kernel (writes fail with EROFS; /tmp is a private ephemeral tmpfs). File-modifying tools are disabled. A denied write is PLANNING FEEDBACK: record it in the plan, do not retry it and do not seek another write path. No write grant is offered in this mode; only the user can leave it, with /build.";
		}
		if (mode === "readonly") {
			return "READ-ONLY MODE - NO WORKSPACE CHANGES. The workspace is write-protected by the kernel (writes fail with EROFS; /tmp is a private ephemeral tmpfs) and file-modifying tools are disabled, but this is NOT plan mode: complete the task with reads and read-only commands. A denied command may be retried once, which asks the user to approve a one-shot wider grant.";
		}
		return "BUILD MODE - FULL ACCESS. No sandbox: commands and file edits run with the process's authority.";
	}

	// Tell the agent what it may / may not do and how enforcement works.
	pi.on("before_agent_start", async (event) => {
		event.systemPromptOptions.sections["file_policy"] = policyNotice();
		const sandbox = sandboxed(mode) ? probeSandbox() : undefined;
		const content =
			mode === "plan"
				? `[PLAN MODE ACTIVE - READ-ONLY]
You are in PLAN MODE. You MUST NOT change anything:
- File-modifying tools (edit, write, delete, ...) are disabled.
- Bash enforcement: ${sandboxSummary()}.
${
	sandbox?.available === true
		? `- Every bash command runs inside a read-only workspace sandbox with a private /tmp. Reads, searches, \`git log|status|diff|show\`, pipes, \`cd x && ...\`, loops, \`2>/dev/null\`, \`find -exec\` and any other read-only shell syntax work normally. The sandbox does not inspect your command text, so there are no forbidden keywords: judge by effect, not by spelling.
- /tmp is a private, ephemeral tmpfs: writing there works, but nothing you put there reaches the user or survives the command. Never use it to deliver a result.
- A command that writes to the workspace is refused by the kernel with "Read-only file system". A denial is PLANNING FEEDBACK, not a permission problem: it means that step belongs in the plan. Do not retry it, do not look for another write path, and do not expect a prompt — no write grant is offered while planning.
- The only way to execute is for the user to leave plan mode with /build. If a step truly cannot be planned without executing it, say so and stop; do not proceed.`
		: `- No kernel sandbox is available on this host, so bash is limited to a conservative read-only allowlist. Prefer the dedicated read/search tools, and expect a denial for anything that writes.`
}

Use this mode for discussion, design, and research:
- Read and explore the codebase, gather facts, compare approaches, weigh trade-offs.
- Ask clarifying questions when requirements are ambiguous.
- Produce a concrete step-by-step implementation plan under a "Plan:" header:

Plan:
1. First step
2. Second step
3. Third step

Do NOT implement anything. Present your analysis and plan, then wait for the user to switch to build mode (/build).`
				: mode === "readonly"
					? `[READ-ONLY MODE ACTIVE - NO WORKSPACE CHANGES]
You are in READ-ONLY MODE: the workspace is write-protected by the kernel, but you are NOT planning — complete the task with reads, searches and read-only commands.
- File-modifying tools (edit, write, delete, ...) are disabled; use /build if the user wants changes.
- Bash enforcement: ${sandboxSummary()}.
${
	sandbox?.available === true
							? `- Every bash command runs inside a read-only workspace sandbox with a private /tmp; any shell syntax works and no keywords are forbidden. /tmp is a private ephemeral tmpfs — scratch only, never a deliverable.
- A workspace write is refused with "Read-only file system". That denial is a recoverable permission fact: retry the exact command once and the user is asked to approve a one-shot grant (workspace-write, or unrestricted). Only do that when the write is genuinely required for the task, not to work around the policy silently.`
							: `- No kernel sandbox is available on this host, so bash is limited to a conservative read-only allowlist.`
}

If the task cannot be completed without changing files, say what is required and let the user switch to /build.`
					: `[BUILD MODE ACTIVE - FULL ACCESS]
You are in BUILD MODE. You may make changes:
- edit, write, and other mutating tools are enabled.
- Bash is unrestricted (no sandbox).
- Create, modify, and delete files as needed to implement the agreed plan.

Implement the plan agreed during plan mode (or the task at hand), following the project's conventions (e.g. AGENTS.md).`;

		return {
			message: {
				customType: MODE_CONTEXT,
				content,
				display: false,
			},
		};
	});

	// Strip stale mode context messages when the mode changes between prompts
	// (before_agent_start re-injects a fresh one each turn).
	pi.on("context", async (event) => {
		return {
			messages: event.messages.filter((m) => {
				const msg = m as { customType?: string; content?: unknown };
				if (msg.customType === MODE_CONTEXT) return false;
				if (typeof msg.content === "string") {
					return (
						!msg.content.includes("[PLAN MODE ACTIVE]") &&
						!msg.content.includes("[READ-ONLY MODE ACTIVE]") &&
						!msg.content.includes("[BUILD MODE ACTIVE]")
					);
				}
				return true;
			}),
		};
	});

	// Restore mode + tool state on session start / resume.
	pi.on("session_start", async (_event, ctx) => {
		const entries = ctx.sessionManager.getEntries();
		const stateEntry = [...entries]
			.reverse()
			.find(
				(e) =>
					(e as { type?: string; customType?: string }).type === "custom" &&
					(e as { customType?: string }).customType === STATE_ENTRY,
			) as { data?: { mode?: Mode; tools?: unknown } } | undefined;

		if (pi.getFlag("plan") === true) {
			mode = "plan";
		} else if (stateEntry?.data?.mode === "plan" || stateEntry?.data?.mode === "readonly" || stateEntry?.data?.mode === "build") {
			mode = stateEntry.data.mode;
		}

		if (sandboxed(mode)) {
			const restored = stateEntry?.data?.tools;
			if (toolsBeforePlan === undefined && Array.isArray(restored)) {
				toolsBeforePlan = restored.filter((name): name is string => typeof name === "string");
			}
			applyPlanTools();
			const state = probeSandbox(ctx.cwd);
			if (!state.available) {
				ctx.ui.notify(
					`${mode} mode: no kernel sandbox (${state.reason}). ${
						FALLBACK === "deny" ? "Bash is disabled." : "Falling back to a conservative allowlist."
					}`,
					"warning",
				);
			}
		}
		updateStatus(ctx);
	});
}
