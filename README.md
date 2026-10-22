# sshtac — the tmux AI companion for SSH work

sshtac puts an AI assistant (Claude) next to your shell or SSH session in tmux. You send it terminal
output when you choose; it explains what it sees and proposes **one command at a time**.
**Nothing runs until you approve it with a key press**, and sshtac checks every command itself,
whatever the AI claims about it. It's built for incident response, so it treats everything on
the terminal as potentially hostile.

## Quick start

Needs **Linux or macOS**, **Python 3.11+**, **tmux 3.2+** and an Anthropic API key.

```bash
pipx install sshtac                                   # once (install tmux first: apt install tmux / brew install tmux)
sshtac config --set-key                               # once: save your Anthropic API key
sshtac user@your-server                               # or just `sshtac` for a local shell
```

Upgrade with `pipx upgrade sshtac`. No pipx? `sudo apt install pipx` or `brew install pipx`, then
`pipx ensurepath`.

From source (for development):

```bash
python3 -m venv .venv && .venv/bin/pip install -e .   # once, in this folder
ln -s "$PWD/.venv/bin/sshtac" ~/.local/bin/sshtac      # once: run `sshtac` from anywhere
```

If you skip `--set-key`, sshtac asks for the key when it starts (input hidden) and offers to save it. To leave:
type `/quit` in the chat pane (ends everything) or `/detach` (keeps it running; run `sshtac` again to
come back). The bottom line of the screen always shows the keys.

## The screen

```
┌─[ SHELL ]────────────┬─[ AI CHAT — type here ]
│ your shell / ssh     │ explanations, Q&A    │
│                      ├─[ EXECUTE ]──────────┤
│                      │ proposed command,    │
│                      │ risk, approve/edit   │
└──────────────────────┴──────────────────────┘
```

| Do this | How |
|---|---|
| Ask the AI something | Click the chat pane (or **F4**) and type at `you>` |
| Send new shell output | **F6**: everything since your last approved command |
| Send a specific bit | Drag over it with the mouse, then **F5** |
| Paste several lines into the chat | Just paste: they're held as one message (`...>` prompt) until you press Enter, so you can add a question first |
| Send output *with* a comment or question | Type it at `you>` without pressing Enter, then **F6** (or **F5**): it goes along with the output |
| Run the proposed command | **F7** (destructive ones ask you to type `yes`) |
| Reject it | **F8** |
| Change it first | **F9** opens it in `$EDITOR` |
| Jump between shell and chat | **F4** |
| Scroll a pane | Mouse wheel; **q** goes back to live |
| Leave it running / come back | `/detach` or **Ctrl+B** then **d**; then `sshtac` |
| End everything | `/quit` in the chat (asks to confirm), or `sshtac stop` from another terminal |

Chat commands: `/help`, `/status`, `/sent` (exactly what was last sent to the AI), `/mark`
(start the next F6 capture from here), `/detach`, `/quit`.

## How a command gets approved

Each proposal gets two risk ratings: the AI's own, and sshtac's local policy check, which reads the
command itself and ignores the AI's claims. **The stricter one wins.**

| Risk | Examples | To run it |
|---|---|---|
| read-only | `ls`, `grep`, `ss`, `iptables -L`, `journalctl -u x`, `SELECT …` | F7 |
| mutating | anything not known to be read-only: `cp`, `systemctl restart`, `apt install` | F7 |
| destructive | `rm`, `kill`, stopping services, firewall/account changes, `>` overwrites, SQL `DROP/DELETE`, package removal, anything changing `/dev` | F7, then type `yes` |
| blocked | `curl … \| sh`, `eval $(…)`, `rm -rf /`, `mkfs`, `dd of=/dev/sda`, `chmod -R 777 /`, `history -c`, `unset HISTFILE`, stopping auditd/rsyslog/journald, fork bombs | can only be edited or rejected |

The check sees through quoting and escaping tricks (`'r''m'`, `r\m`, `${IFS}`, `$'\x72m'`), line
continuations, wrappers (`sudo`, `env`, `timeout`, `xargs`, `sh -c '…'`, `ssh host '…'`,
`find -exec`) and commands hidden in `$(…)` or backticks. Anything it can't recognise counts as
mutating.

Also never approvable: **multi-line commands** (in a shell without bracketed paste, each line would
run the moment it's pasted) and commands containing **control or invisible characters** (ESC, CR,
bidi overrides, zero-width characters). Other non-ASCII characters are shown as `⟨U+00A0⟩` so
look-alikes can't hide. If the AI thinks the terminal output tried to instruct it, the execute pane
shows a red **INJECTION SUSPECTED** banner.

**Secrets.** The AI never sees passwords. It writes `{{PLACEHOLDERS}}`. When you approve, the
execute pane asks for each value with a hidden prompt, inserts it safely quoted, and offers to
prefix a space so it stays out of shell history (works if the remote has `HISTCONTROL=ignorespace`).
Values stay in memory and are redacted from everything sent to the AI afterwards.

Approved commands are pasted with tmux's bracketed paste, and Enter is sent separately. The
command line becomes the start of the next F6 capture.

## What gets sent to the AI

Only what you send with F5/F6, plus what you type in the chat (including a half-typed line, which
F5/F6 send along; lines starting with `/` are left alone). Before anything leaves your machine:

1. Terminal escape codes and control characters are removed; invisible Unicode is made visible.
2. Placeholder values you entered this session are replaced with `[REDACTED:session_secret]`.
3. Secrets are redacted: private keys, AWS keys, `Authorization:` headers, JWTs, `password=` /
   `token:` style values, passwords in connection strings, long random-looking tokens.
4. Long output is cut to 20,000 characters, keeping the start and end.
5. The text is wrapped in `<terminal_output>` tags. The AI is told that everything inside them is
   untrusted data and never instructions, and fake closing tags in the output are neutralised.

Type `/sent` to see exactly what went out last.

## Your API key

sshtac looks for a key in this order:

1. `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_PROFILE`) in the terminal you start it from
2. the key file `~/.config/sshtac/api_key`
3. an `ant auth login` profile
4. a hidden prompt, which offers to save what you paste into the key file

```bash
sshtac config --set-key      # save or replace the key (hidden input)
sshtac config                # shows where the key comes from (never the key itself)
sshtac config --remove-key   # delete the key file
```

The key file is separate from `config.toml` on purpose, so you can share or back up your config
without leaking the key. sshtac writes it readable by you only (`chmod 600`) and, like `ssh` with
private keys, refuses to use it if other users can read it. If you'd rather not keep the key on
disk at all, skip the file and paste it at the prompt each time, or export `ANTHROPIC_API_KEY` in
that terminal. Wherever it comes from, the key goes only to the chat pane, which is the only part
that talks to the API. It is kept out of the shell pane's environment, so `env` there can't expose it.

## Audit log

Every session writes a timeline to `~/.local/state/sshtac/audit-<session>-<time>.jsonl` (mode 0600):
start/end, each send (redacted, as sent), the AI's replies and proposals, sshtac's risk rating, edits
(before and after), approvals, rejections and refusals. Placeholder **names** are logged, never their
values.

Turn a log into something you can hand to others, or check the policy against what the AI proposed:

```bash
sshtac report > incident.md               # Markdown timeline of the latest session
sshtac report LOG.jsonl -o incident.md    # a specific log; the file is created 0600
sshtac report --full                      # also include the full terminal output and AI replies
sshtac review                             # replay every proposed command (all logs) through the policy
```

`sshtac report` lists the target, start and end (local time and UTC) and model, then each step in
order: what was sent (source, size, redactions; the text itself only with `--full`), the first lines
of each AI reply, every proposed command with its risk rating and what happened to it (approved,
approved after edit with before → after, rejected, blocked, superseded), refusals and errors. It ends
with a table of the commands that were approved and pasted into the shell. It prints only what the
log contains, so no secret values; AI and terminal text is made inert (links, images and HTML are
escaped, control characters shown as `⟨U+001B⟩`).

`sshtac review [LOGS...]` re-checks every command the AI ever proposed with the current policy
(including your config's extra patterns) and lists where it disagrees with the AI's own label:
**stricter** (likely false positives, grouped by the reason that set the level) and **looser** (the
AI was more cautious, so a rule may be missing), with counts. Commands rated differently now than
during the session are listed too, so you can confirm a policy fix. Neither command changes the logs.

## Safety model

- **Local only.** sshtac, your API key and the logs stay on your machine. SSH runs inside the left
  pane; nothing is installed or run on the server except commands you approve.
- **No auto-execution.** Every command needs your key press, and destructive ones your typed `yes`.
- **The AI holds no credentials.** It never connects anywhere and never sees secret values.
- **Terminal output is untrusted.** It is redacted, delimited, and the local policy check gates
  every command regardless of the AI's label.
- **Secrets never touch disk.** Placeholder values live in memory only, and the API key too unless
  you choose to save it in the owner-only key file. Edits go through a 0600 temp file in a private
  runtime directory (`$XDG_RUNTIME_DIR/sshtac/`, a RAM disk on most Linux systems, or
  `/tmp/sshtac-$UID/` where that isn't set, e.g. macOS) and are deleted straight after. The API key
  is kept out of the shell pane's environment.
- sshtac runs **its own tmux server** (`tmux -L sshtac`), so its keys and settings never affect your
  normal tmux.

## Configuration

```bash
sshtac config --init      # create ~/.config/sshtac/config.toml with every setting explained
sshtac config             # show which file is used and check it for mistakes
```

Edit the file, then restart sshtac (`/quit`, then `sshtac`). Unknown settings and wrong types are
rejected with a message naming the setting. The main ones:

```toml
model = "claude-sonnet-5-5"

[ai]
effort = "medium"          # low | medium | high | xhigh | max
show_reasoning = "auto"    # "always" shows the AI's reasoning summary with every reply

[capture]
max_chars = 20000

[policy]
blocked_patterns = ['\bterraform\s+destroy\b']   # your own never-approve rules

[redaction]
patterns = [{ name = "ticket", regex = 'TCK-\d+' }]
```

Environment overrides: `SSHTAC_CONFIG` (config path), `SSHTAC_MODEL`, `SSHTAC_TMUX_SOCKET`.

### Changing the keys

```toml
[keys]
send_selection = "F5"
send_results = "F6"
approve = "F7"
reject = "F8"
edit = "F9"
focus_toggle = "F4"
```

Use tmux key names: function keys `F1`–`F24`, optionally with modifiers (`S-F7`, `M-F7`, `C-F7`),
or any key with a modifier, such as `M-a` (Alt+a, or Option+a on a Mac) or `C-a` (Ctrl+a).
Plain letters aren't allowed, because the key would be captured while you type. Two actions can't
share a key. After restarting sshtac, the old keys are unbound automatically.

To see what sshtac has bound:

```bash
tmux -L sshtac list-keys -T root
```

### When a function key doesn't work

Some terminals keep F-keys for themselves or send something tmux doesn't recognise. Common cases:

- **GNOME Terminal**: F10 opens the menu and F11 toggles full screen (sshtac's defaults avoid both).
- **macOS**: F-keys control brightness and volume. Hold **fn**, or turn on *Use F1, F2, etc. keys as
  standard function keys* in System Settings → Keyboard.
- **VS Code / IDE terminals** often capture F-keys for debugging.
- **PuTTY**'s default keyboard mode sends F1–F4 differently, so **F4** may not work. Set
  *Terminal → Keyboard → The Function keys and keypad* to *Xterm R6*, or remap `focus_toggle`.
- **sshtac inside another tmux or screen**: the outer one may catch the key first.

To check what your terminal sends, press **Ctrl+V** and then the key in an ordinary shell.
`^[[18~` means F7 arrives fine. If nothing appears, or your terminal does something else, use
Alt-based keys instead:

```toml
[keys]
send_selection = "M-s"
send_results = "M-o"
approve = "M-y"
reject = "M-n"
edit = "M-e"
focus_toggle = "M-Tab"
```

Mac users: in Terminal.app enable *Use Option as Meta key*; in iTerm2 set Option to *Esc+*.

### Copying and pasting

Dragging selects text inside one pane, keeps it highlighted (so F5 can send it), and copies it into
tmux's buffer. Paste it into the focused pane with **Ctrl+B** then **]**. Whether it also reaches
your computer's clipboard depends on your terminal supporting OSC 52 (Windows Terminal, iTerm2 with
clipboard access allowed, kitty, WezTerm, foot). To use your terminal's own selection instead, hold
**Shift** while dragging (**Option** in iTerm2); that selection spans all panes. Pasting from your
computer works as usual (e.g. Ctrl+Shift+V).

## Commands

```
sshtac [ssh args...]        start, or reattach to, a session (no args: a local shell)
sshtac -- <ssh args...>     the same, when the host is named like a sshtac command (e.g. "config")
sshtac stop [--session S]   end a session
sshtac config [--init | --example]
sshtac report [LOG | --latest] [--full] [-o FILE]   Markdown report of a session's audit log
sshtac review [LOGS... | --all]                     policy vs the AI's labels, over the audit logs
```

The session is named after the host (`sshtac-web-01-example-com`, or `sshtac-local`). Running `sshtac` again
reattaches, and also repairs the session's keys and settings if a previous start was interrupted.
When it reattaches, the bottom line says so for a few seconds ("reconnected to your session from
14:02 (ssh …)"), so an old session (say, one still at a password prompt) isn't mistaken for a new
connection. For a fresh start, `/quit` it first.

## Limitations

- sshtac reads the terminal only when you press F5/F6; it never watches it.
- F6 tracks output with a line marker. If history reaches `history_limit` (50,000 lines), the
  oldest lines since the marker may be missing; sshtac says so when it happens. While a full-screen
  program (vim, less, top) is open, F6 captures only that screen.
- The local check is conservative and pattern-based: it errs towards stricter. When it's wrong in
  the strict direction, approve with `yes` or edit the command. It does not make a malicious
  command safe; you still read what you approve.
- Python can't guarantee secrets are wiped from memory, only that they are never written out.
- The AI only sees what you send it. On a compromised host, the output of `ps`, `ls` or `netstat`
  can itself be lying.

## Development

```bash
.venv/bin/python -m unittest discover -s tests -t .    # unit + tmux integration tests (~20s)
SSHTAC_TEST_FAKE_MODEL=1 sshtac                     # try the UI with a scripted fake AI, no API calls
```

The integration tests start a private tmux server (`tmux -L sshtac-test-<pid>`) with a bare
`bash --norc`; they never touch your real sshtac session or your shell's startup files. The manual
test plan, run against a throwaway SSH container, is in [TESTING.md](TESTING.md).

| Module | Role |
|---|---|
| `launcher.py` | creates the tmux server, session, panes, key bindings |
| `core.py` | chat pane: IPC server, conversation, audit log, captures |
| `executor.py` | execute pane: display, approve/reject/edit, placeholders, paste |
| `llm.py` | system prompt, `propose_command` tool, history rules |
| `pipeline.py` | strip → redact → truncate → wrap for everything sent |
| `policy.py` | local risk classifier |
| `charsafe.py`, `placeholders.py`, `marks.py` | character checks, safe substitution, F6 range maths |
| `ipc.py`, `runtime.py`, `tmuxctl.py`, `audit.py`, `config.py` | plumbing |

## License

MIT — see [LICENSE](LICENSE).
