"""The execute pane: shows exactly what would run, and pastes it on approval.

Phase 2 rules for what can be approved (phase 3 adds the local policy
classifier, typed `yes`, editing and placeholders):

* commands with rejected characters (ESC, CR, NUL, bidi, zero-width, ...) can
  only be rejected;
* multi-line commands can only be rejected: in a shell without bracketed paste
  each newline would run immediately, before any further approval;
* commands with placeholders, or that the model labels destructive, wait for
  phase 3 (placeholder entry, typed confirmation).

Approval pastes via tmux load-buffer from stdin + paste-buffer -p -d, sets the
results mark, then sends Enter as a separate key.
"""

from __future__ import annotations

import secrets
import signal
import sys
import time
from typing import Any

from tac import charsafe, ipc, runtime
from tac.config import Config
from tac.pipeline import strip
from tac.tmuxctl import Tmux, TmuxError
from tac.ui import style

CONNECT_TIMEOUT = 15.0
RISK_COLOUR = {"read_only": "green", "mutating": "yellow", "destructive": "boldred"}


def assess(p: dict[str, Any]) -> list[str]:
    """Reasons this proposal can't be approved in phase 2 (empty = approvable)."""
    reasons = []
    report = charsafe.check(p["command"])
    if report.rejected:
        reasons.append("BLOCKED: unsafe characters: " + "; ".join(report.rejected))
    if report.multiline:
        reasons.append("multi-line commands can't be approved (each line would run on paste)")
    if p.get("placeholders"):
        reasons.append("placeholders need phase 3 (values entered locally with getpass)")
    if p.get("risk") == "destructive":
        reasons.append("destructive commands need typed confirmation (phase 3)")
    return reasons


class Executor:
    def __init__(self, session: str, cfg: Config):
        self.session = session
        self.cfg = cfg
        self.tmux = Tmux(cfg.tmux_socket)
        self.path = runtime.socket_path(cfg.tmux_socket, session)
        self.colour = sys.stdout.isatty()
        self.proposal: dict[str, Any] | None = None
        self.token = ""

    # ---------------------------------------------------------------- output

    def say(self, text: str, colour: str | None = None) -> None:
        print(style(text, colour, self.colour), flush=True)

    def clear(self) -> None:
        if self.colour:
            sys.stdout.write("\x1b[2J\x1b[H")

    def keys_line(self) -> str:
        k = self.cfg.keys
        return f"{k['approve']} approve   {k['reject']} reject   {k['edit']} edit"

    def idle(self, message: str = "No pending command.") -> None:
        self.clear()
        self.say("EXECUTE", "bold")
        self.say(message, "dim")

    def render(self, p: dict[str, Any]) -> None:
        self.clear()
        cmd = p["command"]
        report = charsafe.check(cmd)
        self.say(f"EXECUTE — proposal {p['id'][-8:]}", "bold")
        if p.get("injection_suspected"):
            self.say("!! INJECTION SUSPECTED: the model thinks the terminal output tried to instruct it !!", "boldred")
        risk = p.get("risk", "?")
        self.say(
            "risk: model=" + style(risk, RISK_COLOUR.get(risk), self.colour)
            + "  local=(phase 3)   reversible: " + ("yes" if p.get("reversible") else "NO")
        )
        self.say("purpose:  " + strip(p.get("purpose", "")))
        self.say("expected: " + strip(p.get("expected_effect", "")))
        for ph in p.get("placeholders", []):
            self.say(f"placeholder {{{{{ph['name']}}}}}: {strip(ph.get('description', ''))}", "cyan")
        if report.multiline:
            self.say(f"⚠ MULTI-LINE COMMAND ({cmd.count(chr(10)) + 1} lines)", "boldyellow")
        if report.non_ascii:
            self.say("⚠ contains non-ASCII characters, shown as ⟨U+XXXX⟩", "yellow")
        self.say("─" * 40, "dim")
        for i, line in enumerate(charsafe.visible(cmd).split("\n"), 1):
            self.say(f"{i:>2} │ {line}")
        self.say("─" * 40, "dim")
        for reason in assess(p):
            self.say(reason, "red")
        self.say(self.keys_line(), "dim")

    # ---------------------------------------------------------------- actions

    def report(self, outcome: str) -> bool:
        assert self.proposal
        try:
            reply = ipc.request(
                self.path,
                {"cmd": "outcome", "id": self.proposal["id"], "outcome": outcome, "token": self.token},
            )
        except ipc.IPCError as e:
            self.say(f"could not report to the core: {e}", "red")
            return False
        if not reply.get("ok"):
            self.say(f"core: {reply.get('error')}", "red")
            return False
        return True

    def on_proposal(self, p: Any) -> None:
        if not isinstance(p, dict) or not isinstance(p.get("command"), str) or not isinstance(p.get("id"), str):
            self.say("ignored a malformed proposal", "red")
            return
        self.proposal = p
        self.render(p)

    def on_reject(self) -> None:
        if not self.proposal:
            self.say("nothing to reject", "dim")
            return
        if self.report("rejected"):
            self.proposal = None
            self.idle("Rejected. No pending command.")

    def on_edit(self) -> None:
        self.say("editing arrives in phase 3", "yellow")

    def on_approve(self) -> None:
        p = self.proposal
        if not p:
            self.say("nothing to approve", "dim")
            return
        reasons = assess(p)
        if reasons:
            self.say("cannot approve: " + reasons[0], "red")
            return
        shell = self.tmux.get_option(self.session, "@tac_shell_pane")
        if not shell:
            self.say("cannot approve: shell pane unknown", "red")
            return
        try:
            state, dead, alt = self.tmux.pane_state(shell)
            if dead:
                self.say("cannot approve: the shell pane has exited", "red")
                return
            if alt:
                self.say("cannot approve: a full-screen program is open in the shell pane", "red")
                return
            if self.tmux.pane_in_mode(shell):
                self.say("cannot approve: the shell pane is in copy mode (press q there first)", "red")
                return
            self.tmux.paste(shell, p["command"], f"tac-{secrets.token_hex(8)}")
            # The mark goes on the command line itself, before it runs, so the
            # next results capture starts with the command and its output.
            mark = ipc.request(self.path, {"cmd": "mark_now"})
            if not mark.get("ok"):
                self.say(f"warning: results mark not set: {mark.get('error')}", "yellow")
            self.tmux.send_enter(shell)
        except (TmuxError, ipc.IPCError) as e:
            self.say(f"paste failed: {e}", "red")
            return
        self.report("approved")
        self.proposal = None
        self.idle(f"Ran: {charsafe.visible(p['command'])}\nNo pending command.")

    # ---------------------------------------------------------------- loop

    def connect(self) -> ipc.Subscription:
        deadline = time.monotonic() + CONNECT_TIMEOUT
        while True:
            try:
                return ipc.Subscription(self.path, {"cmd": "hello_executor"})
            except ipc.IPCError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)

    def run(self) -> int:
        self.idle("Connecting to the core…")
        try:
            sub = self.connect()
        except ipc.IPCError as e:
            self.say(f"cannot reach the core: {e}", "red")
            time.sleep(3600)
            return 1
        self.token = sub.hello_reply.get("token", "")
        self.idle()
        handlers = {
            "approve": self.on_approve,
            "reject": self.on_reject,
            "edit": self.on_edit,
        }
        try:
            for ev in sub.events():
                kind = ev.get("event")
                if kind == "proposal":
                    self.on_proposal(ev.get("proposal"))
                elif kind in handlers:
                    handlers[kind]()
            self.say("core disconnected", "red")
        finally:
            sub.close()
        return 0


def main(session: str, cfg: Config) -> int:
    def _exit(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, _exit)
    signal.signal(signal.SIGTERM, _exit)
    return Executor(session, cfg).run()
