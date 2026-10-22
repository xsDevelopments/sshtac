"""The execute pane: shows exactly what would run, and pastes it on approval.

What can be approved:

* BLOCKED (local policy), rejected characters (ESC, CR, NUL, bidi, zero-width,
  ...) and multi-line commands can only be edited (F9) or rejected (F8).
  Multi-line stays blocked: in a shell without bracketed paste each newline
  would run on paste, before any further approval.
* DESTRUCTIVE (the stricter of the local verdict and the model's label) needs
  `yes` typed in this pane.
* Placeholders are filled in here with getpass, substituted in memory, and the
  values are added to the core's session-secret redaction set before pasting.

Approval pastes via tmux load-buffer from stdin + paste-buffer -p -d, sets the
results mark on the command line, then sends Enter as a separate key.
"""

from __future__ import annotations

import getpass
import os
import secrets
import shlex
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any

from sshtac import charsafe, ipc, placeholders, policy, runtime
from sshtac.config import Config
from sshtac.pipeline import strip
from sshtac.policy import Risk
from sshtac.tmuxctl import Tmux, TmuxError
from sshtac.ui import style

CONNECT_TIMEOUT = 15.0
RISK_COLOUR = {
    Risk.READ_ONLY: "green", Risk.MUTATING: "yellow", Risk.DESTRUCTIVE: "boldred", Risk.BLOCKED: "boldred",
}


@dataclass
class Assessment:
    local: policy.Verdict
    model: Risk
    effective: Risk
    chars: charsafe.CharReport
    blockers: list[str] = field(default_factory=list)


def assess(command: str, model_label: str, classifier: policy.Classifier) -> Assessment:
    chars = charsafe.check(command)
    local = classifier.classify(command)
    model = Risk.from_label(model_label)
    eff = max(local.risk, model)
    blockers = []
    if chars.rejected:
        blockers.append("unsafe characters: " + "; ".join(chars.rejected))
    if chars.multiline:
        blockers.append("multi-line commands can't be approved (each line would run on paste)")
    if eff == Risk.BLOCKED:
        blockers.append("blocked by local policy: " + ("; ".join(local.top_reasons) or "blocked"))
    return Assessment(local, model, eff, chars, blockers)


class Cancelled(Exception):
    pass


class Executor:
    def __init__(self, session: str, cfg: Config):
        self.session = session
        self.cfg = cfg
        self.tmux = Tmux(cfg.tmux_socket)
        self.path = runtime.socket_path(cfg.tmux_socket, session)
        self.colour = sys.stdout.isatty()
        self.proposal: dict[str, Any] | None = None
        self.original_command = ""
        self.edited = False
        self.token = ""
        pol = cfg.raw["policy"]
        self.classifier = policy.Classifier(pol["blocked_patterns"], pol["destructive_patterns"])

    # ---------------------------------------------------------------- output

    def say(self, text: str, colour: str | None = None) -> None:
        print(style(text, colour, self.colour), flush=True)

    def clear(self) -> None:
        if self.colour:
            sys.stdout.write("\x1b[2J\x1b[H")

    def idle(self, message: str = "No pending command.") -> None:
        self.clear()
        self.say("EXECUTE", "bold")
        self.say(message, "dim")

    def render(self, p: dict[str, Any]) -> None:
        self.clear()
        cmd = p["command"]
        a = assess(cmd, p.get("risk", ""), self.classifier)
        k = self.cfg.key_labels
        title = f"EXECUTE — proposal {p['id'][-8:]}" + (" (edited by you)" if self.edited else "")
        self.say(title, "bold")
        if p.get("injection_suspected"):
            self.say("!! INJECTION SUSPECTED: the model thinks the terminal output tried to instruct it !!", "boldred")
        c = lambda r: style(r.label, RISK_COLOUR[r], self.colour)
        self.say(
            f"risk: {c(a.effective)}   (local {c(a.local.risk)}, model {c(a.model)})   "
            f"reversible: {'yes' if p.get('reversible') else 'NO'}"
        )
        for r in a.local.top_reasons[:3]:
            self.say(f"  · {r}", "dim")
        self.say("purpose:  " + strip(p.get("purpose", "")))
        self.say("expected: " + strip(p.get("expected_effect", "")))
        for ph in self._placeholders(p):
            self.say(f"placeholder {{{{{ph['name']}}}}}: {strip(ph.get('description', ''))}", "cyan")
        if a.chars.multiline:
            self.say(f"⚠ MULTI-LINE COMMAND ({cmd.count(chr(10)) + 1} lines)", "boldyellow")
        if a.chars.non_ascii:
            self.say("⚠ contains non-ASCII characters, shown as ⟨U+XXXX⟩", "yellow")
        self.say("─" * 40, "dim")
        for i, line in enumerate(charsafe.visible(cmd).split("\n"), 1):
            self.say(f"{i:>2} │ {line}")
        self.say("─" * 40, "dim")
        if a.blockers:
            for b in a.blockers:
                self.say("⛔ " + b, "red")
            self.say(f"{k['edit']} edit   {k['reject']} reject", "dim")
        elif a.effective >= Risk.DESTRUCTIVE:
            self.say(f"{k['approve']} approve (you'll type yes)   {k['reject']} reject   {k['edit']} edit", "dim")
        else:
            self.say(f"{k['approve']} approve   {k['reject']} reject   {k['edit']} edit", "dim")

    def _placeholders(self, p: dict[str, Any]) -> list[dict[str, str]]:
        known = {ph["name"]: ph.get("description", "") for ph in p.get("placeholders", []) if isinstance(ph, dict)}
        return [{"name": n, "description": known.get(n, "(added in edit)")} for n in placeholders.names(p["command"])]

    # ---------------------------------------------------------------- core

    def request(self, msg: dict[str, Any]) -> dict[str, Any]:
        try:
            reply = ipc.request(self.path, {**msg, "token": self.token})
        except ipc.IPCError as e:
            return {"ok": False, "error": str(e)}
        return reply

    def report(self, outcome: str, **fields: Any) -> bool:
        assert self.proposal
        reply = self.request({"cmd": "outcome", "id": self.proposal["id"], "outcome": outcome, **fields})
        if not reply.get("ok"):
            self.say(f"core: {reply.get('error')}", "red")
            return False
        return True

    def log(self, kind: str, **fields: Any) -> None:
        reply = self.request({"cmd": "log", "kind": kind, **fields})
        if not reply.get("ok"):
            self.say(f"could not write the audit log: {reply.get('error')}", "red")

    # ---------------------------------------------------------------- focus / input

    def _panes(self) -> tuple[str | None, str | None]:
        return (self.tmux.get_option(self.session, "@sshtac_shell_pane"),
                self.tmux.get_option(self.session, "@sshtac_exec_pane"))

    def focus_self(self) -> None:
        _, me = self._panes()
        if me:
            self.tmux.select_pane(me)
        try:
            import termios

            termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)  # drop stray keystrokes
        except (ImportError, OSError, ValueError):
            pass

    def focus_shell(self) -> None:
        shell, _ = self._panes()
        if shell:
            try:
                self.tmux.select_pane(shell)
            except TmuxError:
                pass

    def ask(self, prompt: str) -> str:
        try:
            return input(style(prompt, "boldyellow", self.colour))
        except (EOFError, KeyboardInterrupt):
            print()
            raise Cancelled() from None

    def secret(self, prompt: str) -> str:
        try:
            return getpass.getpass(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            raise Cancelled() from None

    # ---------------------------------------------------------------- actions

    def on_proposal(self, p: Any) -> None:
        if not isinstance(p, dict) or not isinstance(p.get("command"), str) or not isinstance(p.get("id"), str):
            self.say("ignored a malformed proposal", "red")
            return
        self.proposal = dict(p)
        self.original_command = p["command"]
        self.edited = False
        self.render(self.proposal)

    def on_reject(self) -> None:
        if not self.proposal:
            self.say("nothing to reject", "dim")
            return
        if self.report("rejected", command=self.proposal["command"], edited=self.edited):
            self.proposal = None
            self.idle("Rejected. No pending command.")

    def on_edit(self) -> None:
        p = self.proposal
        if not p:
            self.say("nothing to edit", "dim")
            return
        self.focus_self()
        before = p["command"]
        try:
            after = self._run_editor(before)
        except Cancelled as e:
            self.render(p)
            self.say(f"edit cancelled{': ' + str(e) if str(e) else ''}", "yellow")
            self.focus_shell()
            return
        if after is None or after == before:
            self.render(p)
            self.say("no change", "dim")
            self.focus_shell()
            return
        p["command"] = after
        self.edited = True
        a = assess(after, p.get("risk", ""), self.classifier)
        self.log("edit", proposal_id=p["id"], before=before, after=after,
                 local_risk=a.local.risk.label, effective=a.effective.label, reasons=a.local.reasons)
        self.render(p)
        self.focus_shell()

    def _run_editor(self, text: str) -> str | None:
        """Edit `text` in $VISUAL/$EDITOR via a 0600 temp file in the private
        runtime dir; the file is deleted afterwards whatever happens."""
        editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
        try:
            argv = shlex.split(editor)
        except ValueError:
            argv = ["vi"]
        d = runtime.server_dir(self.cfg.tmux_socket)
        fd, path = tempfile.mkstemp(prefix="edit-", suffix=".sh", dir=d)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(text + "\n")
            self.clear()
            try:
                rc = subprocess.run(argv + [path]).returncode
            except OSError as e:
                raise Cancelled(f"could not start editor {argv[0]!r}: {e}") from None
            if rc != 0:
                raise Cancelled(f"editor exited with status {rc}")
            with open(path) as f:
                new = f.read()
        finally:
            for p in (path, path + "~"):
                try:
                    os.unlink(p)
                except FileNotFoundError:
                    pass
        new = new.strip()
        return new or None

    def on_approve(self) -> None:
        p = self.proposal
        if not p:
            self.say("nothing to approve", "dim")
            return
        cmd = p["command"]
        a = assess(cmd, p.get("risk", ""), self.classifier)
        if a.blockers:
            self.say("cannot approve: " + a.blockers[0], "red")
            self.log("block", proposal_id=p["id"], command=cmd, reasons=a.blockers,
                     local_risk=a.local.risk.label, effective=a.effective.label)
            return
        shell, _ = self._panes()
        if not shell:
            self.say("cannot approve: shell pane unknown", "red")
            return
        names = placeholders.names(cmd)
        needs_input = a.effective >= Risk.DESTRUCTIVE or bool(names)
        values: dict[str, str] = {}
        final = cmd
        prefixed = False
        try:
            if needs_input:
                self.focus_self()
            if a.effective >= Risk.DESTRUCTIVE:
                why = a.local.top_reasons if a.local.risk >= Risk.DESTRUCTIVE else ["labelled destructive by the model"]
                self.say("This command is DESTRUCTIVE: " + "; ".join(why[:2]), "boldred")
                if self.ask("Type yes to run it: ").strip() != "yes":
                    raise Cancelled("not confirmed")
            if names:
                descs = {ph["name"]: ph["description"] for ph in self._placeholders(p)}
                self.say("Values are used once, kept in memory only and never shown or logged.", "dim")
                for name in names:
                    values[name] = self.secret(f"{name} ({strip(descs.get(name, ''))}): ")
                try:
                    final = placeholders.substitute(cmd, values)
                except placeholders.PlaceholderError as e:
                    raise Cancelled(str(e)) from None
                reply = self.request({"cmd": "add_secrets", "values": list(values.values())})
                if not reply.get("ok"):
                    raise Cancelled(f"could not register the secrets for redaction: {reply.get('error')}")
                self.say("This command contains a secret. It may be saved in the remote shell's history.", "yellow")
                ans = self.ask("Prefix a space to keep it out of history (works only with HISTCONTROL=ignorespace)? [Y/n] ")
                if ans.strip().lower() not in ("n", "no"):
                    final = " " + final
                    prefixed = True
            if charsafe.check(final).rejected or charsafe.check(final).multiline:
                raise Cancelled("the final command failed the character check")
            self._paste(shell, final)
        except Cancelled as e:
            self.render(p)
            self.say(f"approval cancelled{': ' + str(e) if str(e) else ''}", "yellow")
            self.focus_shell()
            return
        except (TmuxError, ipc.IPCError) as e:
            self.say(f"paste failed: {e}", "red")
            self.focus_shell()
            return
        finally:
            values.clear()
            final = ""
        self.focus_shell()
        self.report(
            "approved", command=cmd, edited=self.edited, placeholders=names, prefixed_space=prefixed,
            local_risk=a.local.risk.label, effective=a.effective.label,
        )
        self.proposal = None
        self.idle(f"Ran: {charsafe.visible(cmd)}\nNo pending command.")

    def _paste(self, shell: str, final: str) -> None:
        state, dead, alt = self.tmux.pane_state(shell)
        if dead:
            raise Cancelled("the shell pane has exited")
        if alt:
            raise Cancelled("a full-screen program is open in the shell pane")
        if self.tmux.pane_in_mode(shell):
            raise Cancelled("the shell pane is in copy mode (press q there first)")
        self.tmux.paste(shell, final, f"sshtac-{secrets.token_hex(8)}")
        # The mark goes on the command line itself, before it runs, so the
        # next results capture starts with the command and its output.
        mark = ipc.request(self.path, {"cmd": "mark_now"})
        if not mark.get("ok"):
            self.say(f"warning: results mark not set: {mark.get('error')}", "yellow")
        self.tmux.send_enter(shell)

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
        handlers = {"approve": self.on_approve, "reject": self.on_reject, "edit": self.on_edit}
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
    # Only the core talks to the API. Don't hand the key to $EDITOR & co.
    from sshtac.launcher import CREDENTIAL_VARS

    for var in CREDENTIAL_VARS:
        os.environ.pop(var, None)
    return Executor(session, cfg).run()
