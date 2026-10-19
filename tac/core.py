"""The core process: runs in the chat pane.

Owns the IPC server, the results-buffer mark, the session-secret set, the
conversation with the model and the audit log. Key bindings talk to it through
short-lived clients; the executor holds a persistent connection, receives
proposals from it and reports back what the human did.

Model calls run on one worker thread so the chat input and IPC stay responsive.
"""

from __future__ import annotations

import hmac
import json
import os
import queue
import secrets
import signal
import sys
import threading
from typing import Any

from tac import ipc, llm, runtime
from tac.audit import AuditLog
from tac.config import Config
from tac.marks import Mark, capture_range, mark_at
from tac.pipeline import SOURCES, redact, redact_session_secrets, strip
from tac.tmuxctl import Tmux, TmuxError
from tac.ui import ChatUI

MAX_SELECTION = 2 * 1024 * 1024
MAX_CHAT = 20_000

HELP = """\
Type a question here and press Enter. Commands: /help /status /mark /sent
Mouse: click a pane to focus it; drag to select text, then {send_selection} sends it; wheel scrolls (q leaves)
Keys:  {send_results} = send new shell output   {approve} = approve   {reject} = reject   {focus_toggle} = shell⇄chat
End the session with `tac stop` from any shell (or kill the tmux session)."""

OUTCOMES = ("approved", "rejected", "superseded")


class Core:
    def __init__(self, session: str, cfg: Config, client_factory: llm.ClientFactory = llm.make_client):
        self.session = runtime.check_session_name(session)
        self.cfg = cfg
        self.tmux = Tmux(cfg.tmux_socket)
        self.pipeline = cfg.pipeline()
        self.ui = ChatUI()
        self.mark: Mark | None = None
        # Values typed for placeholders this session. Memory only, never logged.
        self.session_secrets: set[str] = set()
        self.executor: ipc.Connection | None = None
        self.executor_token = ""
        self.proposal: llm.Proposal | None = None
        self._lock = threading.RLock()
        self._work: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.server: ipc.Server | None = None
        self.audit: AuditLog | None = None
        self.conversation: llm.Conversation | None = None
        self._client_factory = client_factory
        self.last_sent = ""
        self.fake_model = os.environ.get("TAC_TEST_FAKE_MODEL") == "1"
        if self.fake_model:
            from tac.testing import FakeClient

            self._client_factory = FakeClient

    # ---------------------------------------------------------------- lifecycle

    def run(self) -> int:
        path = runtime.socket_path(self.cfg.tmux_socket, self.session)
        self.server = ipc.Server(path, self.dispatch, self._on_disconnect)
        self.audit = AuditLog(self.session)
        ssh_args = self._ssh_args()
        self.audit.event(
            "session_start",
            target=" ".join(ssh_args) if ssh_args else "local shell",
            ssh_args=ssh_args,
            model=self.cfg.model,
        )
        self.server.start()
        threading.Thread(target=self._worker, daemon=True).start()
        self.ui.say(f"tac — session {self.session} — model {self.cfg.model}", "bold", trusted=True)
        self.ui.say(HELP.format(**self.cfg.keys), "dim", trusted=True)
        self.ui.say(f"audit log: {self.audit.path}", "dim", trusted=True)
        if self.fake_model:
            self.ui.say("TAC_TEST_FAKE_MODEL=1: using the scripted fake model, no API calls", "boldyellow", trusted=True)
            self.audit.event("fake_model")
        self._init_conversation(ssh_args)
        try:
            self._set_initial_mark()
            self._input_loop()
        finally:
            self._work.put(None)
            self.audit.event("session_end")
            self.audit.close()
            self.server.close()
        return 0

    def _ssh_args(self) -> list[str]:
        raw = self.tmux.get_option(self.session, "@tac_ssh_args")
        try:
            args = json.loads(raw) if raw else []
        except json.JSONDecodeError:
            return []
        return [a for a in args if isinstance(a, str)] if isinstance(args, list) else []

    def _init_conversation(self, ssh_args: list[str]) -> None:
        ai = self.cfg.ai
        try:
            client = self._client_factory(float(ai["timeout"]))
        except ImportError:
            self.ui.say("the anthropic package is not installed; AI is disabled (pip install anthropic)", "red", trusted=True)
            return
        except Exception as e:
            self.ui.say(f"AI is disabled: {llm.describe_error(e)}", "red")
            return
        target = f"ssh {' '.join(ssh_args)}" if ssh_args else "a local shell"
        self.conversation = llm.Conversation(
            client,
            self.cfg.model,
            effort=ai["effort"],
            max_tokens=ai["max_tokens"],
            fallbacks=ai["fallbacks"] == "default",
            trim_at_tokens=ai["trim_at_tokens"],
            session_context=f"The shell pane is running {target}.",
        )

    def _set_initial_mark(self) -> None:
        # The results buffer starts at the shell's cursor line at launch. If the
        # shell pane isn't readable yet, the first send captures all history.
        try:
            self._do_mark(quiet=True)
        except (TmuxError, RuntimeError):
            self.mark = None

    def _input_loop(self) -> None:
        if not sys.stdin.isatty():
            threading.Event().wait()  # nothing to read; serve IPC until killed
        while True:
            try:
                line = self.ui.read_line().strip()
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                self.ui.say("(Ctrl-D ignored — use `tac stop` to end the session)", "dim", trusted=True)
                continue
            if line:
                self._handle_chat(line)

    def _handle_chat(self, line: str) -> None:
        if line in ("/help", "/?"):
            self.ui.say(HELP.format(**self.cfg.keys), "dim", trusted=True)
        elif line == "/status":
            conv = self.conversation
            self.ui.say(
                f"mark={self.mark}  executor={'connected' if self.executor else 'not connected'}  "
                f"proposal={'pending' if self.proposal else 'none'}  "
                f"session_secrets={len(self.session_secrets)}  model={self.cfg.model}  "
                f"context≈{conv.last_input_tokens if conv else 0} tokens",
                "dim",
            )
        elif line == "/sent":
            self.ui.say(self.last_sent or "(nothing sent yet)")
        elif line == "/mark":
            self._work.put({"cmd": "mark"})
        elif line.startswith("/"):
            self.ui.say(f"unknown command {line.split()[0]}; try /help", "yellow")
        else:
            self._work.put({"cmd": "chat", "text": line[:MAX_CHAT]})

    # ---------------------------------------------------------------- IPC

    def dispatch(self, msg: dict[str, Any], conn: ipc.Connection) -> dict[str, Any] | None:
        cmd = msg.get("cmd")
        if cmd == "ping":
            return {"ok": True}
        if cmd == "hello_executor":
            with self._lock:
                if self.executor is not None:
                    return {"ok": False, "error": "an executor is already connected"}
                self.executor = conn
                conn.role = "executor"
                # Outcome reports come on short-lived connections and must carry
                # this token, so only the connected execute pane can report.
                self.executor_token = secrets.token_hex(16)
                token = self.executor_token
                current = self.proposal
            self.ui.say("execute pane connected", "dim", trusted=True)
            if current:
                # A reconnecting execute pane gets the pending proposal again.
                ev = {"event": "proposal", "proposal": current.to_dict()}
                conn.after_reply.append(lambda: self._push(ev))
            return {"ok": True, "token": token}
        if cmd == "send":
            source = msg.get("source")
            if source not in SOURCES:
                return {"ok": False, "error": f"bad source {source!r}"}
            if source == "selection":
                text = msg.get("text")
                if not isinstance(text, str):
                    return {"ok": False, "error": "selection text missing"}
                if len(text) > MAX_SELECTION:
                    return {"ok": False, "error": "selection too large"}
            self._work.put(msg)
            return {"ok": True}
        if cmd == "mark":
            self._work.put(msg)
            return {"ok": True}
        if cmd == "mark_now":
            # Synchronous: the executor sets the mark between paste and Enter.
            try:
                self._do_mark(quiet=True)
            except (TmuxError, RuntimeError) as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True}
        if cmd == "outcome":
            with self._lock:
                expected = self.executor_token
            token = msg.get("token")
            if not expected or not isinstance(token, str) or not hmac.compare_digest(token, expected):
                return {"ok": False, "error": "outcome must come from the connected execute pane"}
            return self._handle_outcome(msg)
        if cmd in ("approve", "reject", "edit"):
            return self._forward_to_executor(cmd)
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def _on_disconnect(self, conn: ipc.Connection) -> None:
        with self._lock:
            if conn is self.executor:
                self.executor = None
                self.executor_token = ""
                self.ui.say("execute pane disconnected", "yellow", trusted=True)

    def _push(self, event: dict[str, Any]) -> bool:
        with self._lock:
            ex = self.executor
        if ex is None:
            return False
        try:
            ex.send(event)
            return True
        except OSError:
            return False

    def _forward_to_executor(self, action: str) -> dict[str, Any]:
        if not self._push({"event": action}):
            return {"ok": False, "error": "execute pane is not connected"}
        return {"ok": True}

    def _handle_outcome(self, msg: dict[str, Any]) -> dict[str, Any]:
        pid, outcome = msg.get("id"), msg.get("outcome")
        if outcome not in OUTCOMES or not isinstance(pid, str):
            return {"ok": False, "error": "bad outcome"}
        with self._lock:
            current = self.proposal
            if current is None or current.id != pid:
                return {"ok": False, "error": "no such pending proposal"}
            self.proposal = None
            if self.conversation:
                self.conversation.record_outcome(pid, outcome)
        assert self.audit
        self.audit.event(outcome, proposal_id=pid, command=current.command)
        colour = {"approved": "green", "rejected": "yellow"}.get(outcome, "dim")
        self.ui.say(f"[{outcome}] {current.command}", colour)
        return {"ok": True}

    # ---------------------------------------------------------------- work

    def _worker(self) -> None:
        while (msg := self._work.get()) is not None:
            try:
                if msg["cmd"] == "send":
                    self._do_send(msg)
                elif msg["cmd"] == "chat":
                    self._do_chat(msg["text"])
                elif msg["cmd"] == "mark":
                    self._do_mark()
            except Exception as e:  # never let one failure kill the core
                self.ui.say(f"error: {type(e).__name__}: {e}", "red")
                if self.audit:
                    self.audit.event("error", error=f"{type(e).__name__}: {e}")

    def _shell_pane(self) -> str:
        pane = self.tmux.get_option(self.session, "@tac_shell_pane")
        if not pane:
            raise RuntimeError("@tac_shell_pane is not set on this session")
        return pane

    def _capture_results(self) -> tuple[str, str | None]:
        pane = self._shell_pane()
        state, dead, alt = self.tmux.pane_state(pane)
        notes = []
        if dead:
            notes.append("shell pane has exited")
        if alt:
            notes.append("a full-screen program is running; capturing its screen only")
        with self._lock:
            rng = capture_range(self.mark, state)
            # Advance the mark to the current (cursor) line; it is included
            # again next time so the prompt + next command give context.
            self.mark = mark_at(state)
        if rng.note:
            notes.append(rng.note)
        text = self.tmux.capture(pane, rng.start, rng.end)
        return text.rstrip("\n"), "; ".join(notes) or None

    def _do_send(self, msg: dict[str, Any]) -> None:
        source = msg["source"]
        if source == "results_buffer":
            raw, note = self._capture_results()
        else:
            raw, note = msg["text"], None
        if not raw.strip():
            self.ui.say(f"[{source}] nothing new to send", "yellow", trusted=True)
            return
        with self._lock:
            secrets = set(self.session_secrets)
        prepared = self.pipeline.prepare(raw, source, secrets)
        assert self.audit
        self.audit.event(
            "send",
            source=source,
            text=prepared.text,
            redactions=dict(prepared.redactions),
            truncated=bool(prepared.truncation),
            note=note,
        )
        self.ui.say("─" * 40, "dim", trusted=True)
        self.ui.say(f"sent {source.replace('_', ' ')}: {prepared.summary()}", "cyan", trusted=True)
        if note:
            self.ui.say(f"note: {note}", "yellow")
        self._ask(prepared.text)

    def _do_chat(self, text: str) -> None:
        # Your own typing is trusted (not wrapped), but it still goes through
        # stripping and redaction in case you paste something sensitive.
        with self._lock:
            secrets = set(self.session_secrets)
        clean, n = redact_session_secrets(strip(text), secrets)
        clean, counts = redact(clean, self.pipeline.patterns, self.pipeline.entropy)
        if n or counts:
            self.ui.say("note: redacted part of your message before sending", "yellow", trusted=True)
        assert self.audit
        self.audit.event("chat", text=clean)
        self._ask(clean)

    def _ask(self, text: str) -> None:
        conv = self.conversation
        if conv is None:
            self.ui.say("(AI is disabled — see the message above)", "dim", trusted=True)
            return
        self.last_sent = text
        self.ui.say("… asking the model", "dim", trusted=True)
        assert self.audit
        try:
            reply = conv.ask(text)
        except Exception as e:
            err = llm.describe_error(e)
            self.ui.say(f"model call failed: {err}", "red")
            self.audit.event("model_error", error=err)
            return
        if reply.trimmed:
            self.ui.say("note: context was large; trimmed the oldest terminal output", "yellow", trusted=True)
            self.audit.event("context_trimmed")
        if reply.refused:
            cat = reply.refusal_category or "unspecified"
            self.ui.say(
                f"the model declined this request (category: {cat}). Nothing was added "
                "to the conversation; rephrase or send less output.",
                "yellow",
            )
            self.audit.event("model_refusal", category=reply.refusal_category)
            return
        self.audit.event(
            "model_reply",
            text=reply.text,
            proposal=reply.proposal.to_dict() if reply.proposal else None,
            proposal_error=reply.proposal_error,
            stop_reason=reply.stop_reason,
            served_by=reply.served_by,
            usage=reply.usage,
        )
        if reply.served_by:
            self.ui.say(f"(answered by fallback model {reply.served_by})", "dim")
        self.ui.say("claude>", "magenta", trusted=True)
        self.ui.say(reply.text or "(no text)")
        if reply.proposal_error:
            self.ui.say(f"invalid command proposal ignored: {reply.proposal_error}", "yellow")
        if reply.proposal:
            self._offer(reply.proposal)

    def _offer(self, proposal: llm.Proposal) -> None:
        with self._lock:
            old = self.proposal
            self.proposal = proposal
            if old and self.conversation:
                self.conversation.record_outcome(old.id, "superseded")
        assert self.audit
        if old:
            self.audit.event("superseded", proposal_id=old.id, command=old.command)
        if self._push({"event": "proposal", "proposal": proposal.to_dict()}):
            k = self.cfg.keys
            self.ui.say(
                f"→ command proposed in the execute pane: {k['approve']} approve, {k['reject']} reject",
                "cyan",
                trusted=True,
            )
        else:
            self.ui.say("→ command proposed, but the execute pane is not connected", "yellow", trusted=True)

    def _do_mark(self, quiet: bool = False) -> None:
        state, _, _ = self.tmux.pane_state(self._shell_pane())
        with self._lock:
            self.mark = mark_at(state)
        if not quiet:
            self.ui.say(f"results mark set at line {self.mark.line}", "dim", trusted=True)


def main(session: str, cfg: Config) -> int:
    # tmux sends SIGHUP when the pane/session goes away. Turn it into a normal
    # exit so `finally` blocks remove the socket and close the audit log.
    def _exit(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, _exit)
    signal.signal(signal.SIGTERM, _exit)
    try:
        return Core(session, cfg).run()
    except (ipc.IPCError, runtime.RuntimeDirError, OSError) as e:
        print(f"tac core: {e}", file=sys.stderr)
        try:
            input("press Enter to close")
        except EOFError:
            pass
        return 1
