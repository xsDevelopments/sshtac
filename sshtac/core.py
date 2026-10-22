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
import subprocess
import sys
import threading
import time
from typing import Any

from sshtac import clipboard, ipc, llm, policy, runtime
from sshtac.audit import AuditLog
from sshtac.config import Config
from sshtac.marks import Mark, capture_range, mark_at
from sshtac.pipeline import SOURCES, redact, redact_session_secrets, strip
from sshtac.tmuxctl import Tmux, TmuxError
from sshtac.ui import ChatUI

MAX_SELECTION = 2 * 1024 * 1024
MAX_CHAT = 20_000
# Lines arriving closer together than this are one paste, not separate messages.
PASTE_GAP = 0.05
MAX_SECRETS = 64
LOG_KINDS = ("block", "edit")

HELP = """\
Type a question here and press Enter. Commands: /help /status /mark /sent
Tip: type a comment without pressing Enter, then {send_results}/{send_selection}: it goes along with the output
     Pasted lines are held as one message (...> prompt) until you press Enter
Mouse: click a pane to focus it; drag to select text, then {send_selection} sends it; wheel scrolls (q leaves)
Keys:  {send_results} = send new shell output   {approve} = approve   {reject} = reject   {focus_toggle} = shell⇄chat
Copy:  drag copies a selection   {copy_reply} = copy the AI's last reply   {copy_output} = copy new shell output
Leave: /detach (or Ctrl+B then d) keeps everything running — run sshtac again to come back.
       /quit ends sshtac completely, including the shell and any SSH connection."""

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
        self.proposals: dict[str, llm.Proposal] = {}  # every proposal this session, by id
        pol = cfg.raw["policy"]
        self.classifier = policy.Classifier(pol["blocked_patterns"], pol["destructive_patterns"])
        self._lock = threading.RLock()
        self._work: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.server: ipc.Server | None = None
        self.audit: AuditLog | None = None
        self.conversation: llm.Conversation | None = None
        self._client_factory = client_factory
        self.last_sent = ""
        self.last_reply = ""  # for the copy_reply key
        # Set while a send waits for the half-typed chat line (see _take_draft).
        self._draft_slot: dict[str, Any] | None = None
        self._paste_pending = False  # lines of a paste held back, waiting for Enter
        self.fake_model = os.environ.get("SSHTAC_TEST_FAKE_MODEL") == "1"
        if self.fake_model:
            from sshtac.testing import FakeClient

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
        self.ui.say(f"sshtac — session {self.session} — model {self.cfg.model}", "bold", trusted=True)
        self.ui.say(HELP.format(**self.cfg.key_labels), "dim", trusted=True)
        self.ui.say(f"audit log: {self.audit.path}", "dim", trusted=True)
        self.ui.say(f"config: {self.cfg.source or 'built-in defaults (no config file)'}", "dim", trusted=True)
        if self.fake_model:
            self.ui.say("SSHTAC_TEST_FAKE_MODEL=1: using the scripted fake model, no API calls", "boldyellow", trusted=True)
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
        raw = self.tmux.get_option(self.session, "@sshtac_ssh_args")
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
            reasoning_summary=ai["show_reasoning"] != "never",
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
        # A multi-line paste reaches us as several Enter-terminated lines in
        # quick succession. Those are collected into one message, which is sent
        # on your next Enter (so you can add to it) or with F5/F6.
        pending: list[str] = []

        def set_pending(lines: list[str]) -> None:
            pending[:] = lines
            with self._lock:
                self._paste_pending = bool(lines)

        while True:
            started = time.monotonic()
            try:
                line = self.ui.read_line(continuing=bool(pending))
            except KeyboardInterrupt:
                print()
                if pending:
                    set_pending([])
                    self.ui.say("(pasted text discarded)", "dim", trusted=True)
                continue
            except EOFError:
                print()
                self.ui.say("(Ctrl-D ignored — use `sshtac stop` to end the session)", "dim", trusted=True)
                continue
            quick = time.monotonic() - started < PASTE_GAP
            waiting = self.ui.input_waiting(PASTE_GAP)
            with self._lock:
                slot, self._draft_slot = self._draft_slot, None
            if slot is not None:
                # Submitted for a send (F5/F6), not a chat message.
                slot["text"] = "\n".join([*pending, line]).strip()
                set_pending([])
                slot["done"].set()
            elif waiting or (pending and quick):
                set_pending([*pending, line])  # more of a paste
                if not waiting:
                    k = self.cfg.key_labels
                    self.ui.say(
                        f"(pasted {len(pending)} line{'s' * (len(pending) != 1)}, not sent yet: add more and press Enter to send, "
                        f"or {k['send_results']} to send with new shell output; Ctrl-C discards)",
                        "dim", trusted=True,
                    )
            elif pending:
                text = "\n".join([*pending, line]).strip()
                set_pending([])
                if text:
                    self._work.put({"cmd": "chat", "text": text[:MAX_CHAT]})
            elif line.strip():
                self._handle_chat(line.strip())

    def _handle_chat(self, line: str) -> None:
        if line in ("/help", "/?"):
            self.ui.say(HELP.format(**self.cfg.key_labels), "dim", trusted=True)
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
        elif line == "/detach":
            self.tmux.run("detach-client", "-s", f"={self.session}", check=False)
        elif line in ("/quit", "/exit"):
            self._quit()
        elif line.startswith("/"):
            self.ui.say(f"unknown command {line.split()[0]}; try /help", "yellow")
        else:
            self._work.put({"cmd": "chat", "text": line[:MAX_CHAT]})

    def _quit(self) -> None:
        try:
            ans = self.ui.read_line("End sshtac now? This closes the shell and any SSH connection. [y/N] ")
        except (EOFError, KeyboardInterrupt):
            ans = ""
        if ans.strip().lower() not in ("y", "yes"):
            self.ui.say("not quitting (use /detach to leave it running)", "dim", trusted=True)
            return
        self.ui.say("ending the session…", "yellow", trusted=True)
        if self.audit:
            self.audit.event("quit")
        # Killing the session sends us SIGHUP; main()'s handler turns that into
        # a normal exit, so the socket is removed and the audit log closed.
        self.tmux.kill_session(self.session)

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
            # Taken now, at the key press, not when the worker gets to it.
            self._work.put({**msg, "draft_slot": self._take_draft()})
            return {"ok": True}
        if cmd == "mark":
            self._work.put(msg)
            return {"ok": True}
        if cmd == "copy":
            # Here, not on the worker: it may be busy waiting for the model.
            if msg.get("what") not in ("reply", "output"):
                return {"ok": False, "error": "bad copy request"}
            return self._copy(msg["what"])
        if cmd == "mark_now":
            # Synchronous: the executor sets the mark between paste and Enter.
            try:
                self._do_mark(quiet=True)
            except (TmuxError, RuntimeError) as e:
                return {"ok": False, "error": str(e)}
            return {"ok": True}
        if cmd in ("outcome", "add_secrets", "log"):
            with self._lock:
                expected = self.executor_token
            token = msg.get("token")
            if not expected or not isinstance(token, str) or not hmac.compare_digest(token, expected):
                return {"ok": False, "error": f"{cmd} must come from the connected execute pane"}
            if cmd == "outcome":
                return self._handle_outcome(msg)
            if cmd == "add_secrets":
                return self._add_secrets(msg)
            return self._handle_log(msg)
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

    def _redact(self, text: str) -> str:
        """Regex + session-secret redaction for anything we log or send that
        the human may have typed (edited commands)."""
        with self._lock:
            secrets_ = set(self.session_secrets)
        text, _ = redact_session_secrets(strip(text), secrets_)
        text, _ = redact(text, self.pipeline.patterns, self.pipeline.entropy)
        return text

    def _handle_outcome(self, msg: dict[str, Any]) -> dict[str, Any]:
        pid, outcome = msg.get("id"), msg.get("outcome")
        if outcome not in OUTCOMES or not isinstance(pid, str):
            return {"ok": False, "error": "bad outcome"}
        with self._lock:
            prop = self.proposals.get(pid)
            if prop is None:
                return {"ok": False, "error": "unknown proposal"}
            if self.proposal is not None and self.proposal.id == pid:
                self.proposal = None
        command = msg.get("command") if isinstance(msg.get("command"), str) else prop.command
        edited = bool(msg.get("edited"))
        shown = self._redact(command)
        detail = f"The human edited it first; what ran was: {shown}" if edited and outcome == "approved" else ""
        if edited and outcome == "rejected":
            detail = "(after editing it)"
        if self.conversation:
            self.conversation.record_outcome(pid, outcome, detail)
        names = [n for n in msg.get("placeholders", []) if isinstance(n, str)]
        assert self.audit
        self.audit.event(
            outcome,
            proposal_id=pid,
            command=shown,
            edited=edited,
            placeholders=names,  # names only, never values
            prefixed_space=bool(msg.get("prefixed_space")),
            local_risk=msg.get("local_risk"),
            effective_risk=msg.get("effective"),
        )
        colour = {"approved": "green", "rejected": "yellow"}.get(outcome, "dim")
        self.ui.say(f"[{outcome}{' after edit' if edited else ''}] {shown}", colour)
        return {"ok": True}

    def _add_secrets(self, msg: dict[str, Any]) -> dict[str, Any]:
        values = msg.get("values")
        if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values) or len(values) > MAX_SECRETS:
            return {"ok": False, "error": "bad secrets"}
        with self._lock:
            self.session_secrets.update(values)
        return {"ok": True}

    def _handle_log(self, msg: dict[str, Any]) -> dict[str, Any]:
        kind = msg.get("kind")
        if kind not in LOG_KINDS:
            return {"ok": False, "error": "bad log kind"}
        pid = msg.get("proposal_id")
        fields: dict[str, Any] = {
            "proposal_id": pid,
            "local_risk": msg.get("local_risk"),
            "effective_risk": msg.get("effective"),
            "reasons": [r for r in msg.get("reasons", []) if isinstance(r, str)][:10],
        }
        if kind == "edit":
            before, after = msg.get("before"), msg.get("after")
            if not isinstance(before, str) or not isinstance(after, str):
                return {"ok": False, "error": "bad edit"}
            fields["before"], fields["after"] = self._redact(before), self._redact(after)
            self.ui.say(f"[edited] {fields['after']}  (local: {fields['local_risk']})", "cyan")
        else:
            command = msg.get("command")
            fields["command"] = self._redact(command) if isinstance(command, str) else None
            self.ui.say(f"[blocked] approval refused: {'; '.join(fields['reasons'][:1])}", "red")
        assert self.audit
        self.audit.event(kind, **fields)
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
        pane = self.tmux.get_option(self.session, "@sshtac_shell_pane")
        if not pane:
            raise RuntimeError("@sshtac_shell_pane is not set on this session")
        return pane

    def _capture_results(self, advance: bool = True) -> tuple[str, str | None]:
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
            if advance:
                self.mark = mark_at(state)
        if rng.note:
            notes.append(rng.note)
        text = self.tmux.capture(pane, rng.start, rng.end)
        return text.rstrip("\n"), "; ".join(notes) or None

    def _take_draft(self) -> dict[str, Any] | None:
        """If something is typed at `you>` (not a /command), press Enter in the
        chat pane so the input loop hands that line to this send (F5/F6)
        instead of sending it as a chat message. Submitting the line works the
        same in GNU readline, vi mode and macOS's libedit, and leaves it on
        screen. Returns the slot the input loop fills, or None."""
        text = self.ui.draft()
        with self._lock:
            paste = self._paste_pending
        if not paste and (not text.strip() or text.lstrip().startswith("/")):
            return None
        pane = self.tmux.get_option(self.session, "@sshtac_chat_pane")
        if not pane:
            return None
        slot: dict[str, Any] = {"done": threading.Event(), "text": ""}
        with self._lock:
            self._draft_slot = slot
        try:
            self.tmux.run("send-keys", "-t", pane, "Enter")
        except TmuxError:
            with self._lock:
                self._draft_slot = None
            return None
        return slot

    def _wait_draft(self, slot: dict[str, Any] | None) -> str:
        if slot is None:
            return ""
        slot["done"].wait(2.0)
        with self._lock:
            if self._draft_slot is slot:  # never arrived; a late line is plain chat
                self._draft_slot = None
        return slot["text"][:MAX_CHAT]

    def _do_send(self, msg: dict[str, Any]) -> None:
        source = msg["source"]
        draft = self._wait_draft(msg.get("draft_slot"))
        if source == "results_buffer":
            raw, note = self._capture_results()
        else:
            raw, note = msg["text"], None
        if not raw.strip():
            self.ui.say(f"[{source}] nothing new to send", "yellow", trusted=True)
            if draft:
                self.ui.say("sending your typed message on its own", "dim", trusted=True)
                self._do_chat(draft)
            return
        with self._lock:
            secrets = set(self.session_secrets)
        prepared = self.pipeline.prepare(raw, source, secrets)
        chat = self._clean_chat(draft) if draft else None
        assert self.audit
        self.audit.event(
            "send",
            source=source,
            text=prepared.text,
            redactions=dict(prepared.redactions),
            truncated=bool(prepared.truncation),
            note=note,
            chat=chat,
        )
        self.ui.say("─" * 40, "dim", trusted=True)
        self.ui.say(f"sent {source.replace('_', ' ')}: {prepared.summary()}", "cyan", trusted=True)
        if note:
            self.ui.say(f"note: {note}", "yellow")
        # Your words go after the output, outside the <terminal_output> tags.
        self._ask(prepared.text, chat)

    def _clean_chat(self, text: str) -> str:
        # Your own typing is trusted (not wrapped), but it still goes through
        # stripping and redaction in case you paste something sensitive.
        with self._lock:
            secrets = set(self.session_secrets)
        clean, n = redact_session_secrets(strip(text), secrets)
        clean, counts = redact(clean, self.pipeline.patterns, self.pipeline.entropy)
        if n or counts:
            self.ui.say("note: redacted part of your message before sending", "yellow", trusted=True)
        return clean

    def _do_chat(self, text: str) -> None:
        clean = self._clean_chat(text)
        assert self.audit
        self.audit.event("chat", text=clean)
        self._ask(clean)

    def _ask(self, text: str, comment: str | None = None) -> None:
        conv = self.conversation
        if conv is None:
            self.ui.say("(AI is disabled — see the message above)", "dim", trusted=True)
            return
        self.last_sent = f"{text}\n\n{comment}" if comment else text
        self.ui.say("… asking the model", "dim", trusted=True)
        assert self.audit
        try:
            reply = conv.ask(text, comment)
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
            reasoning=reply.reasoning,
            stop_reason=reply.stop_reason,
            served_by=reply.served_by,
            usage=reply.usage,
        )
        if reply.served_by:
            self.ui.say(f"(answered by fallback model {reply.served_by})", "dim")
        self.ui.say("claude>", "magenta", trusted=True)
        mode = self.cfg.ai["show_reasoning"]
        if reply.reasoning and (mode == "always" or (mode == "auto" and not reply.text)):
            self.ui.say("(reasoning summary)", "dim", trusted=True)
            self.ui.say(reply.reasoning, "dim")
        if reply.text:
            self.ui.say(reply.text)
        elif not reply.reasoning:
            if reply.proposal:
                self.ui.say(f"(no explanation given; the model's stated purpose: {reply.proposal.purpose})", "yellow")
            else:
                self.ui.say("(the model returned no text)", "yellow")
        if reply.proposal_error:
            self.ui.say(f"invalid command proposal ignored: {reply.proposal_error}", "yellow")
        with self._lock:
            self.last_reply = _reply_for_copy(reply)
        if reply.proposal:
            self._offer(reply.proposal)

    # ---------------------------------------------------------------- clipboard

    def _copy(self, what: str) -> dict[str, Any]:
        if what == "reply":
            with self._lock:
                text = self.last_reply
            label = "the AI's last reply"
        else:
            try:
                text, _ = self._capture_results(advance=False)
            except (TmuxError, RuntimeError) as e:
                return {"ok": False, "error": str(e)}
            label = "shell output since your last command"
        if not text.strip():
            msg = "nothing to copy yet" if what == "reply" else "no new shell output to copy"
            self.ui.say(f"[copy] {msg}", "yellow", trusted=True)
            return {"ok": True}
        # tmux's buffer (Ctrl+B ] pastes it) and, with -w, the terminal via OSC 52.
        self.tmux.run("load-buffer", "-w", "-", input=text.encode("utf-8"), check=False)
        where = "tmux's buffer"
        cmd = self.tmux.run("show-options", "-sv", "copy-command", check=False).strip()
        if cmd:
            try:
                clipboard.copy(cmd, text)
                where = "the clipboard"
            except (OSError, subprocess.SubprocessError) as e:
                self.ui.say(f"[copy] clipboard tool failed ({type(e).__name__}); copied to tmux's buffer only", "yellow",
                            trusted=True)
        elif self.cfg.raw["tmux"]["clipboard"] != "off":
            where = "tmux's buffer and, if your terminal supports OSC 52, the clipboard"
        lines = text.count("\n") + 1
        self.ui.say(f"[copy] {label} ({lines} line{'s' * (lines != 1)}) → {where}", "cyan", trusted=True)
        return {"ok": True}

    def _offer(self, proposal: llm.Proposal) -> None:
        with self._lock:
            old = self.proposal
            self.proposal = proposal
            self.proposals[proposal.id] = proposal
            if old and self.conversation:
                self.conversation.record_outcome(old.id, "superseded")
        assert self.audit
        if old:
            self.audit.event("superseded", proposal_id=old.id, command=old.command)
        verdict = self.classifier.classify(proposal.command)
        eff = policy.effective(proposal.risk, verdict.risk)
        self.audit.event(
            "classification",
            proposal_id=proposal.id,
            local_risk=verdict.risk.label,
            model_risk=proposal.risk,
            effective_risk=eff.label,
            reasons=verdict.reasons,
            injection_suspected=proposal.injection_suspected,
        )
        if self._push({"event": "proposal", "proposal": proposal.to_dict()}):
            k = self.cfg.key_labels
            colour = {policy.Risk.BLOCKED: "red", policy.Risk.DESTRUCTIVE: "red"}.get(eff, "cyan")
            self.ui.say(
                f"→ command proposed ({eff.label}) in the execute pane: "
                f"{k['approve']} approve, {k['reject']} reject, {k['edit']} edit",
                colour,
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
        print(f"sshtac core: {e}", file=sys.stderr)
        try:
            input("press Enter to close")
        except EOFError:
            pass
        return 1


def _reply_for_copy(reply: llm.Reply) -> str:
    """What the copy_reply key copies: the reply text (or, without one, the
    reasoning summary), then the proposed command on its own line."""
    parts = [reply.text.strip() or (reply.reasoning or "").strip()]
    if reply.proposal:
        parts.append(f"Proposed command:\n{reply.proposal.command}")
    return "\n\n".join(p for p in parts if p)

