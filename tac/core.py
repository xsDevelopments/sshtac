"""The core process: runs in the chat pane.

Owns the IPC server, the results-buffer mark, the session-secret set and (from
phase 2) the conversation. Key bindings talk to it through short-lived clients;
the executor holds a persistent connection and receives events from it.

Phase 1: captured text goes through the outgoing pipeline and is echoed here
exactly as it would be sent. No API calls.
"""

from __future__ import annotations

import queue
import signal
import sys
import threading
from typing import Any

from tac import ipc, runtime
from tac.config import Config
from tac.marks import Mark, capture_range, mark_at
from tac.pipeline import SOURCES
from tac.tmuxctl import Tmux, TmuxError
from tac.ui import ChatUI

MAX_SELECTION = 2 * 1024 * 1024

HELP = """\
Commands:  /help  /status  /mark (reset the results mark to the current line)
Keys:      {send_selection} in copy mode = send selection   {send_results} = send new output
           {approve} = approve   {reject} = reject   {edit} = edit
End the session with `tac stop` from any shell (or kill the tmux session)."""


class Core:
    def __init__(self, session: str, cfg: Config):
        self.session = runtime.check_session_name(session)
        self.cfg = cfg
        self.tmux = Tmux(cfg.tmux_socket)
        self.pipeline = cfg.pipeline()
        self.ui = ChatUI()
        self.mark: Mark | None = None
        # Values typed for placeholders this session. Memory only, never logged.
        self.session_secrets: set[str] = set()
        self.executor: ipc.Connection | None = None
        self._lock = threading.Lock()
        self._work: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self.server: ipc.Server | None = None

    # ---------------------------------------------------------------- lifecycle

    def run(self) -> int:
        path = runtime.socket_path(self.cfg.tmux_socket, self.session)
        self.server = ipc.Server(path, self.dispatch, self._on_disconnect)
        self.server.start()
        worker = threading.Thread(target=self._worker, daemon=True)
        worker.start()
        self.ui.say(f"tac core — session {self.session}", "bold", trusted=True)
        self.ui.say(HELP.format(**self.cfg.keys), "dim", trusted=True)
        self.ui.say("Phase 1: captures are echoed here as they would be sent; no AI yet.", "dim", trusted=True)
        try:
            self._set_initial_mark()
            self._input_loop()
        finally:
            self._work.put(None)
            self.server.close()
        return 0

    def _set_initial_mark(self) -> None:
        # The results buffer starts at the shell's cursor line at launch. If the
        # shell pane isn't readable yet, the first send captures all history.
        try:
            pane = self._shell_pane()
            state, _, _ = self.tmux.pane_state(pane)
            self.mark = mark_at(state)
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
            self.ui.say(
                f"mark={self.mark}  executor={'connected' if self.executor else 'not connected'}  "
                f"session_secrets={len(self.session_secrets)}  model={self.cfg.model}",
                "dim",
            )
        elif line == "/mark":
            self._work.put({"cmd": "mark"})
        elif line.startswith("/"):
            self.ui.say(f"unknown command {line.split()[0]}; try /help", "yellow")
        else:
            self.ui.say("(the AI arrives in phase 2 — chat is not sent anywhere yet)", "dim", trusted=True)

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
            self.ui.say("execute pane connected", "dim", trusted=True)
            return {"ok": True}
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
        if cmd in ("approve", "reject", "edit"):
            return self._forward_to_executor(cmd)
        return {"ok": False, "error": f"unknown command {cmd!r}"}

    def _on_disconnect(self, conn: ipc.Connection) -> None:
        with self._lock:
            if conn is self.executor:
                self.executor = None
                self.ui.say("execute pane disconnected", "yellow", trusted=True)

    def _forward_to_executor(self, action: str) -> dict[str, Any]:
        with self._lock:
            ex = self.executor
        if ex is None:
            return {"ok": False, "error": "execute pane is not connected"}
        try:
            ex.send({"event": action})
        except OSError as e:
            return {"ok": False, "error": f"execute pane unreachable: {e}"}
        return {"ok": True}

    # ---------------------------------------------------------------- work

    def _worker(self) -> None:
        while (msg := self._work.get()) is not None:
            try:
                if msg["cmd"] == "send":
                    self._do_send(msg)
                elif msg["cmd"] == "mark":
                    self._do_mark()
            except Exception as e:  # never let one bad capture kill the core
                self.ui.say(f"error: {type(e).__name__}: {e}", "red")

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
        rng = capture_range(self.mark, state)
        if rng.note:
            notes.append(rng.note)
        text = self.tmux.capture(pane, rng.start, rng.end)
        # Advance the mark to the current (cursor) line; it is included again
        # next time so the prompt + next command give context.
        self.mark = mark_at(state)
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
        prepared = self.pipeline.prepare(raw, source, self.session_secrets)
        self.ui.say("─" * 40, "dim", trusted=True)
        self.ui.say(f"would send ({prepared.summary()}):", "cyan", trusted=True)
        if note:
            self.ui.say(f"note: {note}", "yellow")
        self.ui.say(prepared.text)

    def _do_mark(self) -> None:
        state, _, _ = self.tmux.pane_state(self._shell_pane())
        self.mark = mark_at(state)
        self.ui.say(f"results mark set at line {self.mark.line}", "dim", trusted=True)


def main(session: str, cfg: Config) -> int:
    # tmux sends SIGHUP when the pane/session goes away. Turn it into a normal
    # exit so `finally` blocks remove the socket.
    def _exit(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, _exit)
    signal.signal(signal.SIGTERM, _exit)
    try:
        return Core(session, cfg).run()
    except (ipc.IPCError, runtime.RuntimeDirError) as e:
        print(f"tac core: {e}", file=sys.stderr)
        try:
            input("press Enter to close")
        except EOFError:
            pass
        return 1
