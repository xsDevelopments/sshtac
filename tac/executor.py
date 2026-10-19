"""The execute pane: shows the pending command and handles approve/reject/edit.

Phase 1: connects to the core and acknowledges key presses. There is never a
pending command yet, so nothing can be pasted.
"""

from __future__ import annotations

import signal
import sys
import time

from tac import ipc, runtime
from tac.config import Config
from tac.ui import style

CONNECT_TIMEOUT = 15.0


def _connect(tmux_socket: str, session: str) -> ipc.Subscription:
    path = runtime.socket_path(tmux_socket, session)
    deadline = time.monotonic() + CONNECT_TIMEOUT
    while True:
        try:
            return ipc.Subscription(path, {"cmd": "hello_executor"})
        except ipc.IPCError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)


def main(session: str, cfg: Config) -> int:
    def _exit(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGHUP, _exit)
    signal.signal(signal.SIGTERM, _exit)
    colour = sys.stdout.isatty()
    k = cfg.keys

    def say(text: str, c: str | None = None) -> None:
        print(style(text, c, colour), flush=True)

    say("EXECUTE", "bold")
    say(f"{k['approve']} approve   {k['reject']} reject   {k['edit']} edit", "dim")
    try:
        sub = _connect(cfg.tmux_socket, session)
    except ipc.IPCError as e:
        say(f"cannot reach the core: {e}", "red")
        time.sleep(3600)
        return 1
    say("No pending command.", "dim")
    try:
        for ev in sub.events():
            action = ev.get("event")
            if action in ("approve", "reject", "edit"):
                say(f"[{action}] no pending command (proposals arrive in phase 2)", "yellow")
        say("core disconnected", "red")
    finally:
        sub.close()
    return 0
