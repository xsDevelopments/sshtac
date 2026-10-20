"""Thin wrapper around the tmux CLI. Every tmux call in sshtac goes through here.

All calls use a dedicated server (`tmux -L <socket_name>`), and arguments are
passed as argv, never through a shell.
"""

from __future__ import annotations

import re
import shutil
import subprocess

from sshtac.marks import PaneState

MIN_VERSION = (3, 2)


class TmuxError(Exception):
    pass


def parse_version(text: str) -> tuple[int, int]:
    """'tmux 3.4' / 'tmux 3.3a' / 'tmux next-3.5' -> (3, 4)."""
    m = re.search(r"(\d+)\.(\d+)", text)
    if not m:
        raise TmuxError(f"can't parse tmux version from {text!r}")
    return int(m.group(1)), int(m.group(2))


class Tmux:
    def __init__(self, socket_name: str = "sshtac", binary: str | None = None):
        self.socket_name = socket_name
        self.binary = binary or shutil.which("tmux") or "tmux"

    def argv(self, *args: str) -> list[str]:
        return [self.binary, "-L", self.socket_name, *args]

    def run(self, *args: str, input: bytes | None = None, check: bool = True) -> str:
        try:
            p = subprocess.run(self.argv(*args), input=input, capture_output=True, timeout=10)
        except FileNotFoundError:
            raise TmuxError("tmux not found on PATH") from None
        except subprocess.TimeoutExpired:
            raise TmuxError(f"tmux {args[0]} timed out") from None
        if check and p.returncode != 0:
            err = p.stderr.decode(errors="replace").strip()
            raise TmuxError(f"tmux {args[0]}: {err or f'exit {p.returncode}'}")
        return p.stdout.decode(errors="replace")

    # ----------------------------------------------------------------- queries

    def version(self) -> tuple[int, int]:
        return parse_version(self.run("-V"))

    def has_session(self, name: str) -> bool:
        # "=name" forces an exact match rather than a prefix match.
        return self._rc_ok("has-session", "-t", f"={name}")

    def _rc_ok(self, *args: str) -> bool:
        try:
            return subprocess.run(self.argv(*args), capture_output=True, timeout=10).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def display(self, target: str, fmt: str) -> str:
        return self.run("display-message", "-p", "-t", target, fmt).rstrip("\n")

    def list_sessions(self) -> list[str]:
        if not self._rc_ok("list-sessions"):
            return []
        return [s for s in self.run("list-sessions", "-F", "#{session_name}").splitlines() if s]

    def get_option(self, session: str, name: str) -> str | None:
        out = self.run("show-options", "-v", "-q", "-t", f"={session}:", name, check=False).strip()
        return out or None

    def pane_state(self, pane: str) -> tuple[PaneState, bool, bool]:
        """(state, pane_dead, alternate_on)."""
        out = self.display(
            pane, "#{history_size} #{cursor_y} #{history_limit} #{pane_dead} #{alternate_on}"
        )
        try:
            h, y, lim, dead, alt = out.split()
            return PaneState(int(h), int(y), int(lim)), dead == "1", alt == "1"
        except ValueError:
            raise TmuxError(f"unexpected pane state {out!r} for {pane}") from None

    def capture(self, pane: str, start: int, end: int) -> str:
        # -J joins wrapped lines; no -e, so no escape sequences come through.
        out = self.run("capture-pane", "-p", "-J", "-t", pane, "-S", str(start), "-E", str(end))
        # -J keeps trailing spaces; they are padding, not output.
        return "\n".join(line.rstrip(" ") for line in out.split("\n"))

    # ----------------------------------------------------------------- actions

    def set_option(self, session: str, name: str, value: str) -> None:
        self.run("set-option", "-t", f"={session}:", name, value)

    def set_pane_option(self, pane: str, name: str, value: str, check: bool = True) -> None:
        self.run("set-option", "-p", "-t", pane, name, value, check=check)

    def display_message(self, target: str | None, msg: str) -> None:
        # The message is a format string: escape '#' so it is shown literally.
        args = ["display-message"]
        if target:
            args += ["-t", target]
        self.run(*args, msg.replace("#", "##"), check=False)

    def pane_in_mode(self, pane: str) -> bool:
        return self.display(pane, "#{pane_in_mode}") == "1"

    def paste(self, pane: str, text: str, buffer: str) -> None:
        """Bracketed paste of `text` into `pane`, never via a file: the text goes
        in on stdin, and the buffer is deleted as part of the paste (-d)."""
        self.run("load-buffer", "-b", buffer, "-", input=text.encode())
        try:
            self.run("paste-buffer", "-p", "-d", "-b", buffer, "-t", pane)
        except TmuxError:
            self.run("delete-buffer", "-b", buffer, check=False)
            raise

    def send_enter(self, pane: str) -> None:
        self.run("send-keys", "-t", pane, "Enter")

    def select_pane(self, pane: str) -> None:
        self.run("select-pane", "-t", pane)

    def kill_session(self, name: str) -> None:
        self.run("kill-session", "-t", f"={name}")
