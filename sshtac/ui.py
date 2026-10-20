"""Terminal output helpers for the chat and execute panes.

Everything printed here may contain text that came from the remote terminal, so
callers pass it through `pipeline.strip` first; `ChatUI.say` strips again
regardless. No markup interpretation (rich markup, etc.) is ever applied to
untrusted text.
"""

from __future__ import annotations

import sys
import threading

from sshtac.pipeline import strip

_COLOURS = {
    "dim": "2",
    "bold": "1",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "blue": "34",
    "magenta": "35",
    "cyan": "36",
    "boldred": "1;31",
    "boldyellow": "1;33",
}


def style(text: str, name: str | None, enabled: bool = True) -> str:
    if not name or not enabled:
        return text
    return f"\x1b[{_COLOURS[name]}m{text}\x1b[0m"


class ChatUI:
    """Line-oriented output that doesn't trample the user's half-typed input.

    Background threads call `say`; the main thread sits in `input()`. While input
    is active we clear the prompt line, print, then redraw prompt + buffer.
    """

    prompt = "you> "

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.colour = self.out.isatty()
        self._lock = threading.Lock()
        self._in_input = False
        self._at_main_prompt = False
        try:
            import readline  # noqa: F401  (line editing for input())

            self._readline = readline
        except ImportError:
            self._readline = None

    def say(self, text: str, colour: str | None = None, *, trusted: bool = False) -> None:
        if not trusted:
            text = strip(text)
        text = style(text, colour, self.colour)
        with self._lock:
            if self._in_input and self.colour:
                buf = self._readline.get_line_buffer() if self._readline else ""
                self.out.write("\r\x1b[2K" + text + "\n" + self.prompt + buf)
            else:
                self.out.write(text + "\n")
            self.out.flush()

    def read_line(self, prompt: str | None = None) -> str:
        """Blocking input(); raises EOFError / KeyboardInterrupt like input()."""
        with self._lock:
            self._in_input = True
            self._at_main_prompt = prompt is None
        try:
            return input(self.prompt if prompt is None else prompt)
        finally:
            with self._lock:
                self._in_input = self._at_main_prompt = False

    def draft(self) -> str:
        """What is typed at the `you>` prompt but not yet entered ("" if the
        prompt isn't up, e.g. during a y/N question)."""
        with self._lock:
            if not (self._at_main_prompt and self._readline):
                return ""
            return self._readline.get_line_buffer()
