"""Terminal output helpers for the chat and execute panes.

Everything printed here may contain text that came from the remote terminal, so
callers pass it through `pipeline.strip` first; `ChatUI.say` strips again
regardless. No markup interpretation (rich markup, etc.) is ever applied to
untrusted text.
"""

from __future__ import annotations

import codecs
import getpass
import os
import select
import sys
import termios
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


def read_secret(prompt: str, fd: int | None = None, out=None) -> str:
    """Read one line without showing it, printing `*` per character so you
    can see your typing arrive. Backspace and Ctrl+U edit; Enter ends it;
    Ctrl+C raises KeyboardInterrupt, Ctrl+D on an empty line EOFError, as
    with input(). Arrow and function keys are ignored. Not a terminal: getpass."""
    out = out or sys.stdout
    if fd is None:
        try:
            fd = sys.stdin.fileno()
        except (OSError, ValueError):
            return getpass.getpass(prompt)
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        return getpass.getpass(prompt)
    new = list(old)
    new[3] &= ~(termios.ECHO | termios.ICANON)  # ISIG stays: Ctrl+C still interrupts
    new[6] = list(old[6])
    new[6][termios.VMIN], new[6][termios.VTIME] = 1, 0
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    chars: list[str] = []
    out.write(prompt)
    out.flush()
    termios.tcsetattr(fd, termios.TCSANOW, new)
    try:
        while True:
            b = os.read(fd, 1)
            if not b:
                raise EOFError
            if b in (b"\r", b"\n"):
                break
            if b in (b"\x7f", b"\x08"):  # Backspace
                if chars:
                    chars.pop()
                    out.write("\b \b")
            elif b == b"\x15":  # Ctrl+U
                out.write("\b \b" * len(chars))
                chars.clear()
            elif b == b"\x04":  # Ctrl+D
                if not chars:
                    raise EOFError
            elif b == b"\x1b":
                _skip_escape(fd)
            elif b[0] < 0x20:
                pass  # other control keys
            else:
                for ch in decoder.decode(b):
                    chars.append(ch)
                    out.write("*")
            out.flush()
        return "".join(chars)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        out.write("\n")
        out.flush()
        chars.clear()


def _skip_escape(fd: int) -> None:
    """Swallow the rest of an escape sequence (an arrow or function key)."""
    if not select.select([fd], [], [], 0.05)[0]:
        return  # a lone Escape
    b = os.read(fd, 1)
    if b not in (b"[", b"O"):
        return
    while select.select([fd], [], [], 0.05)[0]:
        b = os.read(fd, 1)
        if not b or 0x40 <= b[0] <= 0x7E:
            return


class ChatUI:
    """Line-oriented output that doesn't trample the user's half-typed input.

    Background threads call `say`; the main thread sits in `input()`. While input
    is active we clear the prompt line, print, then redraw prompt + buffer.
    """

    prompt = "you> "
    cont_prompt = "...> "  # more lines of a paste

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.colour = self.out.isatty()
        self._lock = threading.Lock()
        self._in_input = False
        self._at_main_prompt = False
        self._shown_prompt = self.prompt
        self._stale: str | None = None
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
                buf = self._line_buffer()
                self.out.write("\r\x1b[2K" + text + "\n" + self._shown_prompt + buf)
            else:
                self.out.write(text + "\n")
            self.out.flush()

    def read_line(self, prompt: str | None = None, *, continuing: bool = False) -> str:
        """Blocking input(); raises EOFError / KeyboardInterrupt like input().
        No prompt means the chat prompt (`...>` when `continuing` a paste)."""
        chat = prompt is None
        shown = (self.cont_prompt if continuing else self.prompt) if chat else prompt
        with self._lock:
            self._in_input = True
            self._at_main_prompt = chat
            self._shown_prompt = shown
            self._stale = self._readline.get_line_buffer() if self._readline else None
        try:
            return input(shown)
        finally:
            with self._lock:
                self._in_input = self._at_main_prompt = False

    def input_waiting(self, timeout: float) -> bool:
        """More typed or pasted input is already queued on stdin. The terminal
        is briefly taken out of line mode for the check: in line mode a last
        pasted line without a newline doesn't count as readable (macOS)."""
        try:
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
        except (OSError, ValueError, termios.error):
            old = None
        try:
            if old is not None:
                new = list(old)
                new[3] &= ~(termios.ICANON | termios.ECHO)
                new[6] = list(old[6])
                new[6][termios.VMIN], new[6][termios.VTIME] = 1, 0
                termios.tcsetattr(fd, termios.TCSANOW, new)
            return bool(select.select([sys.stdin], [], [], timeout)[0])
        except (OSError, ValueError, termios.error):
            return False
        finally:
            if old is not None:
                try:
                    termios.tcsetattr(fd, termios.TCSANOW, old)
                except termios.error:
                    pass

    def draft(self) -> str:
        """What is typed at the `you>` prompt but not yet entered ("" if the
        prompt isn't up, e.g. during a y/N question)."""
        with self._lock:
            if not (self._at_main_prompt and self._readline):
                return ""
            return self._line_buffer()

    def _line_buffer(self) -> str:
        """The current input line. macOS's libedit keeps reporting the previous,
        already-entered line until a key is pressed, so ignore that value until
        the buffer has changed. Call with the lock held."""
        buf = self._readline.get_line_buffer() if self._readline else ""
        if self._stale is not None:
            if buf == self._stale:
                return ""
            self._stale = None
        return buf
