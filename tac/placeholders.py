"""{{PLACEHOLDER}} handling: find them, and substitute values safely.

Values are typed by the human (getpass), held in memory only, and inserted so
the shell sees them as one literal word whatever they contain:

* outside quotes:        {{X}}       ->  'value'
* inside single quotes:  '..{{X}}..' ->  '..''value''..'    (close, quote, reopen)
* inside double quotes:  "..{{X}}.." ->  "..""'value'""..". (same idea)

shlex.quote produces the single-quoted form, which nothing inside can escape
from: no expansion, no history expansion (!), no word splitting. A value can't
contain newlines or control characters (getpass reads one line, and the final
command is re-checked by charsafe anyway).
"""

from __future__ import annotations

import re
import shlex

from tac import charsafe

TOKEN_RE = re.compile(r"\{\{([A-Z][A-Z0-9_]*)\}\}")


class PlaceholderError(ValueError):
    pass


def names(command: str) -> list[str]:
    """Placeholder names in order of first appearance."""
    seen: list[str] = []
    for n in TOKEN_RE.findall(command):
        if n not in seen:
            seen.append(n)
    return seen


def _check_value(name: str, value: str) -> None:
    if value == "":
        raise PlaceholderError(f"{name}: empty value")
    for ch in value:
        if charsafe.is_rejected(ch) or ch == "\n":
            raise PlaceholderError(f"{name}: value contains a control or invisible character")


def substitute(command: str, values: dict[str, str]) -> str:
    """Replace every {{NAME}} with its value, quoted for its context."""
    missing = [n for n in names(command) if n not in values]
    if missing:
        raise PlaceholderError(f"no value for {', '.join(missing)}")
    for n, v in values.items():
        _check_value(n, v)

    out: list[str] = []
    i, n = 0, len(command)
    state = None  # None | "'" | '"'
    while i < n:
        m = TOKEN_RE.match(command, i)
        if m:
            q = shlex.quote(values[m.group(1)])
            if state is None:
                out.append(q)
            elif state == "'":
                out.append("'" + q + "'")
            else:
                out.append('"' + q + '"')
            i = m.end()
            continue
        c = command[i]
        if state is None:
            if c == "\\" and i + 1 < n:
                out.append(command[i : i + 2])
                i += 2
                continue
            if c == "$" and command.startswith("$'", i):
                raise PlaceholderError("placeholders inside $'...' strings are not supported")
            if c in "'\"":
                state = c
        elif state == "'":
            if c == "'":
                state = None
        else:  # double quotes
            if c == "\\" and i + 1 < n:
                out.append(command[i : i + 2])
                i += 2
                continue
            if c == '"':
                state = None
        out.append(c)
        i += 1
    if state is not None:
        raise PlaceholderError("unbalanced quotes in the command")
    return "".join(out)
