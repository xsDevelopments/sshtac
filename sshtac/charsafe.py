"""Character safety for commands about to be pasted into a shell.

A command is rejected if it contains anything a terminal or shell might act on
invisibly: ESC, CR, NUL, tab and other C0 controls, DEL, C1 controls, Unicode
format characters (bidi overrides, zero-width characters, BOM, tag characters)
and line/paragraph separators. A newline is not rejected here but flagged:
multi-line commands get their own handling.

Any other non-ASCII character is allowed but shown visibly (e.g. ⟨U+00A0⟩) so
look-alikes such as a no-break space can't hide in a command.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

_REJECT_CATEGORIES = frozenset({"Cf", "Zl", "Zp", "Cs", "Co", "Cn"})


def codepoint(ch: str) -> str:
    return f"⟨U+{ord(ch):04X}⟩"


def _describe(ch: str) -> str:
    o = ord(ch)
    names = {0x00: "NUL", 0x09: "TAB", 0x0D: "CR", 0x1B: "ESC", 0x7F: "DEL"}
    if o in names:
        return names[o]
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "control character"


def is_rejected(ch: str) -> bool:
    o = ord(ch)
    if ch == "\n":
        return False
    if o < 0x20 or o == 0x7F or 0x80 <= o <= 0x9F:
        return True
    return o > 0x7F and unicodedata.category(ch) in _REJECT_CATEGORIES


@dataclass
class CharReport:
    rejected: list[str] = field(default_factory=list)  # human-readable reasons
    multiline: bool = False
    non_ascii: bool = False

    @property
    def ok(self) -> bool:
        return not self.rejected


def check(command: str) -> CharReport:
    report = CharReport(multiline="\n" in command)
    seen: set[str] = set()
    for i, ch in enumerate(command):
        if is_rejected(ch):
            if ch not in seen:
                seen.add(ch)
                report.rejected.append(f"{codepoint(ch)} {_describe(ch)} at position {i}")
        elif ord(ch) > 0x7F:
            report.non_ascii = True
    return report


def visible(text: str) -> str:
    """Render a command for display: ASCII as-is (newlines kept), everything
    else as ⟨U+XXXX⟩."""
    return "".join(ch if ch == "\n" or 0x20 <= ord(ch) < 0x7F else codepoint(ch) for ch in text)
