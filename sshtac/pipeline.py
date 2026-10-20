"""Outgoing pipeline. Everything sent to the model passes through `Pipeline.prepare`.

Steps, in order:

1. strip           ANSI escapes and control characters (keeps only \\n and \\t);
                   invisible Unicode format characters are made visible.
2. session secrets values entered for placeholders this session, exact match.
3. redact          configurable regexes, replaced with [REDACTED:<type>].
4. truncate        head + tail with a marker, to the configured cap.
5. wrap            <terminal_output source="..."> delimiters; any copy of the
                   delimiter inside the content is neutralised.

Session secrets run before the regexes (the spec lists them after) so that a
regex match overlapping part of a secret can never leave the rest of it behind.

All functions here are pure: no I/O, no globals mutated.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

SOURCES = frozenset({"selection", "results_buffer"})


def redaction_tag(kind: str) -> str:
    return f"[REDACTED:{kind}]"


# --------------------------------------------------------------------------- 1. strip

_ANSI_RE = re.compile(
    r"""
      \x1b\[[0-?]*[ -/]*[@-~]                  # CSI
    | \x1b\][^\x07\x1b\n]*(?:\x07|\x1b\\)?     # OSC, ended by BEL or ST
    | \x1b[PX^_][^\x1b\n]*(?:\x1b\\)?          # DCS / SOS / PM / APC
    | \x1b[ -/]*[0-~]                          # other ESC sequences
    | \x9b[0-?]*[ -/]*[@-~]                    # 8-bit CSI
    """,
    re.VERBOSE,
)
# C0 except \t and \n, DEL, and C1.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_NON_ASCII_RE = re.compile(r"[^\x00-\x7f]")
# Format characters (zero-width, bidi overrides, BOM, Unicode tag characters used
# for "invisible" prompt injection) and line/paragraph separators.
_INVISIBLE_CATEGORIES = frozenset({"Cf", "Zl", "Zp"})


def visible_codepoint(ch: str) -> str:
    return f"⟨U+{ord(ch):04X}⟩"


def _make_visible(m: re.Match[str]) -> str:
    ch = m.group()
    if unicodedata.category(ch) in _INVISIBLE_CATEGORIES:
        return visible_codepoint(ch)
    return ch


def strip(text: str) -> str:
    """Remove terminal escapes and control characters, keeping \\n and \\t.

    A bare CR becomes a newline rather than being dropped, so carriage-return
    overwrites (progress bars, or tricks that hide text from a human viewer) stay
    readable instead of silently merging lines.
    """
    text = text.replace("\r\n", "\n")
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r", "\n")
    text = _CTRL_RE.sub("", text)
    return _NON_ASCII_RE.sub(_make_visible, text)


# --------------------------------------------------------------------------- 2. session secrets


def redact_session_secrets(text: str, secrets: Iterable[str]) -> tuple[str, int]:
    """Replace every exact occurrence of each secret. Longest first, so a secret
    that contains another is removed whole."""
    variants: set[str] = set()
    for s in secrets:
        if s:
            variants.add(s)
            stripped = strip(s)
            if stripped:
                variants.add(stripped)
    count = 0
    tag = redaction_tag("session_secret")
    for s in sorted(variants, key=len, reverse=True):
        n = text.count(s)
        if n:
            text = text.replace(s, tag)
            count += n
    return text, count


# --------------------------------------------------------------------------- 3. regex redaction


@dataclass(frozen=True)
class RedactionPattern:
    """A named regex. If it has a group called `secret`, only that group is
    replaced (so `password=hunter2` becomes `password=[REDACTED:password]`);
    otherwise the whole match is."""

    name: str
    regex: re.Pattern[str]


_NOT_ALREADY = r"(?!\[REDACTED:)"
_KV_VALUE = rf"""{_NOT_ALREADY}(?P<secret>"[^"\n]*"|'[^'\n]*'|[^\s'",;}}]+)"""


def _kv(words: str) -> str:
    # key = value / key: value / "key": "value", with the separator on one line.
    return (
        rf"""(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*?(?:{words})[A-Za-z0-9_.-]*["']?"""
        rf"""[ \t]*[:=][ \t]*{_KV_VALUE}"""
    )


_PASSWORD_WORDS = r"password|passwd|passphrase"
_SECRET_WORDS = (
    r"secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?"
)

DEFAULT_PATTERNS: tuple[tuple[str, str, int], ...] = (
    # (name, regex, flags) — order matters: specific before generic.
    (
        "private_key",
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"
        r"(?:.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|.*\Z)",
        re.DOTALL,
    ),
    (
        "conn_string",
        r"\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s:/@'\"]+:" + _NOT_ALREADY
        + r"(?P<secret>[^\s'\"]+)@",
        0,
    ),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", 0),
    (
        "aws_access_key",
        r"\b(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|APKA)[A-Z0-9]{16}\b",
        0,
    ),
    (
        "auth_header",
        r"\b(?:proxy-)?authorization[ \t]*[:=][ \t]*"
        r"(?:(?:bearer|basic|digest|token|negotiate|ntlm|apikey)[ \t]+)?"
        + _NOT_ALREADY + r"(?P<secret>[^\s'\",;]+)",
        re.IGNORECASE,
    ),
    ("bearer_token", r"\bbearer[ \t]+" + _NOT_ALREADY + r"(?P<secret>[A-Za-z0-9._~+/-]{12,}=*)", re.IGNORECASE),
    (
        # Base64 after "Basic": requires a digit, +, /, = or a lower→upper case
        # change so that prose like "Basic configuration" is left alone.
        "basic_auth",
        r"\bbasic[ \t]+(?P<secret>(?=[A-Za-z0-9+/]*(?:[0-9+/=]|(?-i:[a-z][A-Z])))[A-Za-z0-9+/]{8,}={0,2})"
        r"(?![A-Za-z0-9+/=])",
        re.IGNORECASE,
    ),
    (
        "basic_auth",  # curl -u user:pass / --user=user:pass
        r"(?:^|[ \t])(?:-u|--user)(?:[ \t]+|=)['\"]?[^\s:'\"]+:" + _NOT_ALREADY
        + r"(?P<secret>[^\s'\"]+)",
        0,
    ),
    (
        "password",  # --password foo, -passin pass:foo (flag + separate value)
        r"(?<![A-Za-z0-9])--?(?:password|passwd|pass|passin|passout)(?:=|[ \t]+)"
        + _NOT_ALREADY + r"(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|[^\s'\"]+)",
        re.IGNORECASE,
    ),
    (
        "password",  # mysql -pSECRET
        r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]*?[ \t]-p" + _NOT_ALREADY
        + r"(?P<secret>[^\s'\"]+)",
        0,
    ),
    ("password", _kv(_PASSWORD_WORDS), re.IGNORECASE),
    (
        "secret",  # --token foo, --api-key foo
        r"(?<![A-Za-z0-9])--?(?:secret|token|api-key|apikey|access-key|secret-key)(?:=|[ \t]+)"
        + _NOT_ALREADY + r"(?P<secret>\"[^\"\n]*\"|'[^'\n]*'|[^\s'\"]+)",
        re.IGNORECASE,
    ),
    ("secret", _kv(_SECRET_WORDS), re.IGNORECASE),
)

_TOKEN_CHARS = r"A-Za-z0-9+/=_.~-"
_TOKEN_RE = re.compile(rf"(?<![{_TOKEN_CHARS}])[{_TOKEN_CHARS}]{{16,}}(?![{_TOKEN_CHARS}])")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


@dataclass(frozen=True)
class EntropySettings:
    enabled: bool = True
    min_length: int = 32
    threshold: float = 4.3
    # Long hex strings are usually hashes (sha256sum output, git commits), which
    # an investigator needs to see. Set True to redact them as well.
    redact_hex: bool = False

    def is_secret(self, s: str) -> bool:
        if len(s) < self.min_length:
            return False
        if not self.redact_hex and _HEX_RE.fullmatch(s.replace("-", "")):
            return False
        classes = sum(
            bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]")
        )
        if classes < 2:
            return False
        return shannon_entropy(s) >= self.threshold


def redact_high_entropy(text: str, settings: EntropySettings) -> tuple[str, int]:
    """Redact long high-entropy tokens. A token that looks like a path (leading
    /, ./, ~/) is judged segment by segment so ordinary paths survive."""
    if not settings.enabled:
        return text, 0
    count = 0
    tag = redaction_tag("high_entropy")

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        tok = m.group()
        if tok.startswith(("/", "./", "~/", "../")):
            parts = tok.split("/")
            out = []
            for p in parts:
                if settings.is_secret(p):
                    count += 1
                    out.append(tag)
                else:
                    out.append(p)
            return "/".join(out)
        if settings.is_secret(tok):
            count += 1
            return tag
        return tok

    return _TOKEN_RE.sub(repl, text), count


def compile_patterns(
    extra: Sequence[Mapping[str, str]] = (), disable: Iterable[str] = ()
) -> list[RedactionPattern]:
    """Default patterns minus `disable`, plus user patterns from config
    (`{"name": ..., "regex": ...}`; optional `"flags": "i"`)."""
    disabled = set(disable)
    out = [
        RedactionPattern(name, re.compile(rx, flags))
        for name, rx, flags in DEFAULT_PATTERNS
        if name not in disabled
    ]
    for p in extra:
        name = str(p["name"])
        if not re.fullmatch(r"[a-z0-9_]{1,40}", name):
            raise ValueError(f"redaction pattern name must match [a-z0-9_]+: {name!r}")
        flags = re.IGNORECASE if "i" in str(p.get("flags", "")) else 0
        out.append(RedactionPattern(name, re.compile(str(p["regex"]), flags)))
    return out


def redact(
    text: str, patterns: Sequence[RedactionPattern], entropy: EntropySettings
) -> tuple[str, Counter[str]]:
    counts: Counter[str] = Counter()
    for p in patterns:
        tag = redaction_tag(p.name)

        def repl(m: re.Match[str], tag: str = tag, name: str = p.name) -> str:
            counts[name] += 1
            if "secret" in m.re.groupindex and m.group("secret") is not None:
                start = m.start("secret") - m.start()
                end = m.end("secret") - m.start()
                whole = m.group()
                return whole[:start] + tag + whole[end:]
            return tag

        text = p.regex.sub(repl, text)
    text, n = redact_high_entropy(text, entropy)
    if n:
        counts["high_entropy"] += n
    return text, counts


# --------------------------------------------------------------------------- 4. truncate

_MARKER = "\n[… {lines} lines / {chars} chars truncated …]\n"


@dataclass(frozen=True)
class Truncation:
    lines: int
    chars: int


def truncate(text: str, cap: int) -> tuple[str, Truncation | None]:
    """Keep the head and tail of `text` so the result is at most `cap` chars.
    Cuts snap to line boundaries when one is reasonably close."""
    if len(text) <= cap:
        return text, None
    # Upper bound on marker length: counts can't exceed len(text).
    reserve = len(_MARKER.format(lines=len(text), chars=len(text)))
    budget = cap - reserve
    if budget <= 0:
        return text[:cap], Truncation(text.count("\n", cap), len(text) - cap)
    head_n = budget // 2
    tail_n = budget - head_n
    head = text[:head_n]
    tail = text[len(text) - tail_n :] if tail_n else ""
    nl = head.rfind("\n")
    if nl >= head_n // 2:
        head = head[: nl + 1]
    nl = tail.find("\n")
    if 0 <= nl <= tail_n // 2:
        tail = tail[nl + 1 :]
    middle = text[len(head) : len(text) - len(tail)]
    info = Truncation(lines=middle.count("\n"), chars=len(middle))
    marker = _MARKER.format(lines=info.lines, chars=info.chars)
    if head.endswith("\n"):
        marker = marker[1:]
    return head + marker + tail, info


# --------------------------------------------------------------------------- 5. wrap

_DELIM_RE = re.compile(r"<(?=\s*/?\s*terminal_output)", re.IGNORECASE)


def wrap(text: str, source: str) -> str:
    """Wrap untrusted text in delimiters. Any `<terminal_output` / `</terminal_output`
    inside the text is neutralised so the content can't close the block early."""
    if source not in SOURCES:
        raise ValueError(f"unknown source {source!r}")
    body = _DELIM_RE.sub("&lt;", text)
    return f'<terminal_output source="{source}">\n{body}\n</terminal_output>'


# --------------------------------------------------------------------------- pipeline


@dataclass
class Prepared:
    source: str
    text: str  # wrapped; exactly what goes to the API
    body: str  # redacted and truncated, unwrapped
    original_chars: int
    redactions: Counter[str] = field(default_factory=Counter)
    truncation: Truncation | None = None

    def summary(self) -> str:
        parts = [f"{len(self.body)} chars (from {self.original_chars})"]
        if self.redactions:
            parts.append(
                "redacted " + ", ".join(f"{k}×{v}" for k, v in sorted(self.redactions.items()))
            )
        else:
            parts.append("no redactions")
        if self.truncation:
            parts.append(
                f"truncated {self.truncation.lines} lines / {self.truncation.chars} chars"
            )
        return "; ".join(parts)


@dataclass
class Pipeline:
    patterns: list[RedactionPattern]
    entropy: EntropySettings
    max_chars: int = 20_000

    @classmethod
    def default(cls, max_chars: int = 20_000) -> "Pipeline":
        return cls(compile_patterns(), EntropySettings(), max_chars)

    def prepare(self, raw: str, source: str, session_secrets: Iterable[str] = ()) -> Prepared:
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}")
        text = strip(raw)
        text, n_secret = redact_session_secrets(text, session_secrets)
        text, counts = redact(text, self.patterns, self.entropy)
        if n_secret:
            counts["session_secret"] += n_secret
        text, trunc = truncate(text, self.max_chars)
        return Prepared(
            source=source,
            text=wrap(text, source),
            body=text,
            original_chars=len(raw),
            redactions=counts,
            truncation=trunc,
        )
