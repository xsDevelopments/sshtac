"""Local command policy, independent of the model.

Every proposed command is classified here and the stricter of this verdict and
the model's own label wins:

    READ_ONLY < MUTATING < DESTRUCTIVE < BLOCKED

Two layers, strictest wins:

1. Structural: a small shell lexer (quotes, escapes, ANSI-C $'..', line
   continuations, $IFS, brace lists) splits the command into pipelines and
   simple commands; command and process substitutions are extracted and
   classified recursively; wrappers (sudo, env, nice, timeout, xargs, sh -c,
   ssh host cmd, ...) are unwrapped; each command is judged by name, flags,
   targets and redirections.
2. Backstop regexes over a token skeleton (dequoted words, ops kept) catch the
   blocked patterns even if the structural pass misses a trick. A word's own
   spaces are hidden from the backstop so that `grep "history -c" file`
   (investigating, not doing) isn't blocked.

Unknown means MUTATING. Anything we can't parse is MUTATING at least.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterable, Sequence


class Risk(IntEnum):
    READ_ONLY = 0
    MUTATING = 1
    DESTRUCTIVE = 2
    BLOCKED = 3

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def from_label(cls, label: str) -> "Risk":
        try:
            return cls[label.upper()]
        except KeyError:
            return cls.MUTATING


@dataclass
class Verdict:
    risk: Risk = Risk.READ_ONLY
    reasons: list[str] = field(default_factory=list)  # all of them, for the audit log
    levels: dict[str, Risk] = field(default_factory=dict)

    def raise_to(self, risk: Risk, reason: str) -> None:
        reason = reason.replace(SUBST, "$(…)")
        if risk > Risk.READ_ONLY:
            if reason not in self.reasons:
                self.reasons.append(reason)
            self.levels[reason] = max(risk, self.levels.get(reason, Risk.READ_ONLY))
        if risk > self.risk:
            self.risk = risk

    def merge(self, other: "Verdict") -> None:
        for r in other.reasons:
            self.raise_to(other.levels.get(r, Risk.MUTATING), r)
        if other.risk > self.risk:
            self.risk = other.risk

    @property
    def top_reasons(self) -> list[str]:
        """The reasons that set the verdict's level: what to show a human."""
        return [r for r in self.reasons if self.levels.get(r) == self.risk]


def effective(model_label: str, local: Risk) -> Risk:
    return max(Risk.from_label(model_label), local)


# --------------------------------------------------------------------------- lexer


class ParseError(ValueError):
    pass


SUBST = "\x00SUBST\x00"  # stands in for a $(...), `...` or <(...) in a word
SEP_OPS = {";", "&&", "||", "&", "|", "|&", "(", ")", "\n"}
REDIR_RE = re.compile(r"&>>|&>|>>|>\||>&|<<<|<<-|<<|<&|<>|>|<")


@dataclass
class Word:
    text: str  # dequoted
    expanded: bool = False  # contains $var / ${..} / substitution / glob
    quoted: bool = False


@dataclass
class Tok:
    kind: str  # "word" | "op" | "redir"
    value: str
    word: Word | None = None


def extract_substitutions(s: str) -> tuple[str, list[str]]:
    """Replace $(...), `...`, <(...), >(...) with SUBST, returning their
    contents. $((...)) arithmetic is replaced with 0. Single-quoted text is
    left alone; double-quoted text is searched (substitution happens there)."""
    out: list[str] = []
    inner: list[str] = []
    i, n = 0, len(s)
    in_single = in_double = False

    def match_paren(j: int) -> int:
        depth, k, sq, dq = 1, j, False, False
        while k < n:
            c = s[k]
            if c == "\\" and not sq:
                k += 2
                continue
            if c == "'" and not dq:
                sq = not sq
            elif c == '"' and not sq:
                dq = not dq
            elif not sq and not dq:
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        return k
            k += 1
        raise ParseError("unbalanced parenthesis")

    while i < n:
        c = s[i]
        if c == "\\" and not in_single:
            out.append(s[i : i + 2])
            i += 2
            continue
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif not in_single:
            if s.startswith("$((", i):
                end = match_paren(i + 3)
                if end + 1 < n and s[end + 1] == ")":
                    out.append("0")
                    i = end + 2
                    continue
            if s.startswith("$(", i) or (not in_double and s.startswith(("<(", ">("), i)):
                end = match_paren(i + 2)
                inner.append(s[i + 2 : end])
                out.append(SUBST)
                i = end + 1
                continue
            if c == "`":
                end = i + 1
                while end < n and s[end] != "`":
                    end += 2 if s[end] == "\\" else 1
                if end >= n:
                    raise ParseError("unbalanced backtick")
                inner.append(s[i + 1 : end].replace("\\`", "`"))
                out.append(SUBST)
                i = end + 1
                continue
        out.append(c)
        i += 1
    if in_single or in_double:
        raise ParseError("unbalanced quote")
    return "".join(out), inner


_ANSI_C = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b",
           "f": "\f", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(s: str, i: int) -> tuple[str, int]:
    """Decode $'...' starting after the opening quote; return (text, index after)."""
    out = []
    while i < len(s):
        c = s[i]
        if c == "'":
            return "".join(out), i + 1
        if c == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt in _ANSI_C:
                out.append(_ANSI_C[nxt])
                i += 2
                continue
            m = re.match(r"x([0-9a-fA-F]{1,2})|([0-7]{1,3})|u([0-9a-fA-F]{1,4})|U([0-9a-fA-F]{1,8})", s[i + 1 :])
            if m:
                h = m.group(1) or m.group(3) or m.group(4)
                out.append(chr(int(h, 16)) if h else chr(int(m.group(2), 8)))
                i += 1 + m.end()
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    raise ParseError("unbalanced $'")


def lex(s: str) -> list[Tok]:
    """Tokenise one command line (substitutions already extracted)."""
    s = s.replace("\\\n", "")  # line continuations
    toks: list[Tok] = []
    cur: list[str] = []
    cur_word = Word("")
    started = False
    i, n = 0, len(s)

    def flush() -> None:
        nonlocal cur, cur_word, started
        if started:
            cur_word.text = "".join(cur)
            if SUBST in cur_word.text:
                cur_word.expanded = True
            toks.append(Tok("word", cur_word.text, cur_word))
        cur, cur_word, started = [], Word(""), False

    while i < n:
        c = s[i]
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "#" and not started:
            while i < n and s[i] != "\n":
                i += 1
            continue
        if c == "\\":
            if i + 1 < n:
                cur.append(s[i + 1])
                started = True
            i += 2
            continue
        if c == "'":
            end = s.find("'", i + 1)
            if end < 0:
                raise ParseError("unbalanced quote")
            cur.append(s[i + 1 : end])
            cur_word.quoted = started = True
            i = end + 1
            continue
        if c == "$" and s.startswith("$'", i):
            text, i = _ansi_c(s, i + 2)
            cur.append(text)
            cur_word.quoted = started = True
            continue
        if c == '"' or (c == "$" and s.startswith('$"', i)):
            i += 2 if c == "$" else 1
            while i < n and s[i] != '"':
                if s[i] == "\\" and i + 1 < n and s[i + 1] in '"\\$`\n':
                    cur.append(s[i + 1])
                    i += 2
                    continue
                if s[i] == "$":
                    cur_word.expanded = True
                cur.append(s[i])
                i += 1
            if i >= n:
                raise ParseError("unbalanced quote")
            cur_word.quoted = started = True
            i += 1
            continue
        if c == "$":
            m = re.match(r"\$(\{IFS\}|IFS(?![A-Za-z0-9_]))", s[i:])
            if m:  # $IFS / ${IFS} used as a separator
                flush()
                i += m.end()
                continue
            if s.startswith("${", i):
                depth, j = 0, i + 1
                while j < n:
                    if s[j] == "\\":
                        j += 2
                        continue
                    if s[j] == "{":
                        depth += 1
                    elif s[j] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                    j += 1
                if j >= n:
                    raise ParseError("unbalanced ${")
                cur.append(s[i : j + 1])
                cur_word.expanded = started = True
                i = j + 1
                continue
            cur_word.expanded = True
            cur.append(c)
            started = True
            i += 1
            continue
        if c in "*?[":
            cur_word.expanded = True
        if c in "<>" or s.startswith("&>", i):
            if started and not cur_word.quoted and "".join(cur).isdigit():
                cur, cur_word, started = [], Word(""), False  # fd number: 2>file
            flush()
            m = REDIR_RE.match(s, i)
            assert m
            toks.append(Tok("redir", m.group()))
            i = m.end()
            continue
        if s.startswith(("&&", "||", "|&"), i):
            flush()
            toks.append(Tok("op", s[i : i + 2]))
            i += 2
            continue
        if c in ";&|()\n":
            flush()
            toks.append(Tok("op", c))
            i += 1
            continue
        cur.append(c)
        started = True
        i += 1
    flush()
    return _expand_braces(toks)


def _expand_braces(toks: list[Tok]) -> list[Tok]:
    """{rm,-rf,/} -> rm -rf / (simple, unquoted brace lists only)."""
    out: list[Tok] = []
    for t in toks:
        if t.kind == "word" and t.word and not t.word.quoted:
            m = re.fullmatch(r"\{([^{}]*,[^{}]*)\}", t.value)
            if m:
                out.extend(Tok("word", p, Word(p)) for p in m.group(1).split(","))
                continue
        out.append(t)
    return out


# --------------------------------------------------------------------------- structure


@dataclass
class Simple:
    words: list[Word]
    redirs: list[tuple[str, Word | None]]


def pipelines(toks: list[Tok]) -> list[list[Simple]]:
    """Split into pipelines of simple commands. Braces and subshell parens
    are separators; `|` / `|&` join commands into one pipeline."""
    result: list[list[Simple]] = []
    pipe: list[Simple] = []
    cur = Simple([], [])
    i = 0

    def end_cmd() -> None:
        nonlocal cur
        if cur.words or cur.redirs:
            pipe.append(cur)
        cur = Simple([], [])

    def end_pipe() -> None:
        nonlocal pipe
        end_cmd()
        if pipe:
            result.append(pipe)
        pipe = []

    while i < len(toks):
        t = toks[i]
        if t.kind == "op":
            if t.value in ("|", "|&"):
                end_cmd()
            else:
                end_pipe()
        elif t.kind == "redir":
            target = toks[i + 1].word if i + 1 < len(toks) and toks[i + 1].kind == "word" else None
            cur.redirs.append((t.value, target))
            if target is not None:
                i += 1
        elif t.value in ("{", "}") and t.word and not t.word.quoted:
            end_pipe()
        else:
            cur.words.append(t.word)  # type: ignore[arg-type]
        i += 1
    end_pipe()
    return result


# --------------------------------------------------------------------------- rules

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "busybox"}
INTERPRETERS = {"python", "python2", "python3", "perl", "ruby", "node", "nodejs", "php", "lua", "tclsh", "pwsh"}
FETCHERS = {"curl", "wget", "fetch", "nc", "ncat", "socat", "aria2c", "lynx"}
PROTECTED_SERVICES = re.compile(
    r"^(auditd|rsyslog|rsyslogd|syslog|syslog-ng|systemd-journald|journald|auditd?\.service|"
    r"rsyslog\.service|syslog\.service|syslog-ng\.service|systemd-journald\.(service|socket)|"
    r"systemd-journald-audit\.socket|systemd-journald-dev-log\.socket)$"
)
LOG_DAEMONS = {"auditd", "rsyslogd", "rsyslog", "syslogd", "syslog-ng", "systemd-journald", "journald"}
BLOCK_DEV = re.compile(r"^/dev/(sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|md\d|dm-\d|mapper/|disk/|loop\d|sr\d|mem$|kmem$|port$)")
SAFE_SINKS = re.compile(r"^(/dev/null|/dev/stdout|/dev/stderr|/dev/tty|/dev/fd/\d+|&?\d|-)$")
HISTORY_FILES = {".bash_history", ".zsh_history", ".history", ".sh_history", ".ash_history",
                 "fish_history", ".mysql_history", ".psql_history", ".python_history", ".lesshst"}
HIST_VARS = {"HISTFILE", "HISTSIZE", "HISTFILESIZE", "SAVEHIST"}
SYSTEM_DIRS = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib32", "/lib64", "/opt",
               "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var", "/usr/bin", "/usr/lib",
               "/usr/sbin", "/usr/local", "/var/lib", "/var/log"}
HOME_REFS = {"~", "$HOME", "${HOME}"}

READ_ONLY = {
    "ls", "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "zgrep", "rg", "zcat",
    "bzcat", "xzcat", "zless", "ps", "ss", "netstat", "lsof", "who", "w", "last", "lastb",
    "lastlog", "stat", "df", "du", "uptime", "id", "whoami", "groups", "uname", "file", "wc",
    "cut", "tr", "strings", "hexdump", "od", "getent", "free", "vmstat", "iostat", "mpstat",
    "pstree", "pgrep", "pidof", "lsblk", "blkid", "findmnt", "dig", "nslookup", "host", "ping",
    "traceroute", "tracepath", "getfacl", "lsattr", "namei", "readlink", "realpath", "basename",
    "dirname", "which", "whereis", "type", "echo", "printf", "test", "[", "true", "false",
    "sleep", "lsmod", "modinfo", "lspci", "lsusb", "lscpu", "lsns", "tree", "column", "jq",
    "diff", "cmp", "comm", "nl", "fold", "rev", "tac", "md5sum", "sha1sum", "sha224sum",
    "sha256sum", "sha384sum", "sha512sum", "shasum", "b2sum", "cksum", "sum", "top", "htop", "ausearch",
    "aureport", "debsums", "base64", "arp", "pwd", "cd", "locale", "env", "printenv",
    "iptables-save", "ip6tables-save", "dpkg-query", "apt-cache", "nproc", "tty", "logname",
    "users", "nstat", "conntrack", "ethtool", "sestatus", "getenforce", "aa-status", "lslogins",
    "chage", "faillog", "showmount", "exportfs", "timedatectl", "hostnamectl", "loginctl",
    "tcpdump", "xxd", "read",
}
WRAPPERS_WITH_ARGS = {
    # wrapper: options that take a value
    "sudo": set("ugpCDhrtUT"), "doas": set("uC"), "nice": set("n"), "ionice": set("cnp"),
    "stdbuf": set("ioe"), "timeout": set("sk"), "chrt": set(), "taskset": set(),
    "nohup": set(), "time": set("fo"), "command": set(), "builtin": set(), "exec": set("a"),
    "unbuffer": set(), "strace": set("eopsSEuP"), "ltrace": set("eopsSn"), "xargs": set("IinPdaELs"),
    "nsenter": set("tmuinpUCrwSG"), "flock": set("wEc"), "setsid": set(), "chronic": set(),
}


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1]


def _norm_path(p: str) -> str:
    if not p.startswith("/"):
        return p
    p = re.sub(r"/+", "/", p)
    p = posixpath.normpath(p)
    return "/" if p in ("//", "") else p


def _under_dev(p: str) -> bool:
    """A path in /dev: device nodes the whole system depends on (or /dev/tcp,
    bash's network redirection). Changing anything here is destructive."""
    n = _norm_path(p)
    return n == "/dev" or n.startswith("/dev/")


def _is_history(p: str) -> bool:
    return _base(_norm_path(p).rstrip("/")) in HISTORY_FILES


def _is_log(p: str) -> bool:
    n = _norm_path(p)
    return n == "/var/log" or n.startswith(("/var/log/", "/run/log/journal"))


def _flags(args: Sequence[Word]) -> list[str]:
    out = []
    for a in args:
        if a.text == "--":
            break
        if a.text.startswith("-") and a.text != "-":
            out.append(a.text)
    return out


def _positional(args: Sequence[Word]) -> list[Word]:
    out, after = [], False
    for a in args:
        if after or not a.text.startswith("-") or a.text == "-":
            out.append(a)
        elif a.text == "--":
            after = True
    return out


def _has_short(flags: Iterable[str], letters: str) -> bool:
    return any(f.startswith("-") and not f.startswith("--") and any(ch in f[1:] for ch in letters) for f in flags)


class Classifier:
    def __init__(self, extra_blocked: Sequence[str] = (), extra_destructive: Sequence[str] = ()):
        self.extra_blocked = [re.compile(p, re.IGNORECASE) for p in extra_blocked]
        self.extra_destructive = [re.compile(p, re.IGNORECASE) for p in extra_destructive]

    # ------------------------------------------------------------------ entry

    def classify(self, command: str, _depth: int = 0) -> Verdict:
        v = Verdict()
        if _depth > 6:
            v.raise_to(Risk.DESTRUCTIVE, "too deeply nested to analyse")
            return v
        try:
            flat, inners = extract_substitutions(command)
            toks = lex(flat)
        except ParseError as e:
            v.raise_to(Risk.MUTATING, f"could not parse the command ({e})")
            self._backstop(_raw_skeleton(command), v)
            return v
        for inner in inners:
            sub = self.classify(inner, _depth + 1)
            v.merge(sub)
        self._backstop(_skeleton(toks), v)
        self._backstop_raw(command, v)
        for pipe in pipelines(toks):
            self._pipeline(pipe, v, _depth)
        return v

    # ------------------------------------------------------------------ backstop

    def _backstop(self, skeleton: str, v: Verdict) -> None:
        for name, rx in BLOCKED_PATTERNS:
            if rx.search(skeleton):
                v.raise_to(Risk.BLOCKED, f"matches blocked pattern: {name}")
        for rx in self.extra_blocked:
            if rx.search(skeleton):
                v.raise_to(Risk.BLOCKED, f"matches configured blocked pattern {rx.pattern!r}")
        for rx in self.extra_destructive:
            if rx.search(skeleton):
                v.raise_to(Risk.DESTRUCTIVE, f"matches configured destructive pattern {rx.pattern!r}")

    def _backstop_raw(self, command: str, v: Verdict) -> None:
        if FORK_BOMB.search(command):
            v.raise_to(Risk.BLOCKED, "fork bomb")

    # ------------------------------------------------------------------ pipelines

    def _pipeline(self, pipe: list[Simple], v: Verdict, depth: int) -> None:
        upstream_fetch = False
        for idx, cmd in enumerate(pipe):
            words = _strip_assignments(cmd.words, v)
            name, args = self._unwrap(words, v, depth)
            if name is not None and idx > 0:
                reads_stdin = not _positional(args) or any(a.text in ("-", "-s", "/dev/stdin") for a in args)
                if name in SHELLS and not _flag_value(args, "-c") and reads_stdin:
                    v.raise_to(Risk.BLOCKED, f"pipes data into a shell ({name})")
                if name in INTERPRETERS and upstream_fetch and reads_stdin:
                    v.raise_to(Risk.BLOCKED, f"pipes downloaded/decoded data into {name}")
            if name is not None and (name in FETCHERS or (name == "base64" and _has_decode(args))
                                     or (name == "xxd" and "-r" in _flags(args))
                                     or (name == "openssl" and "-d" in _flags(args))):
                upstream_fetch = True
            self._redirections(cmd.redirs, v)
            if name is not None:
                self._command(name, args, v, depth, pipe)

    def _unwrap(self, words: list[Word], v: Verdict, depth: int) -> tuple[str | None, list[Word]]:
        while words:
            first = words[0]
            if first.text in ("!", "time", "then", "do", "else", "elif", "if", "while", "until"):
                # `do x=1; ...`: assignments can follow a keyword too
                words = _strip_assignments(words[1:], v)
                continue
            if first.text in ("for", "case", "select", "function", "done", "fi", "esac", "in"):
                return None, []
            if first.expanded:
                v.raise_to(Risk.DESTRUCTIVE, f"command name {first.text!r} is computed at run time")
                return None, []
            name = _base(first.text)
            args = words[1:]
            if name in WRAPPERS_WITH_ARGS:
                if name == "command" and args and args[0].text in ("-v", "-V"):
                    return "type", args
                if name == "xargs" or name == "watch":
                    v.raise_to(Risk.MUTATING, f"{name} runs a command with arguments from input")
                words = _skip_options(args, WRAPPERS_WITH_ARGS[name])
                if name == "timeout" and words and re.fullmatch(r"[\d.]+[smhd]?", words[0].text):
                    words = words[1:]
                if name in ("nice",) and words and re.fullmatch(r"-?\d+", words[0].text):
                    words = words[1:]
                if name in ("chrt", "taskset") and words:
                    words = words[1:]
                if not words:
                    return name, []
                continue
            if name == "env":
                rest = _skip_options(args, set("uSC"))
                rest = _strip_assignments(rest, v)
                if not rest:
                    return "env", []
                words = rest
                continue
            if name == "watch":
                rest = _skip_options(args, set("nd"))
                v.merge(self.classify(" ".join(w.text for w in rest), depth + 1))
                return None, []
            if name == "busybox" and args:
                words = args
                continue
            return name, args
        return None, []

    # ------------------------------------------------------------------ redirections

    def _redirections(self, redirs: list[tuple[str, Word | None]], v: Verdict) -> None:
        for op, target in redirs:
            if target is None or op in ("<", "<<", "<<-", "<<<", "<&"):
                continue
            path = _norm_path(target.text)
            if op in (">&",) and re.fullmatch(r"\d+|-", target.text):
                continue
            if BLOCK_DEV.match(path):
                v.raise_to(Risk.BLOCKED, f"writes to a block device ({target.text})")
            elif SAFE_SINKS.match(target.text):
                continue
            elif _under_dev(path):
                v.raise_to(Risk.DESTRUCTIVE, f"writes to {target.text} (device or network redirect)")
            elif _is_history(path) and op in (">", ">|", "&>", "<>", ">&"):
                v.raise_to(Risk.BLOCKED, f"overwrites a shell history file ({target.text})")
            elif _is_log(path) and op in (">", ">|", "&>", "<>", ">&"):
                v.raise_to(Risk.DESTRUCTIVE, f"overwrites a log file, destroying evidence ({target.text})")
            elif op in (">", ">|", "&>", "<>", ">&"):
                v.raise_to(Risk.DESTRUCTIVE, f"redirection overwrites {target.text}")
            else:
                v.raise_to(Risk.MUTATING, f"redirection appends to {target.text}")

    # ------------------------------------------------------------------ commands

    def _command(self, name: str, args: list[Word], v: Verdict, depth: int, pipe: list[Simple]) -> None:
        flags = _flags(args)
        pos = _positional(args)
        texts = [a.text for a in args]

        if name in SHELLS:
            code = _flag_value(args, "-c")
            if code is not None:
                if code.expanded:
                    v.raise_to(Risk.BLOCKED, f"{name} -c runs computed or fetched content")
                v.merge(self.classify(code.text, depth + 1))
                return
            if any(a.expanded and SUBST in a.text or a.text.startswith("/dev/fd") for a in pos):
                v.raise_to(Risk.BLOCKED, f"{name} runs code from a substitution")
            v.raise_to(Risk.MUTATING, f"{name} runs a script" if pos else f"{name} starts a shell")
            return
        if name in ("eval",):
            if any(a.expanded for a in args):
                v.raise_to(Risk.BLOCKED, "eval of computed content")
            v.raise_to(Risk.MUTATING, "eval")
            v.merge(self.classify(" ".join(texts), depth + 1))
            return
        if name in ("source", "."):
            if any(a.expanded for a in args):
                v.raise_to(Risk.BLOCKED, f"{name} of computed content")
            v.raise_to(Risk.MUTATING, f"{name} runs a script in the current shell")
            return
        if name in INTERPRETERS:
            v.raise_to(Risk.MUTATING, f"{name} can run arbitrary code")
            return
        if name == "ssh":
            v.raise_to(Risk.MUTATING, "ssh runs a command on another host")
            from sshtac.launcher import ssh_destination

            dest = ssh_destination(texts)
            if dest is not None and dest in texts:
                remote = texts[texts.index(dest) + 1 :]
                if remote:
                    v.merge(self.classify(" ".join(remote), depth + 1))
            return
        if name in ("nc", "ncat", "netcat", "socat"):
            if _has_short(flags, "ec") or any(f.startswith(("--exec", "--sh-exec", "--lua-exec")) for f in flags) \
                    or any("exec:" in t.lower() or "system:" in t.lower() for t in texts):
                v.raise_to(Risk.BLOCKED, f"{name} wired to a shell (bind/reverse shell)")
            v.raise_to(Risk.MUTATING, f"{name} opens network connections")
            return

        if name.startswith("mkfs") or name in ("mke2fs", "wipefs", "mkswap"):
            v.raise_to(Risk.BLOCKED, f"{name} destroys a filesystem")
            return
        if name == "dd":
            outs = [t[3:] for t in texts if t.startswith("of=")]
            for o in outs:
                if BLOCK_DEV.match(_norm_path(o)):
                    v.raise_to(Risk.BLOCKED, f"dd writes to a block device ({o})")
                else:
                    v.raise_to(Risk.DESTRUCTIVE, f"dd overwrites {o}")
            return
        if name in ("rm", "unlink", "shred", "truncate", "rmdir"):
            self._rm(name, args, flags, pos, v)
            return
        if name in ("history",):
            if _has_short(flags, "cd"):
                v.raise_to(Risk.BLOCKED, "clears or edits shell history")
            elif flags:
                v.raise_to(Risk.MUTATING, "history with options")
            return
        if name in ("unset", "export", "declare", "typeset", "readonly", "local"):
            for a in args:
                var = a.text.split("=", 1)[0]
                if var in HIST_VARS:
                    v.raise_to(Risk.BLOCKED, f"tampers with shell history ({var})")
            v.raise_to(Risk.MUTATING, f"{name} changes shell variables")
            return
        if name == "set":
            if "+o" in texts and "history" in texts:
                v.raise_to(Risk.BLOCKED, "turns off shell history")
            v.raise_to(Risk.MUTATING, "set changes shell options")
            return
        if name == "ln":
            if any(_is_history(p.text) for p in pos):
                v.raise_to(Risk.BLOCKED, "links over a shell history file")
            if any(_under_dev(p.text) for p in pos[-1:]):
                v.raise_to(Risk.DESTRUCTIVE, f"ln replaces {pos[-1].text} in /dev")
            v.raise_to(Risk.MUTATING, "ln creates links")
            return
        if name in ("chmod", "chown", "chgrp", "setfacl", "chattr"):
            recursive = _has_short(flags, "R") or "--recursive" in flags
            for p in pos:
                path = _norm_path(p.text)
                if path == "/" or (recursive and (path in SYSTEM_DIRS or p.text in HOME_REFS)):
                    v.raise_to(Risk.BLOCKED, f"{name} on {p.text}{' recursively' if recursive else ''}")
                elif _under_dev(path):
                    v.raise_to(Risk.DESTRUCTIVE, f"{name} changes device node {p.text}")
            v.raise_to(Risk.MUTATING, f"{name} changes permissions or attributes")
            return
        if name in ("kill", "pkill", "killall", "skill"):
            if any(t in LOG_DAEMONS for t in texts):
                v.raise_to(Risk.BLOCKED, "kills a logging or audit daemon")
            v.raise_to(Risk.DESTRUCTIVE, f"{name} terminates processes")
            return
        if name in ("systemctl",):
            self._systemctl(pos, v)
            return
        if name == "service":
            if len(pos) >= 2:
                unit, action = pos[0].text, pos[1].text
                if action in ("status",):
                    return
                if action in ("stop",) and PROTECTED_SERVICES.match(unit):
                    v.raise_to(Risk.BLOCKED, f"stops logging/audit service {unit}")
                if action == "stop":
                    v.raise_to(Risk.DESTRUCTIVE, f"stops service {unit}")
                    return
            elif len(pos) == 1 and pos[0].text == "--status-all":
                return
            v.raise_to(Risk.MUTATING, "service changes a service")
            return
        if name in ("auditctl",):
            if "-D" in texts or any(t == "-e" for t in texts) and "0" in texts or "-e0" in texts:
                v.raise_to(Risk.BLOCKED, "disables or clears audit rules")
            if all(t in ("-l", "-s", "--list") for t in texts) and texts:
                return
            v.raise_to(Risk.MUTATING, "auditctl changes audit rules")
            return
        if name == "journalctl":
            if any(f.startswith("--vacuum") for f in flags):
                v.raise_to(Risk.DESTRUCTIVE, "journalctl --vacuum deletes logs (evidence)")
            if any(f.startswith(("--rotate", "--flush", "--relinquish-var", "--setup-keys", "--update-catalog")) for f in flags):
                v.raise_to(Risk.MUTATING, "journalctl maintenance option")
            return
        if name == "dmesg":
            if _has_short(flags, "cCDEn") or any(f in ("--clear", "--read-clear", "--console-off", "--console-on", "--console-level") for f in flags):
                if _has_short(flags, "cC") or any(f in ("--clear", "--read-clear") for f in flags):
                    v.raise_to(Risk.DESTRUCTIVE, "dmesg clears the kernel log (evidence)")
                v.raise_to(Risk.MUTATING, "dmesg console settings")
            return
        if name in ("reboot", "shutdown", "poweroff", "halt"):
            v.raise_to(Risk.DESTRUCTIVE, f"{name} takes the host down")
            return
        if name in ("init", "telinit") and any(t in ("0", "6") for t in texts):
            v.raise_to(Risk.DESTRUCTIVE, f"{name} changes runlevel")
            return
        if name in ("userdel", "deluser", "groupdel", "delgroup", "passwd", "chpasswd", "usermod", "gpasswd", "vipw"):
            v.raise_to(Risk.DESTRUCTIVE, f"{name} changes accounts or passwords")
            return
        if name in ("crontab",):
            if "-r" in flags:
                v.raise_to(Risk.DESTRUCTIVE, "crontab -r deletes the crontab")
            elif flags != ["-l"] and not (len(flags) == 2 and "-l" in flags and "-u" in flags):
                v.raise_to(Risk.MUTATING, "crontab changes scheduled jobs")
            return
        if name in ("iptables", "ip6tables", "iptables-legacy", "iptables-nft", "ip6tables-legacy", "ip6tables-nft", "ebtables", "arptables"):
            # Decide by command, not by guessing at the other words: chain
            # names can be anything (ufw's are lowercase, e.g. ufw-user-input).
            change = _iptables_mode(texts)
            if change == "list":
                return
            if change == "zero":
                v.raise_to(Risk.DESTRUCTIVE, f"{name} -Z resets packet counters (evidence)")
                return
            v.raise_to(Risk.DESTRUCTIVE, f"{name} changes firewall rules")
            return
        if name == "sshd":
            if _has_short(flags, "Tt") and not _has_short(flags, "D"):
                return  # -T prints the effective config, -t tests it
            v.raise_to(Risk.MUTATING, "sshd starts an SSH daemon")
            return
        if name == "nginx":
            sig = _flag_value(args, "-s")
            if sig is not None:
                v.raise_to(Risk.DESTRUCTIVE if sig.text in ("stop", "quit") else Risk.MUTATING, f"nginx -s {sig.text}")
                return
            if flags and all(f in ("-t", "-T", "-v", "-V", "-q") or re.fullmatch(r"-[tTvVq]+", f) for f in flags):
                return
            v.raise_to(Risk.MUTATING, "nginx starts or changes the server")
            return
        if name in ("apachectl", "apache2ctl", "httpd", "apache2"):
            words = [t.text for t in pos]
            if any(w in ("stop", "graceful-stop") for w in words):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} stops the web server")
                return
            if (flags and all(re.fullmatch(r"-[tSMlLvV]+", f) for f in flags) and not words) or words in (["configtest"], ["-t"]) \
                    or (words and words[0] in ("configtest", "status", "fullstatus") and not flags):
                return
            v.raise_to(Risk.MUTATING, f"{name} starts or changes the web server")
            return
        if name == "postconf":
            if _has_short(flags, "eX#") or any("=" in p.text for p in pos):
                v.raise_to(Risk.MUTATING, "postconf edits Postfix configuration")
            return
        if name in ("doveconf", "mailq", "dovecot-sysreport"):
            return
        if name == "postqueue":
            if flags and all(f in ("-p", "-j") for f in flags):
                return
            v.raise_to(Risk.MUTATING, "postqueue flushes or changes the mail queue")
            return
        if name == "postsuper":
            if _has_short(flags, "dD"):
                v.raise_to(Risk.DESTRUCTIVE, "postsuper deletes queued mail")
                return
            v.raise_to(Risk.MUTATING, "postsuper changes the mail queue")
            return
        if name in ("iptables-restore", "ip6tables-restore", "nft", "ufw", "firewall-cmd"):
            if name == "nft" and pos and pos[0].text in ("list",):
                return
            if name == "ufw" and pos and pos[0].text in ("status", "show") or (name == "ufw" and texts[:2] == ["app", "list"]):
                return
            if name == "firewall-cmd" and flags and all(f.startswith(("--list", "--get", "--query", "--state", "--zone", "--permanent")) for f in flags) \
                    and any(f.startswith(("--list", "--get", "--query", "--state")) for f in flags):
                return
            v.raise_to(Risk.DESTRUCTIVE, f"{name} changes firewall rules")
            return
        if name in ("fdisk", "sfdisk", "gdisk", "sgdisk", "parted", "cfdisk"):
            if flags and all(f in ("-l", "--list", "-p", "--print", "-s") for f in flags) and name != "cfdisk":
                return
            v.raise_to(Risk.DESTRUCTIVE, f"{name} edits partition tables")
            return
        if name == "sed":
            if any(f == "-i" or f.startswith(("-i", "--in-place")) or (f.startswith("-") and not f.startswith("--") and "i" in f[1:]) for f in flags) \
                    or _has_short(flags, "f") or any(f.startswith("--file") for f in flags):
                v.raise_to(Risk.MUTATING, "sed edits files or runs a script file")
                return
            scripts = [a.text for i, a in enumerate(args) if i > 0 and args[i - 1].text in ("-e", "--expression")]
            if not scripts and pos:
                scripts = [pos[0].text]
            if scripts and all(_sed_safe(sc) for sc in scripts):
                return
            v.raise_to(Risk.MUTATING, "sed script may write files or run commands")
            return
        if name in ("awk", "gawk", "mawk", "nawk"):
            prog = _awk_program(args)
            if prog is not None and not re.search(r"\bsystem\b|\bgetline\b|[>|]", prog):
                return
            v.raise_to(Risk.MUTATING, f"{name} program may write files or run commands")
            return
        if name == "ssh-keygen":
            if _has_short(flags, "lF") and not _has_short(flags, "R"):
                return  # -l shows fingerprints, -F searches known_hosts
            v.raise_to(Risk.MUTATING, "ssh-keygen creates or changes keys")
            return
        if name == "certbot":
            sub = pos[0].text if pos else ""
            if sub == "certificates" or flags in (["--version"], ["-h"], ["--help"]):
                return
            if sub in ("delete", "revoke"):
                v.raise_to(Risk.DESTRUCTIVE, f"certbot {sub} removes certificates")
                return
            v.raise_to(Risk.MUTATING, f"certbot {sub} changes certificates")
            return
        if name == "resolvectl":
            if not pos or pos[0].text in ("status", "query", "statistics", "show-cache", "show-server-state"):
                return
            v.raise_to(Risk.MUTATING, "resolvectl changes DNS settings")
            return
        if name == "cloud-init":
            if pos and pos[0].text in ("status", "query", "analyze") or flags == ["--version"]:
                return
            v.raise_to(Risk.MUTATING, "cloud-init changes the system")
            return
        if name == "postfix":
            sub = pos[0].text if pos else ""
            if sub in ("check", "status"):
                return
            if sub in ("stop", "abort"):
                v.raise_to(Risk.DESTRUCTIVE, f"postfix {sub} stops mail delivery")
                return
            v.raise_to(Risk.MUTATING, f"postfix {sub} changes the mail system")
            return
        if name in ("mknod", "mkfifo"):
            if name == "mknod" or any(_under_dev(p.text) for p in pos):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} creates a device or special file")
            else:
                v.raise_to(Risk.MUTATING, f"{name} creates a special file")
            return
        if name in ("tee",):
            for p in pos:
                path = _norm_path(p.text)
                if BLOCK_DEV.match(path):
                    v.raise_to(Risk.BLOCKED, f"tee writes to a block device ({p.text})")
                elif SAFE_SINKS.match(p.text):
                    continue
                elif _under_dev(path):
                    v.raise_to(Risk.DESTRUCTIVE, f"tee writes to {p.text}")
                elif _is_history(path) and not _has_short(flags, "a"):
                    v.raise_to(Risk.BLOCKED, f"tee overwrites a shell history file ({p.text})")
                elif _has_short(flags, "a") or "--append" in flags:
                    v.raise_to(Risk.MUTATING, f"tee appends to {p.text}")
                else:
                    v.raise_to(Risk.DESTRUCTIVE, f"tee overwrites {p.text}")
            return
        if name in ("cp", "mv", "install", "rsync", "scp"):
            if any(BLOCK_DEV.match(_norm_path(p.text)) for p in pos):
                v.raise_to(Risk.BLOCKED, f"{name} writes to a block device")
            if name == "mv" and any(_is_history(p.text) for p in pos[:-1]):
                v.raise_to(Risk.BLOCKED, "moves away a shell history file")
            # mv takes its sources away too; cp & co. only write the destination.
            touched = pos if name == "mv" else pos[-1:]
            for p in touched:
                if _under_dev(p.text) and not SAFE_SINKS.match(p.text):
                    v.raise_to(Risk.DESTRUCTIVE, f"{name} changes {p.text} in /dev")
                elif name == "mv" and _norm_path(p.text) == "/dev/null":
                    v.raise_to(Risk.DESTRUCTIVE, "mv replaces or moves /dev/null")
            if name == "rsync" and "--delete" in " ".join(flags):
                v.raise_to(Risk.DESTRUCTIVE, "rsync --delete removes files")
            v.raise_to(Risk.MUTATING, f"{name} writes files")
            return
        if name == "find":
            self._find(args, v, depth)
            return
        if name in ("mysql", "mariadb", "psql", "sqlite3", "mongo", "mongosh", "clickhouse-client", "cqlsh", "redis-cli", "sqlplus"):
            text = " ".join(w.text for c in pipe for w in c.words)
            if re.search(r"\b(drop|delete|truncate)\b", text, re.IGNORECASE) or (
                name == "redis-cli" and re.search(r"\b(flushall|flushdb|del|unlink)\b", text, re.IGNORECASE)):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} statement deletes data")
                return
            sql = _sql_text(name, args)
            if sql is not None and len(pipe) == 1 and _sql_read_only(sql):
                return
            v.raise_to(Risk.MUTATING, f"{name} may change data")
            return
        if name in ("apt", "apt-get", "aptitude", "yum", "dnf", "zypper", "apk", "snap", "pip", "pip3", "pipx", "npm", "gem", "brew", "flatpak"):
            sub = pos[0].text if pos else ""
            if name in ("apt", "apt-get", "aptitude") and any(
                f in ("-s", "--simulate", "--dry-run", "--just-print", "--no-act", "--recon") for f in flags
            ):
                return  # simulation only prints what would happen
            if sub in ("remove", "purge", "autoremove", "erase", "uninstall", "del", "rm"):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} {sub} removes packages")
            elif sub in ("list", "show", "policy", "search", "info", "repolist", "check-update", "freeze", "depends", "rdepends", "madison"):
                return
            else:
                v.raise_to(Risk.MUTATING, f"{name} {sub} changes packages")
            return
        if name == "pacman":
            if flags and flags[0].startswith("-Q"):
                return
            if flags and flags[0].startswith("-R"):
                v.raise_to(Risk.DESTRUCTIVE, "pacman -R removes packages")
                return
            v.raise_to(Risk.MUTATING, "pacman changes packages")
            return
        if name == "dpkg":
            if any(f in ("-r", "-P", "--remove", "--purge") for f in flags):
                v.raise_to(Risk.DESTRUCTIVE, "dpkg removes packages")
            elif flags and all(f in ("-l", "-L", "-S", "-s", "-p", "-c", "-I", "-V", "--list", "--listfiles", "--search", "--status", "--print-avail", "--contents", "--info", "--verify", "--get-selections", "--audit", "-C") for f in flags):
                return
            else:
                v.raise_to(Risk.MUTATING, "dpkg changes packages")
            return
        if name == "rpm":
            if any(f in ("-e", "--erase") for f in flags):
                v.raise_to(Risk.DESTRUCTIVE, "rpm -e removes packages")
            elif flags and (flags[0].startswith("-q") or flags[0] in ("-V", "--verify", "--query", "-K", "--checksig")):
                return
            else:
                v.raise_to(Risk.MUTATING, "rpm changes packages")
            return
        if name in ("docker", "podman", "nerdctl", "crictl", "kubectl"):
            sub = " ".join(t.text for t in pos[:2])
            first = pos[0].text if pos else ""
            if first in ("ps", "images", "inspect", "logs", "top", "stats", "version", "info", "get", "describe", "explain", "api-resources") or sub in ("container ls", "image ls", "config view"):
                return
            if first in ("rm", "rmi", "kill", "stop", "delete", "drain", "prune") or "prune" in sub or sub.endswith(" rm"):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} {sub} removes or stops things")
                return
            v.raise_to(Risk.MUTATING, f"{name} {sub} changes state")
            return
        if name == "ip":
            p = [t.text for t in pos]
            if len(p) <= 1 or p[1] in ("show", "list", "ls", "lst", "sh", "get", "s"):
                return
            v.raise_to(Risk.MUTATING, "ip changes network configuration")
            return
        if name == "ifconfig":
            if len(pos) <= 1:
                return
            v.raise_to(Risk.MUTATING, "ifconfig changes an interface")
            return
        if name == "route":
            if not pos:
                return
            v.raise_to(Risk.MUTATING, "route changes routing")
            return
        if name == "mount":
            if not pos:
                return
            v.raise_to(Risk.MUTATING, "mount changes mounts")
            return
        if name == "date":
            if any(f in ("-s", "--set") or f.startswith("--set=") for f in flags) or any(not p.text.startswith("+") for p in pos):
                v.raise_to(Risk.MUTATING, "date sets the clock")
            return
        if name == "hostname":
            if pos:
                v.raise_to(Risk.MUTATING, "hostname sets the host name")
            return
        if name == "sort":
            if "-o" in flags or any(f.startswith("--output") for f in flags):
                v.raise_to(Risk.MUTATING, "sort writes a file")
            return
        if name == "uniq":
            if len(pos) > 1:
                v.raise_to(Risk.MUTATING, "uniq writes a file")
            return
        if name == "xxd":
            if len(pos) > 1:
                v.raise_to(Risk.MUTATING, "xxd writes a file")
            return
        if name == "tcpdump":
            if "-w" in flags:
                v.raise_to(Risk.MUTATING, "tcpdump writes a capture file")
            return
        if name in ("setenforce",):
            v.raise_to(Risk.DESTRUCTIVE, "changes SELinux enforcement")
            return
        if name in READ_ONLY:
            return
        v.raise_to(Risk.MUTATING, f"{name} is not on the read-only list")

    def _rm(self, name: str, args: list[Word], flags: list[str], pos: list[Word], v: Verdict) -> None:
        recursive = name == "rm" and (_has_short(flags, "rR") or "--recursive" in flags)
        if "--no-preserve-root" in flags:
            v.raise_to(Risk.BLOCKED, "rm --no-preserve-root")
        for p in pos:
            path = _norm_path(p.text)
            if _is_history(p.text):
                v.raise_to(Risk.BLOCKED, f"{name} destroys a shell history file ({p.text})")
            elif _is_log(p.text):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} deletes logs, destroying evidence ({p.text})")
            elif _under_dev(p.text):
                v.raise_to(Risk.DESTRUCTIVE, f"{name} removes {p.text} from /dev")
            if recursive:
                stripped = re.sub(r"/\*$", "", path) or "/"
                if path in ("/", "/*") or stripped in SYSTEM_DIRS or p.text.rstrip("/*") in HOME_REFS or p.text in ("~/", "~/*"):
                    v.raise_to(Risk.BLOCKED, f"recursive {name} of {p.text}")
            if name in ("shred", "truncate") and BLOCK_DEV.match(path):
                v.raise_to(Risk.BLOCKED, f"{name} on a block device")
        v.raise_to(Risk.DESTRUCTIVE, f"{name} deletes data")

    def _systemctl(self, pos: list[Word], v: Verdict) -> None:
        p = [w.text for w in pos]
        if not p:
            return
        verb, units = p[0], p[1:]
        read_only = {"status", "show", "cat", "help", "is-active", "is-enabled", "is-failed", "is-system-running",
                     "list-units", "list-unit-files", "list-sockets", "list-timers", "list-jobs",
                     "list-dependencies", "list-machines", "show-environment", "get-default"}
        if verb in read_only:
            return
        if verb in ("stop", "disable", "mask", "kill", "freeze") and any(PROTECTED_SERVICES.match(u) for u in units):
            v.raise_to(Risk.BLOCKED, f"systemctl {verb} on a logging/audit service")
        if verb in ("stop", "disable", "mask", "kill", "reboot", "poweroff", "halt", "isolate", "emergency", "rescue", "kexec", "freeze"):
            v.raise_to(Risk.DESTRUCTIVE, f"systemctl {verb}")
            return
        v.raise_to(Risk.MUTATING, f"systemctl {verb} changes service state")

    def _find(self, args: list[Word], v: Verdict, depth: int) -> None:
        texts = [a.text for a in args]
        if "-delete" in texts:
            v.raise_to(Risk.DESTRUCTIVE, "find -delete removes files")
        for f in ("-fprint", "-fprint0", "-fprintf", "-fls"):
            if f in texts:
                v.raise_to(Risk.MUTATING, f"find {f} writes a file")
        i = 0
        while i < len(texts):
            if texts[i] in ("-exec", "-execdir", "-ok", "-okdir"):
                j = i + 1
                while j < len(texts) and texts[j] not in (";", "+"):
                    j += 1
                # {} stands for whatever find matches, which can include its
                # start paths: judge the inner command against each of them.
                starts = []
                for t in texts:
                    if t.startswith(("-", "(", "!")):
                        break
                    starts.append(t)
                for start in starts or ["."]:
                    inner = [start if t == "{}" else t for t in texts[i + 1 : j]]
                    if inner:
                        v.merge(self.classify(" ".join(_shell_quote(t) for t in inner), depth + 1))
                i = j
            i += 1


_SED_ADDR = r"(?:\d+|\$|/(?:\\.|[^/\\])*/)"
_SED_PRINT = re.compile(rf"^(?:{_SED_ADDR}(?:,{_SED_ADDR})?)?\s*!?\s*[pdq=]?$")
_SED_SUBST = re.compile(rf"^(?:{_SED_ADDR}(?:,{_SED_ADDR})?\s*)?s(.)((?:\\.|(?!\1).)*)\1((?:\\.|(?!\1).)*)\1([gpiImM0-9]*)$")


def _sed_safe(script: str) -> bool:
    """Only print/delete-from-output/quit commands and substitutions without
    the w (write file) or e (execute) flags."""
    parts = [p.strip() for p in re.split(r"[;\n]", script) if p.strip()]
    return bool(parts) and all(_SED_PRINT.match(p) or _SED_SUBST.match(p) for p in parts)


def _awk_program(args: Sequence[Word]) -> str | None:
    """The inline awk program, or None if it comes from a file or can't be found."""
    i = 0
    while i < len(args):
        t = args[i].text
        if t in ("-f", "--file") or t.startswith(("-f", "--file=", "-i", "--include", "-E", "--exec")):
            return None
        if t in ("-F", "-v", "--assign", "--field-separator"):
            i += 2
            continue
        if t.startswith(("-F", "-v")) or t == "--":
            i += 1
            continue
        if t.startswith("-"):
            i += 1
            continue
        return t
    return None


_SQL_CLIENT_FLAG = {"mysql": "-e", "mariadb": "-e", "clickhouse-client": "-q", "psql": "-c"}


def _sql_text(name: str, args: Sequence[Word]) -> str | None:
    short = _SQL_CLIENT_FLAG.get(name)
    if short is None:
        return None
    for i, a in enumerate(args):
        t = a.text
        if t in (short, "--execute", "--command", "--query") and i + 1 < len(args):
            return args[i + 1].text
        for long in ("--execute=", "--command=", "--query="):
            if t.startswith(long):
                return t[len(long):]
        if t.startswith(short) and len(t) > 2 and not t.startswith("--"):
            return t[2:]
    return None


def _sql_read_only(sql: str) -> bool:
    stmts = [s.strip() for s in sql.split(";") if s.strip()]
    if not stmts or re.search(r"\binto\s+(out|dump)file\b|\bfor\s+update\b", sql, re.IGNORECASE):
        return False
    return all(re.match(r"(?i)(select|show|describe|desc|explain)\b", s) for s in stmts)


_IPT_CHANGE_LONG = {"--append", "--delete", "--insert", "--replace", "--flush", "--new-chain",
                    "--delete-chain", "--policy", "--rename-chain"}
_IPT_LIST_LONG = {"--list", "--list-rules", "--check"}
_IPT_VALUE_SHORT = set("tw")  # -t TABLE, -w [SECONDS]


def _iptables_mode(texts: Sequence[str]) -> str:
    """"list" (only -L/-S/-C), "zero" (-Z), or "change" (anything else,
    including no command at all)."""
    commands: set[str] = set()
    i = 0
    while i < len(texts):
        t = texts[i]
        if t.startswith("--"):
            opt = t.split("=", 1)[0]
            if opt in _IPT_CHANGE_LONG:
                commands.add("change")
            elif opt in _IPT_LIST_LONG:
                commands.add("list")
            elif opt == "--zero":
                commands.add("zero")
            elif opt == "--table" and "=" not in t:
                i += 1
        elif t.startswith("-") and len(t) > 1:
            letters = t[1:]
            for ch in letters:
                if ch in "ADIRFNXPE":
                    commands.add("change")
                elif ch in "LSC":
                    commands.add("list")
                elif ch == "Z":
                    commands.add("zero")
            if letters[-1] in _IPT_VALUE_SHORT and i + 1 < len(texts):
                if letters[-1] == "t" or texts[i + 1].isdigit():
                    i += 1
        i += 1
    if "change" in commands or not commands:
        return "change"
    if "zero" in commands:
        return "zero"
    return "list"


def _shell_quote(t: str) -> str:
    import shlex

    return shlex.quote(t)


def _flag_value(args: Sequence[Word], flag: str) -> Word | None:
    for i, a in enumerate(args):
        if a.text == flag or (a.text.startswith("-") and not a.text.startswith("--") and flag[1] in a.text[1:] and a.text.endswith(flag[1])):
            return args[i + 1] if i + 1 < len(args) else Word("")
    return None


def _has_decode(args: Sequence[Word]) -> bool:
    return any(a.text in ("-d", "--decode", "-D") or (a.text.startswith("-") and not a.text.startswith("--") and "d" in a.text) for a in args)


def _skip_options(args: Sequence[Word], with_value: set[str]) -> list[Word]:
    i = 0
    while i < len(args):
        t = args[i].text
        if t == "--":
            return list(args[i + 1 :])
        if not t.startswith("-") or t == "-":
            break
        if t.startswith("--"):
            i += 1
            continue
        letters = t[1:]
        # e.g. -u root: the last letter takes the next word if it needs a value
        if letters and letters[-1] in with_value and len(letters) == 1:
            i += 2
            continue
        i += 1
    return list(args[i:])


def _strip_assignments(words: list[Word], v: Verdict) -> list[Word]:
    i = 0
    while i < len(words) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[i].text):
        var = words[i].text.split("=", 1)[0]
        if var in HIST_VARS:
            v.raise_to(Risk.BLOCKED, f"tampers with shell history ({var})")
        i += 1
    if i and i == len(words):
        v.raise_to(Risk.MUTATING, "sets shell variables")
    return words[i:]


# --------------------------------------------------------------------------- backstop patterns


def _skeleton(toks: list[Tok]) -> str:
    """Dequoted words (their internal whitespace hidden) and operators, joined
    by spaces, lowercased: the text the backstop regexes see."""
    parts = []
    for t in toks:
        if t.kind == "word":
            parts.append(re.sub(r"\s", "\x01", t.value))
        else:
            parts.append(t.value)
    return " ".join(parts).lower()


def _raw_skeleton(command: str) -> str:
    s = command.replace("\\\n", "")
    s = re.sub(r"\$\{?IFS\}?", " ", s)
    s = s.replace("'", "").replace('"', "").replace("\\", "")
    return re.sub(r"\s+", " ", s).lower()


_SH = r"(?:\S*/)?(?:ba|z|da|k|mk|c|tc|fi|a)?sh\b"
_SUDO = r"(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?"
BLOCKED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("download piped into a shell", re.compile(rf"\b(?:curl|wget|fetch)\b[^;&]*\|\s*{_SUDO}{_SH}")),
    ("decoded data piped into a shell", re.compile(rf"\bbase64\s+[^;&|]*(?:-d|--decode)\b[^;&]*\|\s*{_SUDO}{_SH}")),
    ("eval of command substitution", re.compile(r"\beval\b[^;&|]*\x00subst\x00")),
    ("rm --no-preserve-root", re.compile(r"\brm\b[^;&|]*--no-preserve-root")),
    ("recursive rm of /", re.compile(r"\brm\s+(?:-\S+\s+)*(?:-[a-z]*r[a-z]*|--recursive)\s+(?:-\S+\s+)*(?:/+\.?/*|/\*|~/?)(?:\s|$)")),
    ("mkfs", re.compile(r"\b(?:mkfs(?:\.\w+)?|mke2fs|wipefs)\b")),
    ("dd to a device", re.compile(r"\bdd\b[^;&|]*\bof=/dev/(?:sd|hd|vd|xvd|nvme|mmcblk|md\d|dm-|mapper/|disk/|mem|kmem)")),
    ("write to a block device", re.compile(r">\s*/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\d|mmcblk\d|mem|kmem)")),
    ("recursive chmod/chown of /", re.compile(r"\bch(?:mod|own|grp)\s+(?:\S+\s+)*?(?:-[a-z]*r[a-z]*|--recursive)\s+(?:\S+\s+)?/(?:\s|$)")),
    ("history -c", re.compile(r"\bhistory\s+(?:-\S+\s+)*-[a-z]*[cd]\b")),
    ("unset HISTFILE", re.compile(r"\bunset\s+(?:\S+\s+)*hist(?:file|size|filesize)\b")),
    ("HISTFILE/HISTSIZE tampering", re.compile(r"\b(?:histfile=|histsize=0\b|histfilesize=0\b)")),
    ("set +o history", re.compile(r"\bset\s+\+o\s+history\b")),
    ("stopping a logging/audit service", re.compile(
        r"\bsystemctl\s+(?:-\S+\s+)*(?:stop|disable|mask|kill)\s+(?:\S+\s+)*?"
        r"(?:auditd|rsyslog|syslog|syslog-ng|systemd-journald|journald)(?:\.service|\.socket)?\b")),
    ("stopping a logging/audit service", re.compile(r"\bservice\s+(?:auditd|rsyslog|rsyslogd|syslog|syslog-ng)\s+stop\b")),
    ("disabling audit", re.compile(r"\bauditctl\s+(?:\S+\s+)*(?:-e\s*0\b|-d\b)")),
]
FORK_BOMB = re.compile(r"([A-Za-z_:][\w:]*)\s*\(\s*\)\s*\{[^}]*?\1\s*\|\s*&?\s*\1\s*&")


def classify(command: str, extra_blocked: Sequence[str] = (), extra_destructive: Sequence[str] = ()) -> Verdict:
    return Classifier(extra_blocked, extra_destructive).classify(command)
