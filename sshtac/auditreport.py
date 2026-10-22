"""`sshtac report`: turn one JSONL audit log into a Markdown incident timeline.

Everything printed comes from the log itself (plus counts and times derived
from it). The log holds redacted text and placeholder names only, so the report
does too. Text that came from the AI or the terminal is made inert: control
characters become visible ⟨U+XXXX⟩, and Markdown that could turn into links,
images or HTML in a rendered copy is escaped.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, Iterable

from sshtac import charsafe
from sshtac.audit import state_dir

SUMMARY_LINES = 3  # lines of each AI reply shown without --full
MAX_LINE = 300
STAMP_RE = re.compile(r"-(\d{8}T\d{6}Z)\.jsonl$")


# --------------------------------------------------------------------------- loading


@dataclass
class Log:
    path: Path
    events: list[dict[str, Any]] = field(default_factory=list)
    bad_lines: int = 0


def load(path: Path) -> Log:
    log = Log(path)
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                log.bad_lines += 1
                continue
            if isinstance(rec, dict) and isinstance(rec.get("event"), str):
                log.events.append(rec)
            else:
                log.bad_lines += 1
    return log


def log_files(directory: Path | None = None) -> list[Path]:
    """All audit logs, oldest first (by the UTC stamp in the name)."""
    d = directory or state_dir()
    files = [p for p in d.glob("audit-*.jsonl") if p.is_file()]

    def key(p: Path) -> tuple[str, float]:
        m = STAMP_RE.search(p.name)
        return (m.group(1) if m else "", p.stat().st_mtime)

    return sorted(files, key=key)


def latest(directory: Path | None = None) -> Path:
    files = log_files(directory)
    if not files:
        raise FileNotFoundError(f"no audit logs in {directory or state_dir()}")
    return files[-1]


# --------------------------------------------------------------------------- text safety


def _visible_prose(text: str) -> str:
    return "".join(charsafe.codepoint(ch) if charsafe.is_rejected(ch) else ch for ch in text)


def prose(text: str, table: bool = False) -> str:
    """One line of untrusted prose, safe to place in Markdown: no links,
    images or HTML once rendered. Other Markdown (bold, code) is left alone."""
    line = _visible_prose(text).replace("\n", " ")
    if len(line) > MAX_LINE:
        line = line[: MAX_LINE - 1] + "…"
    line = re.sub(r"\\(?=[!-/:-@\[-`{-~])", r"\\\\", line)  # a backslash that would escape
    line = re.sub(r"([\[\]<])", r"\\\1", line)
    return line.replace("|", "\\|") if table else line


def code(text: str, table: bool = False) -> str:
    """A command as an inline code span (one line; newlines shown as ⏎)."""
    s = charsafe.visible(text).replace("\n", " ⏎ ")
    run = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (run + 1)
    if s.startswith("`") or s.endswith("`"):
        s = f" {s} "
    if table:
        s = s.replace("|", "\\|")
    return f"{fence}{s}{fence}"


def block(text: str, indent: str = "  ") -> list[str]:
    """Untrusted multi-line text as a fenced block (for --full)."""
    s = _visible_prose(text)
    run = max((len(m) for m in re.findall(r"`{3,}|~{3,}", s)), default=2)
    fence = "~" * max(3, run + 1)
    return [indent + fence + "text"] + [indent + ln for ln in s.split("\n")] + [indent + fence]


# --------------------------------------------------------------------------- times


def parse_ts(ts: Any) -> datetime | None:
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _full_time(dt: datetime | None, tz: tzinfo | None) -> str:
    if dt is None:
        return "unknown"
    local = dt.astimezone(tz)
    utc = dt.astimezone(timezone.utc)
    same_day = local.date() == utc.date()
    utc_fmt = "%H:%M:%S UTC" if same_day else "%Y-%m-%d %H:%M:%S UTC"
    return f"{local:%Y-%m-%d %H:%M:%S} {local:%Z} ({utc:{utc_fmt}})"


def _duration(d: timedelta) -> str:
    s = int(d.total_seconds())
    h, rem = divmod(s, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m" if h else f"{m}m {s:02d}s"


# --------------------------------------------------------------------------- proposals


@dataclass
class Proposal:
    id: str
    command: str
    purpose: str
    model_risk: str
    ts: datetime | None
    local_risk: str | None = None
    effective_risk: str | None = None
    reasons: list[str] = field(default_factory=list)
    injection_suspected: bool = False
    outcome: str | None = None  # approved / rejected / superseded / blocked
    outcome_ts: datetime | None = None
    edited: bool = False


def _proposals(events: Iterable[dict[str, Any]]) -> dict[str, Proposal]:
    props: dict[str, Proposal] = {}
    for e in events:
        kind = e["event"]
        pid = e.get("proposal_id")
        if kind == "model_reply" and isinstance(e.get("proposal"), dict):
            p = e["proposal"]
            pid = str(p.get("id", ""))
            props[pid] = Proposal(
                id=pid,
                command=str(p.get("command", "")),
                purpose=str(p.get("purpose", "")),
                model_risk=str(p.get("risk", "")),
                ts=parse_ts(e.get("ts")),
                injection_suspected=bool(p.get("injection_suspected")),
            )
        elif pid in props:
            prop = props[pid]
            if kind == "classification":
                prop.local_risk = e.get("local_risk")
                prop.effective_risk = e.get("effective_risk")
                prop.reasons = [r for r in e.get("reasons") or [] if isinstance(r, str)]
                prop.injection_suspected = prop.injection_suspected or bool(e.get("injection_suspected"))
            elif kind in ("approved", "rejected", "superseded"):
                prop.outcome, prop.outcome_ts = kind, parse_ts(e.get("ts"))
                prop.edited = prop.edited or bool(e.get("edited"))
            elif kind == "block" and prop.outcome is None:
                prop.outcome, prop.outcome_ts = "blocked", parse_ts(e.get("ts"))
            elif kind == "edit":
                prop.edited = True
    return props


# --------------------------------------------------------------------------- rendering


def _risk(label: Any) -> str:
    return f"**{label}**" if label in ("destructive", "blocked") else str(label or "unknown")


def _reply_lines(e: dict[str, Any], full: bool) -> tuple[str, list[str]]:
    text = e.get("text") or ""
    reasoning = e.get("reasoning") or ""
    if isinstance(text, str) and text.strip():
        label, body = "AI replied", text
    elif isinstance(reasoning, str) and reasoning.strip():
        label, body = "AI replied (reasoning summary only)", reasoning
    else:
        return "AI replied with no text", []
    lines = [ln for ln in body.split("\n") if ln.strip()]
    if full:
        return label, ["  > " + prose(ln) for ln in lines]
    out = ["  > " + prose(ln) for ln in lines[:SUMMARY_LINES]]
    if len(lines) > SUMMARY_LINES:
        out.append(f"  > … ({len(lines) - SUMMARY_LINES} more lines; use --full)")
    return label, out


def _outcome_text(p: Proposal, tz: tzinfo | None) -> str:
    when = f" at {p.outcome_ts.astimezone(tz):%H:%M:%S}" if p.outcome_ts else ""
    return {
        "approved": f"**approved{' after edit' if p.edited else ''}**{when}",
        "rejected": f"rejected{' after edit' if p.edited else ''}{when}",
        "superseded": f"superseded by a newer proposal{when}, not run",
        "blocked": f"approval blocked by the local policy{when}, not run",
        None: "no decision recorded",
    }[p.outcome]


def render(log: Log, full: bool = False, tz: tzinfo | None = None) -> str:
    events = log.events
    props = _proposals(events)
    start = next((e for e in events if e["event"] == "session_start"), None)
    end = next((e for e in reversed(events) if e["event"] == "session_end"), None)
    first_ts = parse_ts(events[0].get("ts")) if events else None
    last_ts = parse_ts(events[-1].get("ts")) if events else None
    start_ts = parse_ts(start.get("ts")) if start else first_ts
    end_ts = parse_ts(end.get("ts")) if end else None
    zone = (start_ts or datetime.now(timezone.utc)).astimezone(tz)

    target = str(start.get("target", "")) if start else ""
    session = next((str(e["session"]) for e in events if e.get("session")), "")
    model = str(start.get("model", "")) if start else ""
    if any(e["event"] == "fake_model" for e in events):
        model += " (scripted fake model, test run)"

    out: list[str] = [f"# sshtac session report: {prose(target or session or log.path.name)}", ""]
    out += ["| | |", "|---|---|"]
    out.append(f"| Target | {code(target, table=True) if target else 'unknown'} |")
    out.append(f"| Session | {prose(session, table=True) or 'unknown'} |")
    out.append(f"| Model | {prose(model, table=True) or 'unknown'} |")
    out.append(f"| Started | {_full_time(start_ts, tz)} |")
    if end_ts:
        dur = f", after {_duration(end_ts - start_ts)}" if start_ts else ""
        out.append(f"| Ended | {_full_time(end_ts, tz)}{dur} |")
    else:
        out.append(f"| Ended | not recorded; last entry {_full_time(last_ts, tz)} |")
    out.append(f"| Log | {prose(log.path.name, table=True)} |")
    out.append(f"| Activity | {_activity(events, props)} |")
    out.append("")
    offset = zone.strftime("%z")
    out.append(f"Times below are local ({zone.tzname()}, UTC{offset[:3]}:{offset[3:]}).")
    if log.bad_lines:
        out.append(f"{log.bad_lines} unreadable line(s) in the log were skipped.")
    out += ["", "## Timeline", ""]

    day = start_ts.astimezone(tz).date() if start_ts else None
    for e in events:
        dt = parse_ts(e.get("ts"))
        stamp = "??:??:??"
        if dt:
            local = dt.astimezone(tz)
            stamp = f"{local:%H:%M:%S}"
            if local.date() != day:
                day = local.date()
                stamp = f"{local:%Y-%m-%d %H:%M:%S}"
        lines = _event(e, props, full, tz)
        if lines:
            out.append(f"- **{stamp}** {lines[0]}")
            out += lines[1:]
    out += ["", "## Commands that ran", ""]
    out += _ran_table(events, props, tz)
    return "\n".join(out) + "\n"


def _activity(events: list[dict[str, Any]], props: dict[str, Proposal]) -> str:
    count = lambda kind: sum(1 for e in events if e["event"] == kind)  # noqa: E731
    outcomes = [p.outcome for p in props.values()]
    parts = [
        f"{count('send')} sends",
        f"{count('chat')} questions",
        f"{count('model_reply')} AI replies",
    ]
    if props:
        edited = sum(1 for p in props.values() if p.outcome == "approved" and p.edited)
        detail = [f"{outcomes.count('approved')} approved" + (f" ({edited} after edit)" if edited else "")]
        for kind in ("rejected", "blocked", "superseded"):
            if outcomes.count(kind):
                detail.append(f"{outcomes.count(kind)} {kind}")
        if outcomes.count(None):
            detail.append(f"{outcomes.count(None)} undecided")
        parts.append(f"{len(props)} proposed commands: " + ", ".join(detail))
    for kind, word in (("model_refusal", "refusals"), ("model_error", "AI errors"), ("error", "sshtac errors")):
        if count(kind):
            parts.append(f"{count(kind)} {word}")
    return "; ".join(parts)


def _event(e: dict[str, Any], props: dict[str, Proposal], full: bool, tz: tzinfo | None) -> list[str]:
    kind = e["event"]
    if kind == "session_start":
        return [f"Session started: {code(str(e.get('target', '')))}, model {prose(str(e.get('model', '')))}"]
    if kind == "session_end":
        return ["Session ended"]
    if kind == "quit":
        return ["You quit sshtac"]
    if kind == "fake_model":
        return ["Scripted fake model in use (test run, no AI calls)"]
    if kind == "send":
        text = e.get("text") if isinstance(e.get("text"), str) else ""
        source = {"results_buffer": "new terminal output", "selection": "a selection"}.get(
            e.get("source"), prose(str(e.get("source")))
        )
        n_lines = text.count("\n") + 1 if text else 0
        bits = [f"{len(text):,} chars, {n_lines} lines"]
        red = e.get("redactions") or {}
        if isinstance(red, dict) and red:
            bits.append("redacted: " + ", ".join(f"{v} {prose(str(k))}" for k, v in sorted(red.items())))
        if e.get("truncated"):
            bits.append("truncated")
        if e.get("note"):
            bits.append(f"note: {prose(str(e['note']))}")
        line = [f"Sent {source} to the AI ({'; '.join(bits)})"]
        return line + (block(text) if full and text else [])
    if kind == "chat":
        text = str(e.get("text", ""))
        if full:
            return ["You asked:"] + ["  > " + prose(ln) for ln in text.split("\n") if ln.strip()]
        first = next((ln for ln in text.split("\n") if ln.strip()), "")
        more = " …" if text.strip().count("\n") else ""
        return [f"You asked: “{prose(first)}”{more}"]
    if kind == "model_reply":
        label, body = _reply_lines(e, full)
        if e.get("served_by"):
            label += f" (fallback model {prose(str(e['served_by']))})"
        lines = [label + (":" if body else "")] + body
        if e.get("proposal_error"):
            lines.append(f"  - The AI's command proposal was invalid and ignored: {prose(str(e['proposal_error']))}")
        p = e.get("proposal")
        if isinstance(p, dict) and str(p.get("id", "")) in props:
            lines += _proposal_lines(props[str(p.get("id", ""))], tz)
        return lines
    if kind == "classification":
        return []  # folded into the proposal entry
    if kind == "edit":
        return [
            f"You edited the command: {code(str(e.get('before', '')))} → {code(str(e.get('after', '')))}"
            f" (now {_risk(e.get('effective_risk'))})"
        ]
    if kind == "block":
        reasons = [prose(r) for r in e.get("reasons") or [] if isinstance(r, str)]
        return [f"Approval blocked by the local policy: {'; '.join(reasons) or 'no reason recorded'}"]
    if kind == "approved":
        if e.get("edited"):
            line = [f"**Approved** after your edit and pasted into the shell: {code(str(e.get('command', '')))}"
                    f" ({_risk(e.get('effective_risk'))})"]
        else:
            line = [f"**Approved** and pasted into the shell ({_risk(e.get('effective_risk'))})"]
        names = [prose(n) for n in e.get("placeholders") or [] if isinstance(n, str)]
        if names:
            line.append(f"  - Placeholders filled in by you: {', '.join(names)} (values are never logged)")
        if e.get("prefixed_space"):
            line.append("  - Prefixed with a space to keep it out of shell history")
        return line
    if kind == "rejected":
        if e.get("edited"):
            return [f"Rejected after editing it to: {code(str(e.get('command', '')))}"]
        return ["Rejected"]
    if kind == "superseded":
        return [f"Proposal replaced by a newer one, not run: {code(str(e.get('command', '')))}"]
    if kind == "model_refusal":
        return [f"The AI declined to answer (category: {prose(str(e.get('category') or 'unspecified'))})"]
    if kind == "model_error":
        return [f"AI call failed: {prose(str(e.get('error', '')))}"]
    if kind == "error":
        return [f"sshtac error: {prose(str(e.get('error', '')))}"]
    if kind == "context_trimmed":
        return ["The oldest terminal output was trimmed from the AI's context"]
    return [f"Event {prose(kind)}"]


def _proposal_lines(p: Proposal, tz: tzinfo | None) -> list[str]:
    if p.effective_risk:
        risk = f"risk {_risk(p.effective_risk)} (AI said {p.model_risk}, local check {p.local_risk})"
    else:
        risk = f"AI said {_risk(p.model_risk)} (no local check recorded)"
    lines = [f"  - **Proposed:** {code(p.command)}, {risk}"]
    if p.purpose:
        lines.append(f"    - Purpose: {prose(p.purpose)}")
    if p.reasons:
        lines.append(f"    - Local check: {'; '.join(prose(r) for r in p.reasons)}")
    if p.injection_suspected:
        lines.append("    - ⚠ The AI flagged possible prompt injection in the terminal output")
    lines.append(f"    - Outcome: {_outcome_text(p, tz)}")
    return lines


def _ran_table(events: list[dict[str, Any]], props: dict[str, Proposal], tz: tzinfo | None) -> list[str]:
    ran = [e for e in events if e["event"] == "approved"]
    if not ran:
        return ["No commands were approved in this session."]
    out = ["| # | Time | Command | Risk | Notes |", "|---|---|---|---|---|"]
    for i, e in enumerate(ran, 1):
        dt = parse_ts(e.get("ts"))
        when = f"{dt.astimezone(tz):%H:%M:%S}" if dt else "?"
        notes = []
        p = props.get(e.get("proposal_id"))
        if e.get("edited"):
            notes.append("edited; AI proposed " + code(p.command, table=True) if p else "edited")
        names = [prose(n, table=True) for n in e.get("placeholders") or [] if isinstance(n, str)]
        if names:
            notes.append("placeholders: " + ", ".join(names))
        if e.get("prefixed_space"):
            notes.append("kept out of history")
        risk = e.get("effective_risk") or (p.effective_risk if p else None) or (p.model_risk if p else None)
        out.append(f"| {i} | {when} | {code(str(e.get('command', '')), table=True)} | {_risk(risk)} | {'; '.join(notes)} |")
    out += ["", "Approved commands were pasted into the shell; the log does not record their exit status."]
    return out
