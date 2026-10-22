"""`sshtac review`: replay every command the AI proposed through the current
policy and show where the local check and the AI's own label disagree.

Stricter locally: likely false positives in the policy (or the AI under-rating).
Looser locally: the AI was more cautious than the policy; worth a look in case
the policy is missing a rule.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from sshtac.auditreport import Log, code, parse_ts, prose
from sshtac.policy import Classifier, Risk


@dataclass
class Replayed:
    command: str
    model: Risk
    local: Risk
    top_reasons: list[str]
    logged_local: str | None  # what the policy said during the session, if recorded
    log: str
    ts: str


def replay(logs: list[Log], classifier: Classifier) -> list[Replayed]:
    out: list[Replayed] = []
    for log in logs:
        logged = {
            e.get("proposal_id"): e.get("local_risk") for e in log.events if e["event"] == "classification"
        }
        for e in log.events:
            p = e.get("proposal") if e["event"] == "model_reply" else None
            if not isinstance(p, dict) or not isinstance(p.get("command"), str):
                continue
            v = classifier.classify(p["command"])
            dt = parse_ts(e.get("ts"))
            out.append(Replayed(
                command=p["command"],
                model=Risk.from_label(str(p.get("risk", ""))),
                local=v.risk,
                top_reasons=v.top_reasons,
                logged_local=logged.get(p.get("id")),
                log=log.path.name,
                ts=f"{dt.astimezone():%Y-%m-%d %H:%M}" if dt else "?",
            ))
    return out


_PATHISH = re.compile(r"(?<![\w$])(?:~|/)[^\s,;'\"]*")


def reason_group(reason: str) -> str:
    """Group reasons that differ only by the path they mention."""
    return _PATHISH.sub("…", reason)


def _commands(items: list[Replayed], with_reasons: bool = False) -> list[str]:
    seen: dict[str, list[Replayed]] = defaultdict(list)
    for r in items:
        seen[r.command].append(r)
    lines = []
    for cmd, rs in sorted(seen.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        r = rs[0]
        times = f" ×{len(rs)}" if len(rs) > 1 else ""
        extra = f"AI said {r.model.label}, local {r.local.label}"
        if with_reasons and r.top_reasons:
            extra += ": " + "; ".join(prose(x) for x in r.top_reasons)
        lines.append(f"- {code(cmd)}{times}  ({extra}; {prose(r.log)} {r.ts})")
    return lines


def render(items: list[Replayed], n_logs: int, policy_note: str = "") -> str:
    stricter = [r for r in items if r.local > r.model]
    looser = [r for r in items if r.local < r.model]
    changed = [r for r in items if r.logged_local and r.logged_local != r.local.label]
    out = ["# sshtac policy review", ""]
    out.append(
        f"Replayed {len(items)} proposed commands from {n_logs} log(s) through the current policy"
        f"{policy_note}. Agree: {len(items) - len(stricter) - len(looser)}, "
        f"local stricter: {len(stricter)}, local looser: {len(looser)}."
    )

    out += ["", f"## Local check stricter than the AI's label: {len(stricter)}", ""]
    if stricter:
        out.append("Likely false positives in the policy. Grouped by the reason that set the level "
                   "(a command with several reasons is listed under each).")
        groups: dict[str, list[Replayed]] = defaultdict(list)
        for r in stricter:
            for reason in {reason_group(x) for x in r.top_reasons} or {"(no reason recorded)"}:
                groups[reason].append(r)
        for reason, rs in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            out += ["", f"### {prose(reason)}: {len(rs)}", ""]
            out += _commands(rs)
    else:
        out.append("None.")

    out += ["", f"## Local check looser than the AI's label: {len(looser)}", ""]
    if looser:
        out.append("The AI was more cautious than the policy; check whether a rule is missing.")
        pairs: dict[tuple[Risk, Risk], list[Replayed]] = defaultdict(list)
        for r in looser:
            pairs[(r.model, r.local)].append(r)
        for (model, local), rs in sorted(pairs.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            out += ["", f"### AI said {model.label}, local check says {local.label}: {len(rs)}", ""]
            out += _commands(rs, with_reasons=True)
    else:
        out.append("None.")

    if changed:
        out += ["", f"## Local verdict changed since the session: {len(changed)}", ""]
        out.append("The policy rates these differently now than when they were proposed.")
        out.append("")
        for r in changed:
            out.append(f"- {code(r.command)}  (was {prose(r.logged_local or '')}, now {r.local.label}; "
                       f"{prose(r.log)} {r.ts})")
    return "\n".join(out) + "\n"


def run(paths: list[Path], classifier: Classifier, policy_note: str = "") -> str:
    from sshtac.auditreport import load

    logs = [load(p) for p in paths]
    return render(replay(logs, classifier), len(logs), policy_note)
