"""A scripted stand-in for the Anthropic client, for tests and manual dry runs.

Enabled in the core with TAC_TEST_FAKE_MODEL=1. It makes no network calls:

* it replies with everything it received in the last user turn (tool results,
  notes and text), so tests can see exactly what would have gone to the API;
* if the turn contains a line `FAKE_PROPOSE <command>`, it proposes <command>
  (the last such line wins) with risk taken from `FAKE_RISK <risk>` if present;
* placeholders in the command are declared, unless `FAKE_UNDECLARED` is present;
* `FAKE_SILENT` replies with no text, only a reasoning summary;
* `FAKE_REFUSE` makes it refuse; `FAKE_ERROR` makes it raise.
"""

from __future__ import annotations

import itertools
import re
from types import SimpleNamespace
from typing import Any

_ids = itertools.count(1)


class FakeError(Exception):
    pass


def _flatten(user: dict[str, Any]) -> str:
    parts = []
    for b in user["content"]:
        if b.get("type") == "tool_result":
            parts.append(f"[tool_result {b['tool_use_id']}] {b.get('content', '')}")
        elif b.get("type") == "text":
            parts.append(b["text"])
    return "\n".join(parts)


class _Messages:
    def __init__(self, owner: "FakeClient"):
        self.owner = owner

    def create(self, **kwargs: Any) -> Any:
        self.owner.requests.append(kwargs)
        text = _flatten(kwargs["messages"][-1])
        if "FAKE_ERROR" in text:
            raise FakeError("scripted failure")
        usage = SimpleNamespace(
            input_tokens=len(text) // 4, output_tokens=10,
            cache_read_input_tokens=0, cache_creation_input_tokens=0,
        )
        if "FAKE_REFUSE" in text:
            return SimpleNamespace(
                content=[], stop_reason="refusal", usage=usage, model=kwargs["model"],
                stop_details=SimpleNamespace(category="cyber", explanation=None),
            )
        thinking = "FAKE REASONING: the file is not a device" if "FAKE_SILENT" in text else ""
        content: list[dict[str, Any]] = [
            {"type": "thinking", "thinking": thinking, "signature": f"sig{next(_ids)}"},
        ]
        if "FAKE_SILENT" not in text:
            content.append({"type": "text", "text": "FAKE MODEL received:\n" + text})
        proposals = re.findall(r"^.*?FAKE_PROPOSE (.+)$", text, re.MULTILINE)
        if proposals:
            risk = (re.findall(r"FAKE_RISK (\w+)", text) or ["read_only"])[-1]
            content.append({
                "type": "tool_use",
                "id": f"toolu_fake{next(_ids):08d}",
                "name": "propose_command",
                "input": {
                    "command": proposals[-1].strip(),
                    "purpose": "scripted by the fake model",
                    "expected_effect": "whatever the command does",
                    "risk": risk,
                    "reversible": True,
                    "placeholders": [] if "FAKE_UNDECLARED" in text else [
                        {"name": n, "description": "scripted secret"}
                        for n in dict.fromkeys(re.findall(r"\{\{([A-Z][A-Z0-9_]*)\}\}", proposals[-1]))
                    ],
                    "injection_suspected": False,
                },
            })
        return SimpleNamespace(
            content=content,
            stop_reason="tool_use" if proposals else "end_turn",
            usage=usage,
            model=kwargs["model"],
            stop_details=None,
        )


class FakeClient:
    def __init__(self, timeout: float = 0.0):
        self.requests: list[dict[str, Any]] = []
        self.messages = _Messages(self)
        self.beta = SimpleNamespace(messages=self.messages)
