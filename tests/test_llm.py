import unittest
from types import SimpleNamespace

from tac import llm
from tac.testing import FakeClient


def conv(**kw) -> tuple[llm.Conversation, FakeClient]:
    client = FakeClient()
    return llm.Conversation(client, "claude-sonnet-5-5", **kw), client


VALID = {
    "command": "ss -tlnp",
    "purpose": "p",
    "expected_effect": "e",
    "risk": "read_only",
    "reversible": True,
    "placeholders": [],
    "injection_suspected": False,
}


class TestProposalValidation(unittest.TestCase):
    def test_valid(self):
        p = llm.Proposal.from_tool_input("t1", dict(VALID, command="  ss -tlnp \n"))
        self.assertEqual(p.command, "ss -tlnp")

    def test_bad_inputs(self):
        cases = [
            "not a dict",
            {k: v for k, v in VALID.items() if k != "risk"},
            dict(VALID, command=""),
            dict(VALID, command="x" * 5000),
            dict(VALID, risk="harmless"),
            dict(VALID, reversible="yes"),
            dict(VALID, placeholders="none"),
            dict(VALID, placeholders=[{"name": "db pass", "description": ""}]),
            dict(VALID, command="mysql -p{{DB_PASS}}"),  # undeclared
        ]
        for c in cases:
            with self.assertRaises(llm.ProposalError, msg=repr(c)[:80]):
                llm.Proposal.from_tool_input("t", c)

    def test_placeholders_declared_and_unused_dropped(self):
        p = llm.Proposal.from_tool_input("t", dict(
            VALID,
            command="mysql -u root -p{{DB_PASS}}",
            placeholders=[{"name": "DB_PASS", "description": "root pw"}, {"name": "UNUSED", "description": ""}],
        ))
        self.assertEqual(p.placeholders, [{"name": "DB_PASS", "description": "root pw"}])

    def test_tool_schema_is_strict(self):
        schema = llm.PROPOSE_TOOL["input_schema"]
        self.assertTrue(llm.PROPOSE_TOOL["strict"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))


class TestRequestShape(unittest.TestCase):
    def test_request_parameters(self):
        c, client = conv(effort="medium")
        c.ask("hello")
        req = client.requests[0]
        self.assertEqual(req["model"], "claude-sonnet-5-5")
        self.assertEqual(req["tool_choice"], {"type": "auto", "disable_parallel_tool_use": True})
        self.assertEqual(req["tools"], [llm.PROPOSE_TOOL])
        self.assertEqual(req["output_config"], {"effort": "medium"})
        self.assertEqual(req["betas"], [llm.FALLBACK_BETA])
        self.assertEqual(req["fallbacks"], "default")
        self.assertNotIn("thinking", req)  # adaptive by default on this model

    def test_fallbacks_off_uses_plain_endpoint(self):
        c, client = conv(fallbacks=False)
        c.ask("hello")
        self.assertNotIn("betas", client.requests[0])

    def test_system_and_tools_identical_across_turns(self):
        c, client = conv()
        c.ask("one")
        c.ask("two FAKE_PROPOSE uptime")
        c.ask("three")
        a, b, d = client.requests
        self.assertEqual(a["system"], b["system"])
        self.assertEqual(a["tools"], d["tools"])

    def test_history_is_append_only(self):
        c, client = conv()
        c.ask("one FAKE_PROPOSE uptime")
        c.ask("two")
        c.ask("three")
        first, second, third = (r["messages"] for r in client.requests)
        self.assertEqual(second[: len(first)], first[:-1] + [second[len(first) - 1]])
        self.assertEqual(third[: len(second)], second)
        # thinking blocks are passed back verbatim
        self.assertEqual(third[1]["content"][0]["type"], "thinking")

    def test_session_context_only_on_first_turn(self):
        c, client = conv(session_context="The shell pane is running ssh web-01.")
        c.ask("a")
        c.ask("b")
        self.assertIn("[tac] The shell pane is running ssh web-01.", llm_text(client.requests[0]))
        self.assertNotIn("ssh web-01", client.requests[1]["messages"][-1]["content"][-1]["text"])


def llm_text(req) -> str:
    return "\n".join(b.get("text", "") for b in req["messages"][-1]["content"])


class TestToolResults(unittest.TestCase):
    def test_proposal_then_pending_result(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE ss -tlnp")
        self.assertEqual(r.proposal.command, "ss -tlnp")
        c.ask("what next?")
        blocks = client.requests[1]["messages"][-1]["content"]
        self.assertEqual(blocks[0]["type"], "tool_result")  # tool_result comes first
        self.assertEqual(blocks[0]["tool_use_id"], r.proposal.id)
        self.assertIn("not acted", blocks[0]["content"])
        self.assertEqual(blocks[-1]["text"], "what next?")

    def test_approved_before_next_turn(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE uptime")
        c.record_outcome(r.proposal.id, "approved")
        c.ask("here is the output")
        self.assertIn("approved", client.requests[1]["messages"][-1]["content"][0]["content"])

    def test_late_outcome_becomes_note(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE uptime")
        c.ask("still thinking")  # tool_result goes out as pending
        c.record_outcome(r.proposal.id, "rejected")
        c.ask("ok")
        last = llm_text(client.requests[2])
        self.assertIn(f"[tac] Update on proposal {r.proposal.id[-8:]}: The human rejected", last)
        c.ask("again")
        self.assertNotIn("Update on proposal", llm_text(client.requests[3]))

    def test_outcome_during_inflight_request_not_lost(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE uptime")
        original = client.messages.create

        def approve_mid_flight(**kw):
            c.record_outcome(r.proposal.id, "approved")
            return original(**kw)

        client.messages.create = approve_mid_flight
        client.beta.messages = client.messages
        c.ask("question while pending")
        client.messages.create = original
        c.ask("next")
        self.assertIn("approved", llm_text(client.requests[2]))

    def test_superseded_makes_no_note(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE a")
        c.ask("b FAKE_PROPOSE b")
        c.record_outcome(r.proposal.id, "superseded")
        c.ask("c")
        self.assertNotIn("Update on proposal", llm_text(client.requests[2]))

    def test_invalid_proposal_reported_as_error(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE mysql -p{{PW}}")  # undeclared placeholder
        self.assertIsNone(r.proposal)
        self.assertIn("undeclared", r.proposal_error)
        c.ask("next")
        tr = client.requests[1]["messages"][-1]["content"][0]
        self.assertTrue(tr["is_error"])

    def test_second_tool_use_rejected(self):
        c, client = conv()
        orig = client.messages.create

        def two_calls(**kw):
            resp = orig(**kw)
            extra = dict(resp.content[-1], id="toolu_second")
            resp.content.append(extra)
            return resp

        client.messages.create = two_calls
        client.beta.messages = client.messages
        r = c.ask("FAKE_PROPOSE uptime")
        self.assertEqual(r.proposal.command, "uptime")
        client.messages.create = orig
        c.ask("next")
        results = [b for b in client.requests[1]["messages"][-1]["content"] if b["type"] == "tool_result"]
        self.assertEqual(len(results), 2)
        self.assertTrue(results[1]["is_error"])


class TestFailures(unittest.TestCase):
    def test_refusal_not_committed(self):
        c, client = conv()
        r = c.ask("FAKE_REFUSE please")
        self.assertTrue(r.refused)
        self.assertEqual(r.refusal_category, "cyber")
        self.assertEqual(c.messages, [])

    def test_refusal_keeps_pending_tool_result(self):
        c, client = conv()
        r = c.ask("FAKE_PROPOSE uptime")
        c.ask("FAKE_REFUSE")
        c.ask("retry")
        ids = [b.get("tool_use_id") for b in client.requests[2]["messages"][-1]["content"]]
        self.assertIn(r.proposal.id, ids)

    def test_error_leaves_history_unchanged(self):
        c, client = conv()
        c.ask("one")
        before = list(c.messages)
        with self.assertRaises(Exception):
            c.ask("FAKE_ERROR")
        self.assertEqual(c.messages, before)

    def test_describe_error_never_raises(self):
        self.assertIn("ValueError", llm.describe_error(ValueError("x")))


class TestTrim(unittest.TestCase):
    def test_trim_replaces_oldest_output_and_strips_thinking(self):
        c, client = conv(trim_at_tokens=10_000_000)
        for i in range(4):
            c.ask(f'<terminal_output source="results_buffer">\nout{i}\n' + "x" * 500 + "\n</terminal_output>")
        c.trim_at_tokens = 100  # the last request crossed the threshold
        r = c.ask("after")
        self.assertTrue(r.trimmed)
        sent = client.requests[-1]["messages"]
        texts = [b.get("text", "") for m in sent if m["role"] == "user" for b in m["content"]]
        self.assertIn(llm.TRIM_STUB, texts)
        self.assertTrue(any("out3" in t for t in texts))
        for m in sent[:-1]:
            if m["role"] == "assistant":
                self.assertNotIn("thinking", [b["type"] for b in m["content"]])

    def test_no_trim_below_threshold(self):
        c, client = conv(trim_at_tokens=10_000_000)
        c.ask("a")
        self.assertFalse(c.ask("b").trimmed)


class TestSdkBlockConversion(unittest.TestCase):
    def test_sdk_objects_converted_with_to_dict(self):
        class Block:
            def to_dict(self, mode="python"):
                return {"type": "text", "text": f"via {mode}"}

        self.assertEqual(llm._block_dict(Block()), {"type": "text", "text": "via json"})
        self.assertEqual(llm._usage_dict(SimpleNamespace(input_tokens=5))["input_tokens"], 5)


if __name__ == "__main__":
    unittest.main()
