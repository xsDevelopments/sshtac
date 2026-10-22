import contextlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import unittest
from datetime import timedelta, timezone
from pathlib import Path
from unittest import mock

from sshtac import auditreport, cli, review
from sshtac.policy import Classifier, Risk

FIXTURES = Path(__file__).parent / "fixtures" / "audit"
LAB = FIXTURES / "audit-lab-20260301T090000Z.jsonl"
OLD = FIXTURES / "audit-old-20260215T100000Z.jsonl"
PLUS10 = timezone(timedelta(hours=10), "TEST")


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


class TestReport(unittest.TestCase):
    def setUp(self):
        self.log = auditreport.load(LAB)
        self.md = auditreport.render(self.log, tz=PLUS10)

    def test_header(self):
        self.assertIn("# sshtac session report: -p 2222 admin@mail.example", self.md)
        self.assertIn("| Target | `-p 2222 admin@mail.example` |", self.md)
        self.assertIn("| Model | claude-test-model |", self.md)
        self.assertIn("| Started | 2026-03-01 19:00:00 TEST (09:00:00 UTC) |", self.md)
        self.assertIn("| Ended | 2026-03-01 19:04:00 TEST (09:04:00 UTC), after 4m 00s |", self.md)
        self.assertIn("Times below are local (TEST, UTC+10:00).", self.md)
        self.assertIn("1 unreadable line(s)", self.md)
        self.assertIn("5 proposed commands: 2 approved (1 after edit), 1 rejected, 1 blocked, 1 superseded", self.md)

    def test_send_is_summarised_not_quoted(self):
        self.assertIn("**19:01:20** Sent new terminal output to the AI (", self.md)
        self.assertIn("redacted: 1 aws_key; truncated; note: a full-screen program is running", self.md)
        self.assertNotIn("FULLONLY_OUTPUT", self.md)
        full = auditreport.render(self.log, full=True, tz=PLUS10)
        self.assertIn("FULLONLY_OUTPUT", full)

    def test_reply_first_lines(self):
        self.assertIn("> Let's look at the queue first.", self.md)
        self.assertIn("(1 more lines; use --full)", self.md)
        self.assertNotIn("FULLONLY_REPLY", self.md)
        self.assertIn("FULLONLY_REPLY", auditreport.render(self.log, full=True, tz=PLUS10))
        self.assertIn("AI replied (reasoning summary only):", self.md)
        self.assertIn("You asked: “why is the mail queue growing?” …", self.md)

    def test_outcomes(self):
        md = self.md
        self.assertIn("**Proposed:** `mailq | tail -n 5`, risk read_only", md)
        self.assertIn("Outcome: **approved** at 19:01:10", md)
        self.assertIn("risk **destructive** (AI said destructive, local check mutating)", md)
        self.assertIn("Outcome: **approved after edit** at 19:01:50", md)
        self.assertIn("You edited the command: `postsuper -d ALL deferred` → `postsuper -h ALL deferred`", md)
        self.assertIn("Placeholders filled in by you: DB_PASSWORD (values are never logged)", md)
        self.assertIn("Prefixed with a space", md)
        self.assertIn("Outcome: superseded by a newer proposal at 19:02:10, not run", md)
        self.assertIn("Proposal replaced by a newer one, not run: `systemctl restart postfix`", md)
        self.assertIn("Outcome: rejected at 19:02:20", md)
        self.assertIn("Outcome: approval blocked by the local policy at 19:03:05, not run", md)
        self.assertIn("Approval blocked by the local policy: the AI suspected prompt injection", md)
        self.assertIn("possible prompt injection", md)
        self.assertIn("The AI declined to answer (category: cyber)", md)
        self.assertIn("AI call failed: overloaded (529)", md)

    def test_ran_table_has_only_approved(self):
        table = self.md.split("## Commands that ran", 1)[1]
        rows = [ln for ln in table.splitlines() if re.match(r"\| \d+ \|", ln)]
        self.assertEqual(len(rows), 2)
        self.assertIn("`mailq \\| tail -n 5`", rows[0])
        self.assertIn("`postsuper -h ALL deferred`", rows[1])
        self.assertIn("edited; AI proposed `postsuper -d ALL deferred`", rows[1])
        self.assertIn("placeholders: DB_PASSWORD", rows[1])
        self.assertIn("**destructive**", rows[1])

    def test_untrusted_text_is_inert(self):
        for md in (self.md, auditreport.render(self.log, full=True, tz=PLUS10)):
            self.assertNotIn("\x1b", md)
            self.assertIn("⟨U+001B⟩", md)
            self.assertNotRegex(md, r"(?<!\\)\]\(http")  # no live link or image
            self.assertNotRegex(md, r"(?<!\\)<script")
            self.assertIn("\\[click here\\](http://evil.example/x)", md)
            self.assertIn("!\\[img\\]", md)

    def test_never_invents_commands(self):
        # Every code span in the report must be text that is in the log.
        logged = []
        with open(LAB, encoding="utf-8") as f:
            for line in f:
                try:
                    logged.extend(_strings(json.loads(line)))
                except ValueError:
                    pass
        md = auditreport.render(self.log, full=True, tz=PLUS10)
        spans = re.findall(r"`([^`\n]+)`", md)
        self.assertTrue(spans)
        for span in spans:
            span = span.replace("\\|", "|")
            self.assertTrue(any(span in s for s in logged), span)

    def test_code_span_with_backticks(self):
        self.assertEqual(auditreport.code("echo `id`"), "`` echo `id` ``")
        self.assertEqual(auditreport.code("a\nb"), "`a ⏎ b`")
        self.assertEqual(auditreport.code("a|b", table=True), "`a\\|b`")

    def test_empty_and_partial_log(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "audit-x-20260101T000000Z.jsonl"
            p.write_text(json.dumps({"ts": "2026-01-01T00:00:00.000+00:00", "seq": 1, "session": "x",
                                     "event": "session_start", "target": "local shell", "model": "m"}) + "\n")
            md = auditreport.render(auditreport.load(p), tz=timezone.utc)
            self.assertIn("| Ended | not recorded", md)
            self.assertIn("No commands were approved", md)


class TestReview(unittest.TestCase):
    def setUp(self):
        logs = [auditreport.load(OLD)]
        self.items = review.replay(logs, Classifier(extra_destructive=["frobnicate"]))
        self.md = review.render(self.items, 1)

    def test_replay(self):
        self.assertEqual(len(self.items), 6)
        by_cmd = {r.command: r for r in self.items}
        self.assertEqual(by_cmd["cat /etc/hostname"].model, Risk.DESTRUCTIVE)
        self.assertEqual(by_cmd["cat /etc/hostname"].local, Risk.READ_ONLY)
        self.assertEqual(by_cmd["ls -l /var/log"].logged_local, "mutating")

    def test_stricter_grouped_by_reason(self):
        md = self.md
        self.assertIn("Agree: 1, local stricter: 4, local looser: 1.", md)
        self.assertIn("### rm deletes data: 2", md)
        self.assertIn("`rm -rf /tmp/scratch` ×2", md)
        self.assertIn("### redirection overwrites …: 1", md)
        self.assertIn("### matches configured destructive pattern 'frobnicate': 1", md)

    def test_looser_and_changed(self):
        md = self.md
        self.assertIn("### AI said destructive, local check says read_only: 1", md)
        self.assertIn("`cat /etc/hostname`", md)
        self.assertIn("## Local verdict changed since the session: 1", md)
        self.assertIn("`ls -l /var/log`  (was mutating, now read_only", md)

    def test_reason_group(self):
        self.assertEqual(review.reason_group("tee overwrites /etc/ssh/x.conf"), "tee overwrites …")
        self.assertEqual(review.reason_group("redirection overwrites ~/.bashrc"), "redirection overwrites …")
        self.assertEqual(review.reason_group("sievec is not on the read-only list"),
                         "sievec is not on the read-only list")


class TestCli(unittest.TestCase):
    """Runs the subcommands against a temporary state dir, never the real one."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        state = Path(self.tmp.name) / "state" / "sshtac"
        state.mkdir(parents=True)
        for f in (LAB, OLD):
            shutil.copy(f, state / f.name)
        env = {"XDG_STATE_HOME": str(state.parent), "SSHTAC_CONFIG": str(Path(self.tmp.name) / "none.toml")}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_report_latest(self):
        for argv in (["report"], ["report", "--latest"]):
            rc, out, _ = self.run_cli(*argv)
            self.assertEqual(rc, 0)
            self.assertIn("audit-lab-20260301T090000Z.jsonl", out)

    def test_report_to_private_file(self):
        target = Path(self.tmp.name) / "report.md"
        rc, out, err = self.run_cli("report", str(OLD), "-o", str(target))
        self.assertEqual(rc, 0)
        self.assertEqual(out, "")
        self.assertIn("# sshtac session report: local shell", target.read_text())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_report_missing_file(self):
        rc, _, err = self.run_cli("report", str(Path(self.tmp.name) / "nope.jsonl"))
        self.assertEqual(rc, 1)
        self.assertIn("sshtac:", err)

    def test_review_all_and_explicit(self):
        rc, out, _ = self.run_cli("review")
        self.assertEqual(rc, 0)
        self.assertIn("from 2 log(s)", out)
        rc, out, _ = self.run_cli("review", str(OLD))
        self.assertEqual(rc, 0)
        self.assertIn("Replayed 6 proposed commands from 1 log(s)", out)

    def test_review_empty_state_dir(self):
        for f in (Path(os.environ["XDG_STATE_HOME"]) / "sshtac").iterdir():
            f.unlink()
        rc, _, err = self.run_cli("review", "--all")
        self.assertEqual(rc, 1)
        self.assertIn("no audit logs", err)


if __name__ == "__main__":
    unittest.main()
