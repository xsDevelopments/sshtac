import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from tac import charsafe
from tac.audit import AuditLog
from tac.executor import assess
from tac.policy import Classifier, Risk

class TestCharSafety(unittest.TestCase):
    def test_plain_ok(self):
        r = charsafe.check("ls -la /var/log | head -20")
        self.assertTrue(r.ok)
        self.assertFalse(r.multiline)

    def test_rejected_controls(self):
        for ch, name in [("\x1b", "ESC"), ("\r", "CR"), ("\x00", "NUL"), ("\t", "TAB"),
                         ("\x07", "BELL"), ("\x7f", "DEL"), ("\x9b", "control")]:
            r = charsafe.check(f"ls{ch}x")
            self.assertFalse(r.ok, repr(ch))

    def test_rejected_bidi_and_zero_width(self):
        for cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069,
                   0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0xE0041, 0x2028):
            self.assertFalse(charsafe.check(f"ls {chr(cp)}x").ok, hex(cp))

    def test_trojan_source_example(self):
        # Looks like `rm -i file` in a bidi-aware renderer.
        r = charsafe.check("echo ‮ elif ⁦ rm -rf ~ ⁩")
        self.assertFalse(r.ok)
        self.assertIn("U+202E", r.rejected[0])

    def test_multiline_flagged_not_rejected(self):
        r = charsafe.check("ls\nrm -rf /")
        self.assertTrue(r.ok)
        self.assertTrue(r.multiline)

    def test_non_ascii_visible(self):
        r = charsafe.check("rm -rf x")
        self.assertTrue(r.ok)
        self.assertTrue(r.non_ascii)
        self.assertEqual(charsafe.visible("rm -rf x"), "rm⟨U+00A0⟩-rf x")
        self.assertEqual(charsafe.visible("a\x1bb\nc"), "a⟨U+001B⟩b\nc")


class TestAssess(unittest.TestCase):
    C = Classifier()

    def test_plain_read_only_approvable(self):
        a = assess("uptime", "read_only", self.C)
        self.assertEqual(a.blockers, [])
        self.assertEqual(a.effective, Risk.READ_ONLY)

    def test_stricter_label_wins(self):
        self.assertEqual(assess("uptime", "destructive", self.C).effective, Risk.DESTRUCTIVE)
        self.assertEqual(assess("rm /tmp/x", "read_only", self.C).effective, Risk.DESTRUCTIVE)

    def test_blockers(self):
        self.assertIn("unsafe characters", assess("ls\x1b[2J", "read_only", self.C).blockers[0])
        self.assertIn("multi-line", assess("ls\nid", "read_only", self.C).blockers[0])
        self.assertIn("blocked by local policy", assess("rm -rf /", "read_only", self.C).blockers[0])
        # placeholders and destructive commands are approvable (with input)
        self.assertEqual(assess("mysql -p{{PW}}", "mutating", self.C).blockers, [])
        self.assertEqual(assess("kill 1", "destructive", self.C).blockers, [])


class TestAudit(unittest.TestCase):
    def test_file_mode_and_records(self):
        with tempfile.TemporaryDirectory() as d:
            log = AuditLog("tac-local", Path(d) / "tac")
            log.event("session_start", target="local shell")
            log.event("send", source="selection", text="password=[REDACTED:password]")
            log.close()
            log.event("after_close")  # ignored, no crash
            self.assertEqual(stat.S_IMODE(os.stat(log.path).st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(os.stat(Path(d) / "tac").st_mode), 0o700)
            recs = [json.loads(l) for l in log.path.read_text().splitlines()]
            self.assertEqual([r["event"] for r in recs], ["session_start", "send"])
            self.assertEqual([r["seq"] for r in recs], [1, 2])
            self.assertTrue(all(r["ts"].endswith("+00:00") for r in recs))

    def test_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "tac"
            base.mkdir(mode=0o700)
            log = AuditLog("s", base)
            log.close()
            log.path.unlink()
            log.path.symlink_to(Path(d) / "elsewhere")
            # Same second, same name: exclusive create must not follow the link.
            with self.assertRaises(OSError):
                fd = os.open(log.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
