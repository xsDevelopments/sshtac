import copy
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sshtac import clipboard, config
from sshtac.launcher import configure_clipboard


def fake_bin(d: Path, *names: str) -> str:
    for n in names:
        p = d / n
        p.write_text("#!/bin/sh\ncat >/dev/null\n")
        p.chmod(0o700)
    return str(d)


class TestDetect(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        patcher = mock.patch.object(clipboard.sys, "platform", "linux")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_x11_prefers_xclip_and_pins_display(self):
        path = fake_bin(self.dir, "xclip", "xsel")
        cmd = clipboard.detect({"PATH": path, "DISPLAY": ":10.0"})
        self.assertEqual(cmd, "DISPLAY=:10.0 xclip -selection clipboard -in")

    def test_x11_falls_back_to_xsel(self):
        path = fake_bin(self.dir, "xsel")
        self.assertEqual(clipboard.detect({"PATH": path, "DISPLAY": ":0"}), "DISPLAY=:0 xsel --clipboard --input")

    def test_wayland(self):
        path = fake_bin(self.dir, "wl-copy", "xclip")
        cmd = clipboard.detect({"PATH": path, "WAYLAND_DISPLAY": "wayland-0", "DISPLAY": ":0"})
        self.assertEqual(cmd, "WAYLAND_DISPLAY=wayland-0 wl-copy")

    def test_no_display_means_no_tool(self):
        # e.g. sshtac running on a server you SSH'd into: OSC 52 only.
        path = fake_bin(self.dir, "xclip")
        self.assertIsNone(clipboard.detect({"PATH": path}))

    def test_odd_display_value_is_quoted(self):
        path = fake_bin(self.dir, "xclip")
        cmd = clipboard.detect({"PATH": path, "DISPLAY": ":0; rm -rf ~"})
        self.assertTrue(cmd.startswith("DISPLAY=':0; rm -rf ~' "), cmd)

    def test_settings(self):
        path = fake_bin(self.dir, "xclip")
        env = {"PATH": path, "DISPLAY": ":0"}
        self.assertIn("xclip", clipboard.command("auto", env))
        self.assertIsNone(clipboard.command("osc52", env))
        self.assertIsNone(clipboard.command("off", env))
        self.assertEqual(clipboard.command("xclip -selection primary", env), "xclip -selection primary")


class TestCopy(unittest.TestCase):
    def test_tmux_command_keeps_own_redirection(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "clip")
            cmd = clipboard.tmux_command(f"cat > '{out}'")
            subprocess.run(["/bin/sh", "-c", cmd], input=b"hello", check=True)
            self.assertEqual(out.read_text(), "hello")

    def test_copy_runs_command_with_text(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "clip")
            clipboard.copy(f"cat > '{out}'", "line 1\nüñí\n")
            self.assertEqual(out.read_text(encoding="utf-8"), "line 1\nüñí\n")

    def test_copy_failure_raises(self):
        with self.assertRaises(subprocess.CalledProcessError):
            clipboard.copy("exit 3", "x")


class FakeTmux:
    def __init__(self):
        self.calls = []

    def run(self, *args, **kw):
        self.calls.append(args)
        return ""


class TestConfigure(unittest.TestCase):
    def cfg(self, setting):
        data = copy.deepcopy(config.DEFAULTS)
        data["tmux"]["clipboard"] = setting
        return config.from_dict(data)

    def test_auto_with_tool(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(clipboard.sys, "platform", "linux"):
            env = {"PATH": fake_bin(Path(d), "xclip"), "DISPLAY": ":1"}
            t = FakeTmux()
            self.assertIn("xclip", configure_clipboard(t, self.cfg("auto"), env))
        self.assertIn(("set-option", "-s", "set-clipboard", "external"), t.calls)
        cc = [c for c in t.calls if c[2] == "copy-command"][0]
        self.assertIn("DISPLAY=:1 xclip -selection clipboard -in", cc[3])

    def test_off_and_osc52(self):
        t = FakeTmux()
        self.assertIsNone(configure_clipboard(t, self.cfg("off"), {}))
        self.assertIn(("set-option", "-s", "set-clipboard", "off"), t.calls)
        self.assertIn(("set-option", "-s", "copy-command", ""), t.calls)
        t = FakeTmux()
        configure_clipboard(t, self.cfg("osc52"), {"DISPLAY": ":0"})
        self.assertIn(("set-option", "-s", "set-clipboard", "external"), t.calls)
        self.assertIn(("set-option", "-s", "copy-command", ""), t.calls)

    def test_bad_setting(self):
        for bad in ("", "   ", 5):
            with self.assertRaises(config.ConfigError, msg=repr(bad)):
                self.cfg(bad)

    def test_copy_keys_default_and_labels(self):
        cfg = config.from_dict(copy.deepcopy(config.DEFAULTS))
        self.assertEqual((cfg.keys["copy_reply"], cfg.keys["copy_output"]), ("S-F4", "S-F5"))
        self.assertEqual(cfg.key_labels["copy_reply"], "Shift+F4")
        self.assertEqual(config.key_label("M-y"), "M-y")


if __name__ == "__main__":
    unittest.main()
