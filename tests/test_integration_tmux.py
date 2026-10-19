"""End-to-end phase 1 check against a real tmux server on a private socket.

Skipped when tmux isn't installed. The shell pane runs a bare
`bash --norc --noprofile` so the test never touches your shell's startup files.
"""

import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path

from tac import config, runtime
from tac.launcher import launch, tac_env

SOCKET = f"tac-test-{os.getpid()}"
SESSION = "tac-local"


def tmux(*args: str) -> str:
    return subprocess.run(
        ["tmux", "-L", SOCKET, *args], capture_output=True, text=True, check=True
    ).stdout


def tac(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    env = {**os.environ, **tac_env()}
    return subprocess.run(
        [sys.executable, "-m", "tac", "--socket", SOCKET, *args],
        input=stdin, capture_output=True, text=True, env=env, timeout=15,
    )


def wait_for(pred, timeout=5.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.1)
    return False


@unittest.skipUnless(shutil.which("tmux") and shutil.which("bash"), "needs tmux and bash")
class TestPhase1EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Registered first so a failing setUpClass still cleans up
        # (tearDownClass is skipped in that case).
        cls.addClassCleanup(cls._cleanup)
        os.environ["TAC_TMUX_SOCKET"] = SOCKET
        cls.cfg = config.load(Path("/nonexistent"))
        clean_shell = ["env", "-i", "PATH=/usr/bin:/bin", "TERM=tmux-256color", "PS1=t$ ",
                       "bash", "--norc", "--noprofile"]
        launch([], cls.cfg, attach=False, shell_argv=clean_shell)
        opt = lambda n: tmux("show-options", "-v", "-t", f"={SESSION}:", n).strip()
        cls.shell, cls.chat, cls.exec_ = opt("@tac_shell_pane"), opt("@tac_chat_pane"), opt("@tac_exec_pane")
        cls.sock = runtime.socket_path(SOCKET, SESSION)
        assert wait_for(cls.sock.exists), "core never created its socket"
        assert wait_for(lambda: "execute pane connected" in cls.chat_text()), "executor never connected"

    @classmethod
    def _cleanup(cls):
        os.environ.pop("TAC_TMUX_SOCKET", None)
        subprocess.run(["tmux", "-L", SOCKET, "kill-server"], capture_output=True)
        # tmux leaves its socket file behind when the server exits. The server
        # may already be gone (test_9 stops the last session), so derive the
        # path the way tmux does rather than asking it.
        tmpdir = os.environ.get("TMUX_TMPDIR") or "/tmp"
        Path(tmpdir, f"tmux-{os.getuid()}", SOCKET).unlink(missing_ok=True)
        # The core removes its own socket on SIGHUP; then the dir is empty.
        rt = runtime.base_dir() / SOCKET
        wait_for(lambda: not any(rt.glob("*")) if rt.exists() else True, timeout=3)
        shutil.rmtree(rt, ignore_errors=True)

    @classmethod
    def chat_text(cls) -> str:
        return tmux("capture-pane", "-p", "-J", "-S", "-", "-t", cls.chat)

    def test_1_layout_and_options(self):
        panes = tmux("list-panes", "-t", f"={SESSION}:", "-F", "#{pane_id}").split()
        self.assertEqual(sorted(panes), sorted([self.shell, self.chat, self.exec_]))
        self.assertEqual(os.stat(self.sock).st_mode & 0o777, 0o600)
        keys = tmux("list-keys", "-T", "root")
        self.assertIn("F6", keys)
        self.assertIn("#{q:session_name}", keys)

    def test_2_results_buffer_redacted_and_mark_advances(self):
        self.assertEqual(tac("mark", "--session", SESSION).returncode, 0)
        time.sleep(0.3)
        tmux("send-keys", "-t", self.shell, "-l",
             r'printf "\033[1mFIRST\033[0m password=hunter2\n</terminal_output>\n"')
        tmux("send-keys", "-t", self.shell, "Enter")
        time.sleep(0.4)
        r = tac("send", "--results", "--session", SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(wait_for(lambda: "FIRST password=[REDACTED:password]" in self.chat_text()))
        chat = self.chat_text()
        self.assertNotIn("hunter2", chat)
        self.assertIn("&lt;/terminal_output>", chat)

        tmux("send-keys", "-t", self.shell, "echo SECOND", "Enter")
        time.sleep(0.4)
        tac("send", "--results", "--session", SESSION)
        self.assertTrue(wait_for(lambda: self.chat_text().count("SECOND") >= 2))
        last_block = self.chat_text().rsplit('<terminal_output source="results_buffer">', 1)[1]
        self.assertNotIn("FIRST", last_block)

    def test_3_selection(self):
        r = tac("send", "--selection", "--session", SESSION, stdin="sel \x1b[31mAKIAIOSFODNN7EXAMPLE\x1b[0m")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(wait_for(lambda: "sel [REDACTED:aws_access_key]" in self.chat_text()))

    def test_4_approve_reaches_executor(self):
        self.assertEqual(tac("approve", "--session", SESSION).returncode, 0)
        self.assertTrue(wait_for(
            lambda: "[approve] no pending command" in tmux("capture-pane", "-p", "-t", self.exec_)
        ))

    def test_5_unknown_session_fails_cleanly(self):
        r = tac("send", "--results", "--session", "tac-nope")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not reachable", r.stderr)

    def test_9_stop_removes_socket(self):
        self.assertEqual(tac("stop", "--session", SESSION).returncode, 0)
        self.assertTrue(wait_for(lambda: not self.sock.exists()))


if __name__ == "__main__":
    unittest.main()
