import io
import os
import pty
import threading
import unittest

from sshtac.ui import read_secret


class TestReadSecret(unittest.TestCase):
    def read(self, typed: bytes):
        """read_secret on a real terminal, with `typed` as the keystrokes."""
        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        out = io.StringIO()
        result: dict = {}

        def run():
            try:
                result["value"] = read_secret("PORT: ", fd=slave, out=out)
            except BaseException as e:  # noqa: BLE001  (the test checks which)
                result["error"] = e

        t = threading.Thread(target=run)
        t.start()
        os.write(master, typed)
        t.join(5)
        self.assertFalse(t.is_alive(), "read_secret never returned")
        return result, out.getvalue()

    def test_shows_a_star_per_character_never_the_text(self):
        result, shown = self.read("22é2\r".encode())
        self.assertEqual(result["value"], "22é2")
        self.assertEqual(shown, "PORT: ****\n")

    def test_backspace_and_ctrl_u_edit(self):
        result, _ = self.read(b"99\x7f\x7f12\x15abc\x7fd\r")
        self.assertEqual(result["value"], "abd")

    def test_arrow_keys_are_ignored(self):
        result, shown = self.read(b"2\x1b[A\x1b[D2\r")
        self.assertEqual(result["value"], "22")
        self.assertEqual(shown, "PORT: **\n")

    def test_ctrl_d_on_empty_line_is_eof(self):
        result, _ = self.read(b"\x04")
        self.assertIsInstance(result["error"], EOFError)

    def test_echo_is_restored(self):
        import termios

        master, slave = pty.openpty()
        self.addCleanup(os.close, master)
        self.addCleanup(os.close, slave)
        before = termios.tcgetattr(slave)
        os.write(master, b"x\r")
        read_secret("", fd=slave, out=io.StringIO())
        self.assertEqual(termios.tcgetattr(slave), before)


if __name__ == "__main__":
    unittest.main()
