import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from sshtac import ipc, runtime


class TestRuntimeDir(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_creates_0700(self):
        d = runtime.ensure_dir(self.base / "sshtac")
        self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)

    def test_existing_ok(self):
        runtime.ensure_dir(self.base / "sshtac")
        runtime.ensure_dir(self.base / "sshtac")

    def test_rejects_loose_permissions(self):
        d = self.base / "sshtac"
        d.mkdir(mode=0o755)
        os.chmod(d, 0o755)
        with self.assertRaises(runtime.RuntimeDirError):
            runtime.ensure_dir(d)

    def test_rejects_symlink(self):
        real = self.base / "elsewhere"
        real.mkdir(mode=0o700)
        (self.base / "sshtac").symlink_to(real)
        with self.assertRaises(runtime.RuntimeDirError):
            runtime.ensure_dir(self.base / "sshtac")

    def test_session_names(self):
        p = runtime.socket_path("sshtac", "sshtac-web-01", self.base / "sshtac")
        self.assertEqual(p, self.base / "sshtac" / "sshtac" / "sshtac-web-01.sock")
        for bad in ("../x", "a b", "", "x;y", "a/b", "x" * 65):
            with self.assertRaises(ValueError, msg=bad):
                runtime.socket_path("sshtac", bad, self.base / "sshtac")
            with self.assertRaises(ValueError, msg=bad):
                runtime.socket_path(bad, "sshtac-local", self.base / "sshtac")

    def test_same_session_on_two_servers_does_not_collide(self):
        # Regression: a test server's sshtac-local used to share a socket with a
        # live sshtac-local on the real server.
        a = runtime.socket_path("sshtac", "sshtac-local", self.base / "sshtac")
        b = runtime.socket_path("sshtac-test-1", "sshtac-local", self.base / "sshtac")
        self.assertNotEqual(a, b)
        for d in (a.parent, b.parent):
            self.assertEqual(os.stat(d).st_mode & 0o777, 0o700)


class TestIPC(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "t.sock"
        self.events: list[ipc.Connection] = []
        self.disconnected = threading.Event()

        def dispatch(msg, conn):
            if msg.get("cmd") == "echo":
                return {"ok": True, "got": msg}
            if msg.get("cmd") == "sub":
                self.events.append(conn)
                return {"ok": True}
            return {"ok": False, "error": "unknown"}

        self.server = ipc.Server(self.path, dispatch, lambda c: self.disconnected.set())
        self.server.start()

    def tearDown(self):
        self.server.close()
        self.tmp.cleanup()

    def test_socket_mode(self):
        self.assertEqual(os.stat(self.path).st_mode & 0o777, 0o600)

    def test_request_reply_unicode(self):
        reply = ipc.request(self.path, {"cmd": "echo", "text": "héllo\n✓"})
        self.assertEqual(reply["got"]["text"], "héllo\n✓")

    def test_bad_json_gets_error_not_crash(self):
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(str(self.path))
            s.sendall(b"{not json\n")
            self.assertIn(b'"ok": false', s.makefile("rb").readline())
        self.assertTrue(ipc.request(self.path, {"cmd": "echo"})["ok"])

    def test_non_object_rejected(self):
        with socket.socket(socket.AF_UNIX) as s:
            s.connect(str(self.path))
            s.sendall(b"[1,2]\n")
            self.assertIn(b"JSON object", s.makefile("rb").readline())

    def test_subscription_receives_push(self):
        sub = ipc.Subscription(self.path, {"cmd": "sub"})
        try:
            self.events[0].send({"event": "approve"})
            self.assertEqual(next(sub.events()), {"event": "approve"})
        finally:
            sub.close()
        self.assertTrue(self.disconnected.wait(2))

    def test_second_server_refused_while_alive(self):
        with self.assertRaises(ipc.IPCError):
            ipc.Server(self.path, lambda m, c: None)

    def test_stale_socket_replaced(self):
        self.server.close()
        stale = socket.socket(socket.AF_UNIX)
        stale.bind(str(self.path))
        stale.close()  # file exists, nobody listening
        self.server = ipc.Server(self.path, lambda m, c: {"ok": True})
        self.server.start()
        self.assertTrue(ipc.request(self.path, {"cmd": "x"})["ok"])

    def test_unreachable(self):
        with self.assertRaises(ipc.IPCError):
            ipc.request(Path(self.tmp.name) / "nope.sock", {"cmd": "x"})


if __name__ == "__main__":
    unittest.main()
