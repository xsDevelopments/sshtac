"""Unix-socket IPC: newline-delimited JSON objects.

The core is the only server. Short-lived clients (key bindings) send one request
and read one reply. The executor keeps a connection open and receives events the
core pushes to it.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import threading
from pathlib import Path
from typing import Any, Callable

MAX_MESSAGE = 8 * 1024 * 1024  # selections are capped long before this


class IPCError(Exception):
    pass


def encode(msg: dict[str, Any]) -> bytes:
    return json.dumps(msg, ensure_ascii=False).encode() + b"\n"


def decode(line: bytes) -> dict[str, Any]:
    try:
        msg = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise IPCError(f"bad message: {e}") from None
    if not isinstance(msg, dict):
        raise IPCError("message must be a JSON object")
    return msg


def peer_uid(sock: socket.socket) -> int | None:
    if not hasattr(socket, "SO_PEERCRED"):
        return None  # non-Linux: rely on the 0700 directory
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", creds)[1]


class Connection:
    """One accepted client. `send` is thread-safe so the core can push events."""

    def __init__(self, sock: socket.socket, rfile, wfile):
        self.sock = sock
        self.rfile = rfile
        self.wfile = wfile
        self._lock = threading.Lock()
        self.role = "client"
        # Run once the reply to the current request has been written.
        self.after_reply: list[Callable[[], None]] = []

    def send(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self.wfile.write(encode(msg))
            self.wfile.flush()


Handler = Callable[[dict[str, Any], Connection], "dict[str, Any] | None"]


class _RequestHandler(socketserver.StreamRequestHandler):
    server: "_Server"

    def handle(self) -> None:
        uid = peer_uid(self.connection)
        if uid is not None and uid != os.getuid():
            return
        conn = Connection(self.connection, self.rfile, self.wfile)
        try:
            while True:
                line = self.rfile.readline(MAX_MESSAGE + 1)
                if not line:
                    return
                if len(line) > MAX_MESSAGE:
                    conn.send({"ok": False, "error": "message too large"})
                    return
                try:
                    msg = decode(line)
                except IPCError as e:
                    conn.send({"ok": False, "error": str(e)})
                    continue
                reply = self.server.dispatch(msg, conn)
                if reply is not None:
                    conn.send(reply)
                callbacks, conn.after_reply = conn.after_reply, []
                for cb in callbacks:
                    cb()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.server.on_disconnect(conn)


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    dispatch: Handler
    on_disconnect: Callable[[Connection], None]


class Server:
    def __init__(
        self,
        path: Path,
        dispatch: Handler,
        on_disconnect: Callable[[Connection], None] = lambda c: None,
    ):
        self.path = path
        if path.exists() or path.is_symlink():
            if _alive(path):
                raise IPCError(f"another sshtac core is already listening on {path}")
            path.unlink()
        old = os.umask(0o177)
        try:
            self._srv = _Server(str(path), _RequestHandler)
        finally:
            os.umask(old)
        os.chmod(path, 0o600)
        self._srv.dispatch = dispatch
        self._srv.on_disconnect = on_disconnect
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass


def _alive(path: Path) -> bool:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        try:
            s.connect(str(path))
            return True
        except OSError:
            return False


def request(path: Path, msg: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Send one message, wait for one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect(str(path))
        except OSError as e:
            raise IPCError(f"sshtac core not reachable at {path}: {e.strerror or e}") from None
        s.sendall(encode(msg))
        with s.makefile("rb") as f:
            line = f.readline(MAX_MESSAGE + 1)
    if not line:
        raise IPCError("core closed the connection without replying")
    return decode(line)


class Subscription:
    """Persistent client connection (the executor). Read events with `events()`."""

    def __init__(self, path: Path, hello: dict[str, Any], timeout: float = 5.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        try:
            self.sock.connect(str(path))
        except OSError as e:
            self.sock.close()
            raise IPCError(f"sshtac core not reachable at {path}: {e.strerror or e}") from None
        self.rfile = self.sock.makefile("rb")
        self.sock.sendall(encode(hello))
        reply = self._read()
        if reply is None or not reply.get("ok"):
            raise IPCError(f"core refused subscription: {reply}")
        self.hello_reply = reply
        self.sock.settimeout(None)

    def _read(self) -> dict[str, Any] | None:
        line = self.rfile.readline(MAX_MESSAGE + 1)
        return decode(line) if line else None

    def events(self):
        while (msg := self._read()) is not None:
            yield msg

    def close(self) -> None:
        self.rfile.close()
        self.sock.close()
