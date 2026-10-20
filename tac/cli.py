"""Command-line entry point.

    tac [ssh args...]          start or attach (no args: a local shell)
    tac -- <ssh args...>       same, when the host is named like a subcommand
    tac stop [--session S]     end a tac session

Internal (used by panes and key bindings):
    tac core|exec --session S
    tac send --selection|--results --session S
    tac approve|reject|edit --session S
    tac _ssh | _shell
"""

from __future__ import annotations

import argparse
import os
import sys

from tac import __version__

CLIENT_CMDS = {"send", "approve", "reject", "edit", "mark"}
INTERNAL = {"core", "exec", "stop", "_ssh", "_shell"} | CLIENT_CMDS
MAX_SELECTION_READ = 2 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tac", add_help=False)
    p.add_argument("--socket", help=argparse.SUPPRESS)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("core", "exec"):
        sub.add_parser(name).add_argument("--session", required=True)
    s = sub.add_parser("send")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--selection", action="store_true")
    g.add_argument("--results", action="store_true")
    s.add_argument("--session")
    for name in ("approve", "reject", "edit", "mark", "stop"):
        sub.add_parser(name).add_argument("--session")
    sub.add_parser("_ssh")
    sub.add_parser("_shell")
    return p


def _load_config(socket: str | None):
    from tac import config

    cfg = config.load()
    if socket:
        cfg = config.from_dict({**cfg.raw, "tmux": {**cfg.raw["tmux"], "socket_name": socket}})
    return cfg


def _resolve_session(tmux, given: str | None) -> str:
    if given:
        return given
    # Inside a tac pane? Only trust TMUX_PANE if $TMUX points at the tac server;
    # a pane id from your normal tmux server means nothing on ours.
    tmux_env = os.environ.get("TMUX", "").split(",")[0]
    pane = os.environ.get("TMUX_PANE")
    if pane and os.path.basename(tmux_env) == tmux.socket_name:
        name = tmux.display(pane, "#{session_name}")
        if name:
            return name
    sessions = [s for s in tmux.list_sessions() if tmux.get_option(s, "@tac_session")]
    if len(sessions) == 1:
        return sessions[0]
    if not sessions:
        raise SystemExit("tac: no tac session is running")
    raise SystemExit(f"tac: several tac sessions running, pick one with --session: {', '.join(sessions)}")


def _client(args, cfg) -> int:
    from tac import ipc, runtime
    from tac.tmuxctl import Tmux

    tmux = Tmux(cfg.tmux_socket)
    session = _resolve_session(tmux, args.session)
    if args.cmd == "send":
        if args.selection:
            data = sys.stdin.buffer.read(MAX_SELECTION_READ + 1)
            if len(data) > MAX_SELECTION_READ:
                half = MAX_SELECTION_READ // 2
                data = data[:half] + b"\n[... selection too large, middle dropped ...]\n" + data[-half:]
            msg = {"cmd": "send", "source": "selection", "text": data.decode("utf-8", errors="replace")}
        else:
            msg = {"cmd": "send", "source": "results_buffer"}
    else:
        msg = {"cmd": args.cmd}
    try:
        reply = ipc.request(runtime.socket_path(cfg.tmux_socket, session), msg)
    except ipc.IPCError as e:
        reply = {"ok": False, "error": str(e)}
    if not reply.get("ok"):
        err = f"tac: {reply.get('error', 'request failed')}"
        print(err, file=sys.stderr)
        tmux.display_message(f"={session}:", err)
        return 1
    return 0


def _stop(args, cfg) -> int:
    from tac.tmuxctl import Tmux

    tmux = Tmux(cfg.tmux_socket)
    session = _resolve_session(tmux, args.session)
    tmux.kill_session(session)
    print(f"tac: stopped {session}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    if argv[:1] == ["--version"]:
        print(f"tac {__version__}")
        return 0

    first = argv[0] if argv else None
    if first == "--socket" and len(argv) > 2:
        first = argv[2]
    if first not in INTERNAL:
        ssh_args = argv[1:] if argv[:1] == ["--"] else argv
        from tac.config import ConfigError, load
        from tac.launcher import launch
        from tac.runtime import RuntimeDirError
        from tac.tmuxctl import TmuxError

        try:
            launch(ssh_args, load(), prompt_for_key=True)
        except (ConfigError, RuntimeDirError, TmuxError) as e:
            print(f"tac: {e}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\ntac: interrupted; nothing was left running", file=sys.stderr)
            return 130
        except Exception as e:
            if os.environ.get("TAC_DEBUG") == "1":
                raise
            print(f"tac: unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
            print("tac: run with TAC_DEBUG=1 for details", file=sys.stderr)
            return 1
        return 0

    args = _parser().parse_args(argv)
    if args.cmd == "_ssh":
        from tac.launcher import exec_ssh

        return exec_ssh()
    if args.cmd == "_shell":
        from tac.launcher import exec_shell

        return exec_shell()
    cfg = _load_config(args.socket)
    if args.cmd == "core":
        from tac.core import main as core_main

        return core_main(args.session, cfg)
    if args.cmd == "exec":
        from tac.executor import main as exec_main

        return exec_main(args.session, cfg)
    if args.cmd == "stop":
        return _stop(args, cfg)
    return _client(args, cfg)
