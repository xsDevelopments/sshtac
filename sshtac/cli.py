"""Command-line entry point.

    sshtac [ssh args...]          start or attach (no args: a local shell)
    sshtac -- <ssh args...>       same, when the host is named like a subcommand
    sshtac stop [--session S]     end a sshtac session
    sshtac config                 show which config file is used, and check it
    sshtac config --init          create ~/.config/sshtac/config.toml from the example
    sshtac config --example       print the documented example config
    sshtac config --set-key       save your API key to ~/.config/sshtac/api_key (private file)
    sshtac config --remove-key    delete that file
    sshtac report [LOG|--latest] [--full] [-o FILE]
                                  Markdown incident timeline of one audit log (default: latest)
    sshtac review [LOGS...|--all] replay proposed commands through the current policy and list
                                  where it disagrees with the AI's risk label (default: all logs)

Internal (used by panes and key bindings):
    sshtac core|exec --session S
    sshtac send --selection|--results --session S
    sshtac approve|reject|edit --session S
    sshtac _ssh | _shell
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from sshtac import __version__

CLIENT_CMDS = {"send", "approve", "reject", "edit", "mark"}
INTERNAL = {"core", "exec", "stop", "config", "report", "review", "_ssh", "_shell"} | CLIENT_CMDS
MAX_SELECTION_READ = 2 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sshtac", add_help=False)
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
    c = sub.add_parser("config")
    g = c.add_mutually_exclusive_group()
    g.add_argument("--init", action="store_true")
    g.add_argument("--example", action="store_true")
    g.add_argument("--set-key", action="store_true")
    g.add_argument("--remove-key", action="store_true")
    r = sub.add_parser("report")
    g = r.add_mutually_exclusive_group()
    g.add_argument("log", nargs="?")
    g.add_argument("--latest", action="store_true")
    r.add_argument("--full", action="store_true")
    r.add_argument("-o", "--output")
    v = sub.add_parser("review")
    g = v.add_mutually_exclusive_group()
    g.add_argument("logs", nargs="*", default=[])
    g.add_argument("--all", action="store_true")
    sub.add_parser("_ssh")
    sub.add_parser("_shell")
    return p


def _load_config(socket: str | None):
    from sshtac import config

    cfg = config.load()
    if socket:
        cfg = config.from_dict({**cfg.raw, "tmux": {**cfg.raw["tmux"], "socket_name": socket}})
    return cfg


def _resolve_session(tmux, given: str | None) -> str:
    if given:
        return given
    # Inside a sshtac pane? Only trust TMUX_PANE if $TMUX points at the sshtac server;
    # a pane id from your normal tmux server means nothing on ours.
    tmux_env = os.environ.get("TMUX", "").split(",")[0]
    pane = os.environ.get("TMUX_PANE")
    if pane and os.path.basename(tmux_env) == tmux.socket_name:
        name = tmux.display(pane, "#{session_name}")
        if name:
            return name
    sessions = [s for s in tmux.list_sessions() if tmux.get_option(s, "@sshtac_session")]
    if len(sessions) == 1:
        return sessions[0]
    if not sessions:
        raise SystemExit("sshtac: no sshtac session is running")
    raise SystemExit(f"sshtac: several sshtac sessions running, pick one with --session: {', '.join(sessions)}")


def _client(args, cfg) -> int:
    from sshtac import ipc, runtime
    from sshtac.tmuxctl import Tmux

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
        err = f"sshtac: {reply.get('error', 'request failed')}"
        print(err, file=sys.stderr)
        tmux.display_message(f"={session}:", err)
        return 1
    return 0


def _stop(args, cfg) -> int:
    from sshtac.tmuxctl import Tmux

    tmux = Tmux(cfg.tmux_socket)
    session = _resolve_session(tmux, args.session)
    tmux.kill_session(session)
    print(f"sshtac: stopped {session}")
    return 0


def _key_status() -> str:
    from sshtac import apikey
    from sshtac.launcher import has_env_credentials

    if has_env_credentials():
        return "API key: from this terminal's environment (takes priority over the key file)"
    p = apikey.path()
    try:
        key = apikey.read()
    except apikey.KeyFileError as e:
        return f"API key: PROBLEM: {e}"
    if key:
        return f"API key: {p} (private, owner-only)"
    return f"API key: not set; sshtac will ask (save one with: sshtac config --set-key)"


def _config_cmd(args) -> int:
    from sshtac import apikey, config

    path = config.config_path()
    if args.set_key:
        import getpass

        p = apikey.path()
        if p.exists() and input(f"Replace the key in {p}? [y/N] ").strip().lower() not in ("y", "yes"):
            return 1
        key = getpass.getpass("Paste your API key (hidden): ").strip()
        if not key:
            print("sshtac: nothing saved", file=sys.stderr)
            return 1
        if not key.startswith("sk-ant-"):
            print("sshtac: warning: that doesn't look like an Anthropic key (they start with sk-ant-)", file=sys.stderr)
        print(f"sshtac: saved to {apikey.write(key)} (readable only by you)")
        return 0
    if args.remove_key:
        p = apikey.path()
        print(f"sshtac: removed {p}" if apikey.remove() else f"sshtac: there was no key file at {p}")
        return 0
    if args.example:
        print(config.EXAMPLE.read_text(), end="")
        return 0
    if args.init:
        if path.exists():
            print(f"sshtac: {path} already exists; not overwriting it", file=sys.stderr)
            return 1
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(config.EXAMPLE.read_text())
        print(f"sshtac: wrote {path}; edit it, then restart sshtac")
        return 0
    print(f"config file: {path} ({'found' if path.exists() else 'not found, using built-in defaults'})")
    try:
        cfg = config.load()
    except config.ConfigError as e:
        print(f"sshtac: config error: {e}", file=sys.stderr)
        return 1
    k = cfg.keys
    print(f"model: {cfg.model}   effort: {cfg.ai['effort']}   tmux server: -L {cfg.tmux_socket}")
    print("keys:  " + "  ".join(f"{name}={key}" for name, key in k.items()))
    print(_key_status())
    print("config OK")
    return 0


def _report_cmd(args) -> int:
    from sshtac import auditreport

    try:
        path = Path(args.log) if args.log else auditreport.latest()
        text = auditreport.render(auditreport.load(path), full=args.full)
    except OSError as e:
        print(f"sshtac: {e}", file=sys.stderr)
        return 1
    if not args.output:
        sys.stdout.write(text)
        return 0
    # The report quotes the session, so keep it as private as the log itself.
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"sshtac: wrote {args.output} (from {path.name})", file=sys.stderr)
    return 0


def _review_cmd(args) -> int:
    from sshtac import auditreport, config, policy, review

    try:
        cfg = config.load()
    except config.ConfigError as e:
        print(f"sshtac: config error: {e}", file=sys.stderr)
        return 1
    pol = cfg.raw["policy"]
    classifier = policy.Classifier(pol["blocked_patterns"], pol["destructive_patterns"])
    paths = [Path(p) for p in args.logs] or auditreport.log_files()
    if not paths:
        print(f"sshtac: no audit logs in {auditreport.state_dir()}", file=sys.stderr)
        return 1
    extra = len(pol["blocked_patterns"]) + len(pol["destructive_patterns"])
    note = f" (plus {extra} pattern(s) from {cfg.source})" if extra else ""
    try:
        sys.stdout.write(review.run(paths, classifier, note))
    except OSError as e:
        print(f"sshtac: {e}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    if argv[:1] == ["--version"]:
        print(f"sshtac {__version__}")
        return 0

    first = argv[0] if argv else None
    if first == "--socket" and len(argv) > 2:
        first = argv[2]
    if first not in INTERNAL:
        ssh_args = argv[1:] if argv[:1] == ["--"] else argv
        from sshtac.config import ConfigError, load
        from sshtac.launcher import launch
        from sshtac.runtime import RuntimeDirError
        from sshtac.tmuxctl import TmuxError

        try:
            launch(ssh_args, load(), prompt_for_key=True)
        except (ConfigError, RuntimeDirError, TmuxError) as e:
            print(f"sshtac: {e}", file=sys.stderr)
            return 1
        except KeyboardInterrupt:
            print("\nsshtac: interrupted; nothing was left running", file=sys.stderr)
            return 130
        except Exception as e:
            if os.environ.get("SSHTAC_DEBUG") == "1":
                raise
            print(f"sshtac: unexpected error: {type(e).__name__}: {e}", file=sys.stderr)
            print("sshtac: run with SSHTAC_DEBUG=1 for details", file=sys.stderr)
            return 1
        return 0

    args = _parser().parse_args(argv)
    if args.cmd == "config":
        return _config_cmd(args)
    if args.cmd == "report":
        return _report_cmd(args)
    if args.cmd == "review":
        return _review_cmd(args)
    if args.cmd == "_ssh":
        from sshtac.launcher import exec_ssh

        return exec_ssh()
    if args.cmd == "_shell":
        from sshtac.launcher import exec_shell

        return exec_shell()
    cfg = _load_config(args.socket)
    if args.cmd == "core":
        from sshtac.core import main as core_main

        return core_main(args.session, cfg)
    if args.cmd == "exec":
        from sshtac.executor import main as exec_main

        return exec_main(args.session, cfg)
    if args.cmd == "stop":
        return _stop(args, cfg)
    return _client(args, cfg)
