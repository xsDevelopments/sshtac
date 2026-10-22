"""`sshtac [ssh args...]`: create (or attach to) the tmux session and its three panes.

    ┌──────────────┬─────────┐
    │              │  chat   │   core process
    │ shell / ssh  ├─────────┤
    │              │ execute │   executor process
    └──────────────┴─────────┘

ssh arguments never pass through tmux's argv: tmux treats an argument ending in
';' as a command separator and silently rewrites it. Instead they travel as JSON
in SSHTAC_SSH_ARGV to `sshtac _ssh`, which execs ssh directly.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sys
import time
from pathlib import Path

from sshtac import runtime
from sshtac.config import Config, key_label
from sshtac.tmuxctl import MIN_VERSION, Tmux, TmuxError

# Credentials the core needs. tmux copies these from the launching client's
# environment into the session (update-environment), so a sshtac server started
# earlier without them still gets them; the shell pane's shim removes them.
CREDENTIAL_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE", "ANTHROPIC_BASE_URL")

# ssh options that take a value (from ssh(1)).
_SSH_OPTS_WITH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")


def ssh_destination(args: list[str]) -> str | None:
    """First non-option argument of an ssh command line, or None."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return args[i + 1] if i + 1 < len(args) else None
        if a.startswith("-") and len(a) > 1:
            # Bundled flags like -vvA or -p22: an option needing a value consumes
            # the rest of the word, or the next word if nothing follows.
            for j, ch in enumerate(a[1:], start=1):
                if ch in _SSH_OPTS_WITH_ARG:
                    if j == len(a) - 1:
                        i += 1
                    break
            i += 1
            continue
        return a
    return None


def session_name(ssh_args: list[str]) -> str:
    dest = ssh_destination(ssh_args) if ssh_args else None
    if not dest:
        return "sshtac-local"
    host = dest.rsplit("@", 1)[-1]
    host = re.sub(r"^ssh://", "", host)
    host = re.sub(r"[^A-Za-z0-9_-]+", "-", host).strip("-")[:40]
    return f"sshtac-{host or 'ssh'}"


BANNER_MS = 8000


def reconnect_message(ssh_args: list[str], created: int, now: float | None = None) -> str:
    """Status-line banner shown when `sshtac` re-attaches to a running session
    instead of starting a new one (e.g. one still sitting at a password prompt)."""
    started = time.localtime(created)
    same_day = time.strftime("%Y%m%d", started) == time.strftime("%Y%m%d", time.localtime(now))
    when = time.strftime("%H:%M" if same_day else "%d %b %H:%M", started)
    what = "ssh " + shlex.join(ssh_args) if ssh_args else "local shell"
    if len(what) > 60:
        what = what[:59] + "…"
    msg = (f"sshtac: reconnected to your session from {when} ({what}). "
           "For a fresh start: /quit in the chat, then run sshtac again")
    return msg.replace("#", "##")  # display-message expands formats


def tac_argv() -> list[str]:
    """argv that runs this sshtac from inside tmux (panes and key bindings)."""
    return [sys.executable, "-m", "sshtac"]


def tac_env() -> dict[str, str]:
    """Env needed so `python -m sshtac` finds this package when it isn't installed."""
    pkg_parent = str(Path(__file__).resolve().parent.parent)
    if "site-packages" in pkg_parent or "dist-packages" in pkg_parent:
        return {}
    return {"PYTHONPATH": pkg_parent}


def _shell_cmd(argv: list[str], env: dict[str, str]) -> str:
    """Shell command string for run-shell / copy-pipe. Formats are expanded by
    tmux, so literal '#' must be doubled."""
    parts = [f"{k}={shlex.quote(v)}" for k, v in env.items()]
    cmd = ("env " + " ".join(parts) + " " if parts else "") + shlex.join(argv)
    return cmd.replace("#", "##")


def status_hints(cfg: Config) -> str:
    # tmux trims a too-long status-right from the left, so the most important
    # hint (how to get out) goes last.
    k = cfg.key_labels
    return (
        f"drag+{k['send_selection']} send selection │ {k['send_results']} send output │ "
        f"{k['approve']} approve {k['reject']} reject {k['edit']} edit │ {k['focus_toggle']} shell⇄chat │ "
        f"q leave scroll │ exit: /quit in chat · detach: Ctrl+B d "
    )


def configure_server(tmux: Tmux, cfg: Config) -> None:
    """Look and mouse behaviour. These are global options, which is safe
    because sshtac runs its own tmux server; your normal tmux is untouched."""
    for opt, val in (
        # Click to focus a pane, drag to select inside one pane, wheel to scroll.
        ("mouse", "on" if cfg.raw["tmux"]["mouse"] else "off"),
        # Label panes by role. @sshtac_role is our own option: a remote program can
        # change a pane's title with an escape sequence, but not this.
        ("pane-border-status", "top"),
        ("pane-border-format", "#{?@sshtac_role,[ #{@sshtac_role} ],}"),  # ─[ SHELL ]───
        ("pane-active-border-style", "fg=cyan,bold"),
        ("status-left", " sshtac #{session_name} "),
        ("status-left-length", "40"),
        ("status-right", status_hints(cfg).replace("#", "##")),
        ("status-right-length", "200"),
        ("window-status-format", ""),
        ("window-status-current-format", ""),
    ):
        tmux.run("set-option", "-g", opt, val)
    # tmux's right-click menu offers kill/respawn/swap on any pane; turn it off.
    tmux.run("unbind-key", "-T", "root", "MouseDown3Pane", check=False)


def install_bindings(tmux: Tmux, cfg: Config) -> None:
    """Key bindings live on the dedicated sshtac tmux server only."""
    base = tac_argv() + ["--socket", cfg.tmux_socket]
    env = tac_env()
    k = cfg.keys

    def client(*sub: str) -> str:
        # #{q:session_name} is expanded (and shell-quoted) by tmux at key time.
        return _shell_cmd(base + list(sub), env) + " --session #{q:session_name} >/dev/null 2>&1"

    # Remove what an earlier launch bound, so a key you've since changed in
    # the config stops doing anything.
    previous = tmux.run("show-options", "-gqv", "@sshtac_bound_keys", check=False).split()
    for entry in previous:
        table, _, key = entry.partition(":")
        if table and key:
            tmux.run("unbind-key", "-T", table, key, check=False)
    bound: list[str] = []

    for key, sub in (
        (k["send_results"], ("send", "--results")),
        (k["approve"], ("approve",)),
        (k["reject"], ("reject",)),
        (k["edit"], ("edit",)),
    ):
        tmux.run("bind-key", "-T", "root", key, "run-shell", "-b", client(*sub))
        bound.append(f"root:{key}")
    # pipe-and-cancel (not copy-pipe): sending adds nothing to tmux's paste
    # buffers; the selection goes only to sshtac's stdin.
    for table in ("copy-mode", "copy-mode-vi"):
        tmux.run(
            "bind-key", "-T", table, k["send_selection"],
            "send-keys", "-X", "pipe-and-cancel", client("send", "--selection"),
        )
        bound.append(f"{table}:{k['send_selection']}")
        # Releasing a mouse drag copies as usual but keeps the selection
        # highlighted (tmux's default clears it), so it can then be sent.
        tmux.run("bind-key", "-T", table, "MouseDragEnd1Pane", "send-keys", "-X", "copy-pipe-no-clear")
    tmux.run(
        "bind-key", "-T", "root", k["send_selection"], "display-message",
        f"Select text first (drag with the mouse), then press {key_label(k['send_selection'])}",
    )
    bound.append(f"root:{k['send_selection']}")
    # Toggle focus between the shell and the chat. select-pane doesn't expand
    # formats in -t, so go through run-shell, which does.
    tm = shlex.quote(tmux.binary).replace("#", "##")
    sock = shlex.quote(cfg.tmux_socket)
    go = lambda opt: f"run-shell '{tm} -L {sock} select-pane -t #{{{opt}}}'"
    tmux.run(
        "bind-key", "-T", "root", k["focus_toggle"], "if-shell", "-F",
        "#{==:#{pane_id},#{@sshtac_shell_pane}}", go("@sshtac_chat_pane"), go("@sshtac_shell_pane"),
    )
    bound.append(f"root:{k['focus_toggle']}")
    tmux.run("set-option", "-g", "@sshtac_bound_keys", " ".join(bound))


def _check_tmux(tmux: Tmux) -> None:
    v = tmux.version()
    if v < MIN_VERSION:
        raise TmuxError(f"tmux {v[0]}.{v[1]} is too old; sshtac needs {MIN_VERSION[0]}.{MIN_VERSION[1]}+")


def create_session(
    tmux: Tmux, cfg: Config, name: str, ssh_args: list[str], shell_argv: list[str] | None = None
) -> None:
    cols, rows = shutil.get_terminal_size((200, 50))
    env = tac_env()
    env_args = [a for k, v in env.items() for a in ("-e", f"{k}={v}")]
    sshtac = tac_argv() + ["--socket", cfg.tmux_socket]

    new = ["new-session", "-d", "-s", name, "-x", str(cols), "-y", str(rows), "-P", "-F", "#{pane_id}"]
    if ssh_args:
        new += env_args + ["-e", "SSHTAC_SSH_ARGV=" + json.dumps(ssh_args)] + sshtac + ["_ssh"]
    elif shell_argv:
        new += shell_argv  # tests only: fixed argv, never user input
    else:
        new += env_args + sshtac + ["_shell"]
    shell = tmux.run(*new).strip()

    chat = tmux.run(
        "split-window", "-h", "-d", "-t", shell, "-l", cfg.right_width, "-P", "-F", "#{pane_id}",
        *env_args, *sshtac, "core", "--session", name,
    ).strip()
    execp = tmux.run(
        "split-window", "-v", "-d", "-t", chat, "-l", cfg.exec_height, "-P", "-F", "#{pane_id}",
        *env_args, *sshtac, "exec", "--session", name,
    ).strip()

    tmux.set_option(name, "@sshtac_session", "1")
    tmux.set_option(name, "@sshtac_ssh_args", json.dumps(ssh_args))
    tmux.set_option(name, "@sshtac_shell_pane", shell)
    tmux.set_option(name, "@sshtac_chat_pane", chat)
    tmux.set_option(name, "@sshtac_exec_pane", execp)
    decorate_session(tmux, name)
    tmux.select_pane(shell)


def decorate_session(tmux: Tmux, name: str) -> list[str]:
    """Per-pane settings, safe to re-apply on every launch. Returns problems
    found (e.g. a pane that no longer exists) instead of raising."""
    problems = []
    panes = {role: tmux.get_option(name, f"@sshtac_{role}_pane") for role in ("shell", "chat", "exec")}
    labels = {"shell": "SHELL", "chat": "AI CHAT — type here", "exec": "EXECUTE"}
    for role, pane in panes.items():
        if not pane:
            problems.append(f"@sshtac_{role}_pane is not set")
            continue
        try:
            tmux.set_pane_option(pane, "@sshtac_role", labels[role])
        except TmuxError as e:
            problems.append(f"{role} pane {pane}: {e}")
    shell = panes["shell"]
    if shell:
        # Keep a dead ssh pane on screen instead of closing it, so a finished
        # session can't silently turn into a different pane receiving pastes.
        tmux.set_pane_option(shell, "remain-on-exit", "on", check=False)
        tmux.set_pane_option(
            shell,
            "remain-on-exit-format",
            "[sshtac] shell exited (#{pane_dead_status}). Reconnect: prefix + : respawn-pane   End: sshtac stop",
            check=False,
        )
    return problems


def launch(
    ssh_args: list[str],
    cfg: Config,
    attach: bool = True,
    shell_argv: list[str] | None = None,
    prompt_for_key: bool = False,
) -> str:
    tmux = Tmux(cfg.tmux_socket)
    _check_tmux(tmux)
    runtime.server_dir(cfg.tmux_socket)
    name = session_name(ssh_args)
    banner = None
    if tmux.has_session(name):
        print(f"sshtac: attaching to existing session {name}", file=sys.stderr)
        problems = decorate_session(tmux, name)
        if problems:
            raise TmuxError(
                f"session {name} looks broken ({'; '.join(problems)}). "
                f"End it with `sshtac stop --session {name}` and start again."
            )
        banner = _reconnect_banner(tmux, name)
    else:
        if prompt_for_key:
            ask_for_key()
        # Start the server with our history-limit as the global default so the
        # shell pane gets it too. A server needs a session to stay alive, so the
        # option is set in the same command list as the session creation.
        if not tmux.list_sessions():
            tmux.run("start-server", ";", "set-option", "-g", "history-limit", str(cfg.history_limit),
                     ";", "new-session", "-d", "-s", "_tac_boot")
        else:
            tmux.run("set-option", "-g", "history-limit", str(cfg.history_limit))
        _pass_credentials(tmux)
        try:
            create_session(tmux, cfg, name, ssh_args, shell_argv)
        except BaseException:
            # Don't leave a half-built session behind for the next launch to
            # attach to, whatever stopped us (an error, Ctrl+C, ...).
            if tmux.has_session(name):
                tmux.kill_session(name)
            raise
        finally:
            if tmux.has_session("_tac_boot"):
                tmux.kill_session("_tac_boot")
    # Server-wide look and key bindings: re-applied on every launch, so a
    # server whose setup was interrupted is repaired by running sshtac again.
    configure_server(tmux, cfg)
    install_bindings(tmux, cfg)
    if attach:
        env = dict(os.environ)
        if env.pop("TMUX", None):
            print("sshtac: starting inside tmux; nesting a separate sshtac tmux server", file=sys.stderr)
        os.execvpe(tmux.binary, attach_argv(tmux, name, banner), env)
    return name


def attach_argv(tmux: Tmux, name: str, banner: str | None = None) -> list[str]:
    argv = tmux.argv("attach-session", "-t", f"={name}")
    if banner:
        # Runs once the client is attached, so the message goes to it.
        argv += [";", "display-message", "-d", str(BANNER_MS), banner]
    return argv


def _reconnect_banner(tmux: Tmux, name: str) -> str | None:
    try:
        created = int(tmux.display(f"={name}:", "#{session_created}"))
        raw = tmux.get_option(name, "@sshtac_ssh_args")
        args = json.loads(raw) if raw else []
    except (TmuxError, ValueError):
        return None
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        args = []
    return reconnect_message(args, created)


def has_env_credentials(env: dict[str, str] | None = None) -> bool:
    env = os.environ if env is None else env
    return any(env.get(v) for v in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_PROFILE"))


def has_credentials(env: dict[str, str] | None = None) -> bool:
    if has_env_credentials(env):
        return True
    return (Path.home() / ".config" / "anthropic").is_dir()  # `ant auth login` profile


def ask_for_key(getpass_fn=None, input_fn=None) -> None:
    """Find an API key for a new session, in order: this terminal's environment,
    sshtac's key file (~/.config/sshtac/api_key), an `ant auth login` profile, or a
    hidden prompt (with an offer to save it to the key file).

    The key ends up in this process's environment only; tmux copies it to the
    new session (update-environment), and the shell and execute panes remove it
    again. It is never put on a command line."""
    from sshtac import apikey

    if os.environ.get("SSHTAC_TEST_FAKE_MODEL") == "1" or has_env_credentials():
        return
    try:
        key = apikey.read()
    except apikey.KeyFileError as e:
        print(f"sshtac: not using the API key file: {e}", file=sys.stderr)
        key = None
    if key:
        os.environ["ANTHROPIC_API_KEY"] = key
        return
    if has_credentials() or not sys.stdin.isatty():
        return
    import getpass

    getpass_fn = getpass_fn or getpass.getpass
    input_fn = input_fn or input
    print("sshtac: no Anthropic API key found.", file=sys.stderr)
    key = getpass_fn("Paste your API key (hidden), or press Enter to run without AI: ").strip()
    if not key:
        print("sshtac: starting without AI (chat will say it is disabled)", file=sys.stderr)
        return
    if not key.startswith("sk-ant-"):
        print("sshtac: warning: that doesn't look like an Anthropic key (they start with sk-ant-)", file=sys.stderr)
    os.environ["ANTHROPIC_API_KEY"] = key
    where = apikey.path()
    if input_fn(f"Save it to {where} (readable only by you) so sshtac won't ask again? [y/N] ").strip().lower() in ("y", "yes"):
        try:
            apikey.write(key)
            print(f"sshtac: saved. Remove it any time with: sshtac config --remove-key", file=sys.stderr)
        except OSError as e:
            print(f"sshtac: could not save the key: {e}", file=sys.stderr)


def _pass_credentials(tmux: Tmux) -> None:
    current = tmux.run("show-options", "-gv", "update-environment").split()
    for var in CREDENTIAL_VARS:
        if var not in current:
            tmux.run("set-option", "-ga", "update-environment", var)


def _scrub_env() -> None:
    """The shell pane must not inherit sshtac's plumbing or the API credentials:
    anything in its environment can end up in captured output."""
    for var in (*CREDENTIAL_VARS, "PYTHONPATH", "SSHTAC_SSH_ARGV"):
        os.environ.pop(var, None)


def exec_shell() -> int:
    """`sshtac _shell`: the shell pane's process for a local session. Runs your
    login shell, as tmux would, minus the scrubbed variables."""
    _scrub_env()
    shell = os.environ.get("SHELL") or "/bin/sh"
    os.execv(shell, ["-" + os.path.basename(shell)])


def exec_ssh() -> int:
    """`sshtac _ssh`: the shell pane's process when ssh args were given."""
    raw = os.environ.pop("SSHTAC_SSH_ARGV", None)
    if raw is None:
        print("sshtac _ssh: SSHTAC_SSH_ARGV not set", file=sys.stderr)
        return 2
    args = json.loads(raw)
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        print("sshtac _ssh: SSHTAC_SSH_ARGV must be a JSON list of strings", file=sys.stderr)
        return 2
    _scrub_env()
    os.execvp("ssh", ["ssh", *args])
