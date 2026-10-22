"""Configuration: built-in defaults, overlaid by ~/.config/sshtac/config.toml, then env.

Env overrides: SSHTAC_CONFIG (path to the TOML file), SSHTAC_MODEL, SSHTAC_TMUX_SOCKET.
"""

from __future__ import annotations

import copy
import dataclasses
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sshtac.pipeline import EntropySettings, Pipeline, compile_patterns

DEFAULTS: dict[str, Any] = {
    "model": "claude-sonnet-5-5",
    "ai": {
        "effort": "medium",  # low | medium | high | xhigh | max
        "max_tokens": 16_000,
        "timeout": 120.0,  # seconds per API request (the SDK retries twice)
        # Server-side refusal fallback ("default" or "off"): a declined
        # request is re-run on Anthropic's recommended fallback model.
        "fallbacks": "default",
        # Trim the oldest terminal output once a request reaches this size.
        "trim_at_tokens": 400_000,
        # The model's reasoning summary in the chat pane: "auto" shows it when
        # the reply has no visible text, "always", or "never" (not requested).
        "show_reasoning": "auto",
    },
    "tmux": {
        # sshtac runs its own tmux server (`tmux -L sshtac`) so its key bindings and
        # options never touch your normal tmux sessions.
        "socket_name": "sshtac",
        "history_limit": 50_000,
        "mouse": True,  # click to focus, drag to select within a pane, wheel to scroll
        "right_width": "45%",
        "exec_height": "35%",
        # Where copies go: "auto" = your clipboard tool (xclip, xsel, wl-copy,
        # pbcopy) if one is found, plus OSC 52 for terminals that support it;
        # "osc52" = OSC 52 only; "off" = tmux's buffer only; or your own command
        # that reads stdin, e.g. "xclip -selection primary".
        "clipboard": "auto",
    },
    "capture": {"max_chars": 20_000},
    "keys": {
        "send_selection": "F5",  # copy mode
        "send_results": "F6",
        "approve": "F7",
        "reject": "F8",
        "edit": "F9",
        "focus_toggle": "BTab",  # Shift+Tab: jump between the shell and the chat
        "copy_reply": "S-F4",  # copy the AI's last reply to the clipboard
        "copy_output": "S-F5",  # copy shell output since your last command (not sent)
    },
    "policy": {
        # Extra regexes (case-insensitive) over the command's token skeleton.
        "blocked_patterns": [],  # can never be approved
        "destructive_patterns": [],  # need a typed "yes"
    },
    "redaction": {
        "disable": [],  # names of default patterns to turn off
        "patterns": [],  # [{name = "...", regex = "...", flags = "i"}]
        "entropy": {
            "enabled": True,
            "min_length": 32,
            "threshold": 4.3,
            "redact_hex": False,
        },
    },
}

# F-keys alone, Shift+Tab, or any key with a modifier. A bare letter/Enter/Space/
# Tab would be captured from the root table while you type (and "y" could
# approve things); Shift+Tab is free in bash and in sshtac's own panes.
_FKEY = r"F(?:[1-9]|1[0-9]|2[0-4])"
_NAMED = r"Up|Down|Left|Right|Home|End|PageUp|PageDown|PPage|NPage|IC|DC|Insert|Delete|Escape|Enter|Space|Tab|BSpace"
_KEY_RE = re.compile(rf"(?:BTab|(?:[CMS]-)*{_FKEY}|(?:[CMS]-)+(?:{_FKEY}|[A-Za-z0-9]|{_NAMED}))")
# tmux sees Shift+Tab as BTab; a binding written as S-Tab never fires.
_KEY_ALIASES = {"S-Tab": "BTab"}
KEY_LABELS = {"BTab": "Shift+Tab"}


def key_label(key: str) -> str:
    """How to show a tmux key name to a person."""
    if key in KEY_LABELS:
        return KEY_LABELS[key]
    return re.sub(r"^S-(F\d+)$", r"Shift+\1", key)
EXAMPLE = Path(__file__).with_name("config.example.toml")
_SOCKET_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def config_path() -> Path:
    if p := os.environ.get("SSHTAC_CONFIG"):
        return Path(p)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "sshtac" / "config.toml"


def _merge(base: dict[str, Any], over: dict[str, Any], path: str = "") -> None:
    for k, v in over.items():
        where = f"{path}{k}"
        if k not in base:
            raise ConfigError(f"unknown config key: {where}")
        if isinstance(base[k], dict):
            if not isinstance(v, dict):
                raise ConfigError(f"{where} must be a table")
            _merge(base[k], v, where + ".")
        else:
            if type(v) is not type(base[k]) and not (
                isinstance(base[k], float) and isinstance(v, int)
            ):
                raise ConfigError(f"{where} must be {type(base[k]).__name__}")
            base[k] = v


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    model: str
    tmux_socket: str
    history_limit: int
    right_width: str
    exec_height: str
    max_chars: int
    keys: dict[str, str]
    raw: dict[str, Any]
    source: str | None = None  # the file loaded, if any

    @property
    def key_labels(self) -> dict[str, str]:
        return {name: key_label(key) for name, key in self.keys.items()}

    @property
    def ai(self) -> dict[str, Any]:
        return self.raw["ai"]

    def pipeline(self) -> Pipeline:
        r = self.raw["redaction"]
        e = r["entropy"]
        return Pipeline(
            patterns=compile_patterns(r["patterns"], r["disable"]),
            entropy=EntropySettings(
                enabled=e["enabled"],
                min_length=e["min_length"],
                threshold=float(e["threshold"]),
                redact_hex=e["redact_hex"],
            ),
            max_chars=self.max_chars,
        )


def load(path: Path | None = None) -> Config:
    data = copy.deepcopy(DEFAULTS)
    path = path or config_path()
    if path.exists():
        with path.open("rb") as f:
            try:
                _merge(data, tomllib.load(f))
            except tomllib.TOMLDecodeError as e:
                raise ConfigError(f"{path}: {e}") from None
    if m := os.environ.get("SSHTAC_MODEL"):
        data["model"] = m
    if s := os.environ.get("SSHTAC_TMUX_SOCKET"):
        data["tmux"]["socket_name"] = s
    cfg = from_dict(data)
    return dataclasses.replace(cfg, source=str(path)) if path.exists() else cfg


def from_dict(data: dict[str, Any]) -> Config:
    t = data["tmux"]
    if not _SOCKET_RE.fullmatch(t["socket_name"]):
        raise ConfigError("tmux.socket_name must match [A-Za-z0-9_-]+")
    for name, key in data["keys"].items():
        if isinstance(key, str) and key in _KEY_ALIASES:
            key = data["keys"][name] = _KEY_ALIASES[key]
        if not _KEY_RE.fullmatch(key):
            raise ConfigError(
                f"keys.{name} = {key!r}: use a function key (F1-F24), 'BTab' (Shift+Tab) or a "
                f"key with a modifier such as 'M-a', 'C-a' or 'S-F7'"
            )
    used = list(data["keys"].values())
    if dupes := sorted({k for k in used if used.count(k) > 1}):
        raise ConfigError(f"keys: {', '.join(dupes)} is bound to more than one action")
    if not isinstance(t["clipboard"], str) or not t["clipboard"].strip():
        raise ConfigError('tmux.clipboard must be "auto", "osc52", "off" or a command')
    for name in ("right_width", "exec_height"):
        if not re.fullmatch(r"\d{1,3}%|\d{1,4}", t[name]):
            raise ConfigError(f"tmux.{name} must be like '45%' or a cell count")
    ai = data["ai"]
    if ai["effort"] not in ("low", "medium", "high", "xhigh", "max"):
        raise ConfigError("ai.effort must be low, medium, high, xhigh or max")
    if ai["show_reasoning"] not in ("auto", "always", "never"):
        raise ConfigError('ai.show_reasoning must be "auto", "always" or "never"')
    if ai["fallbacks"] not in ("default", "off"):
        raise ConfigError('ai.fallbacks must be "default" or "off"')
    if data["capture"]["max_chars"] < 500:
        raise ConfigError("capture.max_chars must be at least 500")
    cfg = Config(
        model=data["model"],
        tmux_socket=t["socket_name"],
        history_limit=t["history_limit"],
        right_width=t["right_width"],
        exec_height=t["exec_height"],
        max_chars=data["capture"]["max_chars"],
        keys=dict(data["keys"]),
        raw=data,
    )
    for key in ("blocked_patterns", "destructive_patterns"):
        for rx in data["policy"][key]:
            try:
                re.compile(rx)
            except (re.error, TypeError) as e:
                raise ConfigError(f"policy.{key}: bad regex {rx!r}: {e}") from None
    try:
        cfg.pipeline()  # validate user regexes now rather than on first send
    except (ValueError, KeyError, re.error) as e:
        raise ConfigError(f"redaction: {e}") from None
    return cfg
