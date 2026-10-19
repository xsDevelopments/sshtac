"""Configuration: built-in defaults, overlaid by ~/.config/tac/config.toml, then env.

Env overrides: TAC_CONFIG (path to the TOML file), TAC_MODEL, TAC_TMUX_SOCKET.
"""

from __future__ import annotations

import copy
import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tac.pipeline import EntropySettings, Pipeline, compile_patterns

DEFAULTS: dict[str, Any] = {
    "model": "claude-sonnet-5-5",
    "tmux": {
        # tac runs its own tmux server (`tmux -L tac`) so its key bindings and
        # options never touch your normal tmux sessions.
        "socket_name": "tac",
        "history_limit": 50_000,
        "right_width": "45%",
        "exec_height": "35%",
    },
    "capture": {"max_chars": 20_000},
    "keys": {
        "send_selection": "F5",  # copy mode
        "send_results": "F6",
        "approve": "F7",
        "reject": "F8",
        "edit": "F9",
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

_KEY_RE = re.compile(r"[A-Za-z0-9-]{1,32}")
_SOCKET_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


def config_path() -> Path:
    if p := os.environ.get("TAC_CONFIG"):
        return Path(p)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "tac" / "config.toml"


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
    if m := os.environ.get("TAC_MODEL"):
        data["model"] = m
    if s := os.environ.get("TAC_TMUX_SOCKET"):
        data["tmux"]["socket_name"] = s
    return from_dict(data)


def from_dict(data: dict[str, Any]) -> Config:
    t = data["tmux"]
    if not _SOCKET_RE.fullmatch(t["socket_name"]):
        raise ConfigError("tmux.socket_name must match [A-Za-z0-9_-]+")
    for name, key in data["keys"].items():
        if not _KEY_RE.fullmatch(key):
            raise ConfigError(f"keys.{name}: not a tmux key name: {key!r}")
    for name in ("right_width", "exec_height"):
        if not re.fullmatch(r"\d{1,3}%|\d{1,4}", t[name]):
            raise ConfigError(f"tmux.{name} must be like '45%' or a cell count")
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
    try:
        cfg.pipeline()  # validate user regexes now rather than on first send
    except (ValueError, KeyError, re.error) as e:
        raise ConfigError(f"redaction: {e}") from None
    return cfg
