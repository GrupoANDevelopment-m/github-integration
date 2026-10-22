"""Canonical filesystem paths for Goodware.

All paths are derived from the installed package location by default and can be
overridden for containers, tests, and deployments through environment variables.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Union

PathLike = Union[str, os.PathLike[str]]


def _configured_path(env_name: str, default: Path) -> Path:
    value = os.environ.get(env_name)
    return Path(value).expanduser().resolve() if value else default.expanduser().resolve()


ROOT_DIR = _configured_path(
    "GOODWARE_ROOT",
    Path(__file__).resolve().parents[2],
)
DATA_DIR = _configured_path("GOODWARE_DATA_DIR", ROOT_DIR / "data")
CONFIG_DIR = _configured_path("GOODWARE_CONFIG_DIR", ROOT_DIR / "config")
LOG_DIR = _configured_path("GOODWARE_LOG_DIR", ROOT_DIR / "logs")
QUARANTINE_DIR = _configured_path("GOODWARE_QUARANTINE_DIR", ROOT_DIR / "quarantine")


def root_path(*parts: PathLike) -> Path:
    return ROOT_DIR.joinpath(*parts)


def data_path(*parts: PathLike) -> Path:
    return DATA_DIR.joinpath(*parts)


def config_path(*parts: PathLike) -> Path:
    return CONFIG_DIR.joinpath(*parts)


def log_path(*parts: PathLike) -> Path:
    return LOG_DIR.joinpath(*parts)
