"""
Goodware v3.0 - Logger estruturado
"""
from __future__ import annotations

import json
import logging
import os
import sys
import time
from logging.handlers import RotatingFileHandler
from typing import Any, Dict


_LOGGERS: Dict[str, logging.Logger] = {}


def get_logger(name: str = "goodware", log_dir: str = "logs", level: str = "INFO") -> logging.Logger:
    if name in _LOGGERS:
        return _LOGGERS[name]
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    fh = RotatingFileHandler(
        os.path.join(log_dir, f"{name}.log"), maxBytes=10 * 1024 * 1024, backupCount=5
    )
    fh.setFormatter(fmt)
    logger.addHandler(sh)
    logger.addHandler(fh)
    _LOGGERS[name] = logger
    return logger


def log_event(logger: logging.Logger, event: Dict[str, Any]) -> None:
    logger.info(json.dumps(event, default=str))


def timed(logger: logging.Logger, label: str) -> "Timer":
    return Timer(logger, label)


class Timer:
    def __init__(self, logger: logging.Logger, label: str) -> None:
        self.logger = logger
        self.label = label
        self.start = 0.0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, exc_type, exc, tb):
        ms = (time.time() - self.start) * 1000
        self.logger.info(f"timing | {self.label} | {ms:.2f}ms")
