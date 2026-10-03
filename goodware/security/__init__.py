"""Goodware v3.0 — Security hardening module."""
from .constitutional_guard import ConstitutionalGuard, GuardVerdict, InvariantViolation
from .artifact_protection import ArtifactProtector
from .tool_authorization import (
    authorize_tool_call,
    require_oob,
    require_multiparty,
    guarded_tool,
    READ_ONLY_TOOLS,
)

__all__ = [
    "ConstitutionalGuard",
    "GuardVerdict",
    "InvariantViolation",
    "ArtifactProtector",
    "authorize_tool_call",
    "require_oob",
    "require_multiparty",
    "guarded_tool",
    "READ_ONLY_TOOLS",
]
