"""Logging bootstrap for the standalone network-audit processes.

The dashboard configures logging itself (``dashboard.py`` installs a ``dictConfig``), but the
collector and the alert runner are separate systemd services that never import it. With no
handler installed, ``LOGGER.info()`` falls through to the interpreter's last-resort handler,
which only emits WARNING and above - so the one line operators are told to search for,

    journalctl -u wgd-network-audit-collector.service | grep "network audit sqlite storage"

returned nothing on production while the effective SQLite settings were in fact applied
(2026-09-28: verified via ``storage_diagnostics()`` readback, ``journal_size_limit=67108864``).
An unverifiable configuration is a missing configuration, so these two entrypoints opt in here.

Only the ``network_audit`` subtree is promoted to INFO. Third-party libraries keep their
defaults, and the handler is attached to that subtree with ``propagate`` disabled, so a future
root handler cannot make every audit line appear twice.

``enable_audit_logging()`` is exported separately for processes that already configure logging
themselves: the dashboard installs a ``dictConfig`` and therefore only needs the subtree
un-disabled, not a second handler.
"""

from __future__ import annotations

from typing import Any
import logging
import os
import sys

AUDIT_LOGGER_NAME = "network_audit"
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVEL_ENVIRONMENT_VARIABLE = "WGD_AUDIT_LOG_LEVEL"
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_HANDLER_MARKER = "_wgd_network_audit_handler"


def resolve_log_level(raw: str | int | None = None) -> int:
    """Translate a level name/number into a logging level, defaulting instead of raising.

    These processes are the only writer of the audit trail; a malformed environment value must
    not be able to stop collection, so anything unusable falls back to INFO.
    """
    if raw is None:
        return DEFAULT_LOG_LEVEL
    if isinstance(raw, int):
        return raw if raw > 0 else DEFAULT_LOG_LEVEL
    candidate = str(raw).strip().upper()
    if candidate.isdigit():
        level = int(candidate)
        return level if level > 0 else DEFAULT_LOG_LEVEL
    resolved = logging.getLevelName(candidate)
    return resolved if isinstance(resolved, int) else DEFAULT_LOG_LEVEL


def enable_audit_logging(name: str = AUDIT_LOGGER_NAME) -> int:
    """Un-disable every existing logger in the audit subtree, and return how many were touched.

    ``logging.config.dictConfig`` defaults to ``disable_existing_loggers=True``, and ``dashboard.py``
    relies on that default: the call sets ``disabled`` on *every* ``Logger`` instance that exists at
    that moment, not just on ancestors. Since ``network_audit.service`` (the module holding the
    storage diagnostic) is a separate instance from the ``network_audit`` root of the subtree,
    clearing only the root name leaves the record swallowed - ``Logger.handle()`` bails out on the
    child's own flag before it ever consults the hierarchy. Production hit this on 2026-09-28 as
    test-order noise; the same mechanism silences dashboard-side audit warnings for real.

    The sweep is deliberately scoped to the subtree: third-party loggers stay exactly as
    ``disable_existing_loggers`` left them. ``Logger.enable()`` is avoided because it only exists
    on 3.11+ while this codebase runs on 3.10.
    """
    manager = logging.Logger.manager
    prefix = f"{name}."
    enabled = 0
    for key, value in manager.loggerDict.items():
        if isinstance(value, logging.Logger) and (key == name or key.startswith(prefix)):
            value.disabled = False
            enabled += 1
    return enabled


def configure_runtime_logging(
    level: str | int | None = None,
    stream: Any | None = None,
) -> logging.Handler:
    """Make ``network_audit`` INFO records observable; safe to call more than once.

    ``stream`` defaults to ``sys.stderr``, which systemd captures into the unit journal. It is a
    parameter rather than a hard reference so the observability itself can be tested for real
    (counting calls on a mocked logger would pass even with no handler installed at all).
    """
    requested = resolve_log_level(
        level if level is not None else os.environ.get(LOG_LEVEL_ENVIRONMENT_VARIABLE)
    )
    logger = logging.getLogger(AUDIT_LOGGER_NAME)
    enable_audit_logging()
    logger.setLevel(requested)
    for handler in logger.handlers:
        if getattr(handler, _HANDLER_MARKER, False):
            return handler
    handler = logging.StreamHandler(sys.stderr if stream is None else stream)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    setattr(handler, _HANDLER_MARKER, True)
    logger.addHandler(handler)
    logger.propagate = False
    return handler
