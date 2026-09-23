"""Reconcile the persisted network policy set with the volatile nftables runtime.

nftables tables live in the kernel, so `inet wgd_network_policy` disappears on every
reboot and on any external ruleset flush, while the Dashboard database still marks those
Peers as managed. Until now the only way back was a human pressing "sync" in the policy
page: 2026-09-22 09:02 the host rebooted for a kernel upgrade and every managed Peer
silently fell back to the gateway's permissive `iifname "wg0" accept` forwarding, with no
policy verdicts reaching the audit collector either. That is a fail-open, not a cosmetic
gap.

This module is the scripted repair: it compares the Agent-reported digest and tagged-rule
count with the desired set and re-publishes only when they differ, so a systemd timer can
run it every few minutes without churning the live ruleset. It writes nothing to the
database — the persisted policies remain the single source of truth.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .service import NetworkPolicyService, NetworkPolicyServiceError, PolicyAgentClient

DASHBOARD_DATABASE_NAME = "wgdashboard"
EXIT_IN_SYNC = 0
EXIT_FAILED = 1
EXIT_DRIFT = 2


def build_service(socket_path: str | None = None) -> NetworkPolicyService:
    """Wire the policy service to the Dashboard's configured database.

    Only `ConnectionString` is reused, never the full `DashboardConfig` object: building
    that would write default keys back into `wg-dashboard.ini`, which a read-mostly
    reconciler has no business doing.
    """
    import sqlalchemy as db

    from modules.DatabaseConnection import ConnectionString

    return NetworkPolicyService(db.create_engine(ConnectionString(DASHBOARD_DATABASE_NAME)), PolicyAgentClient(socket_path))


def reconcile(service: NetworkPolicyService, check_only: bool) -> tuple[dict[str, Any], int]:
    """Return the report payload plus the process exit code for one reconciliation pass."""
    if check_only:
        report = service.runtime_check()
        return report, EXIT_IN_SYNC if report["status"] == "in_sync" else EXIT_DRIFT
    report = service.synchronize_runtime(force=False)
    return report, EXIT_IN_SYNC if report["status"] == "in_sync" else EXIT_FAILED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile the WGDashboard network policy ruleset with its persisted state",
    )
    parser.add_argument(
        "--socket",
        default=None,
        help="policy agent socket; defaults to WGD_NETWORK_POLICY_SOCKET or the standard path",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="report drift and exit " + str(EXIT_DRIFT) + " without touching nftables",
    )
    args = parser.parse_args(argv)

    try:
        service = build_service(args.socket)
        report, exit_code = reconcile(service, args.check_only)
    except (NetworkPolicyServiceError, OSError, ValueError) as error:
        print(json.dumps({"status": "error", "message": str(error)}, sort_keys=True), file=sys.stderr)
        return EXIT_FAILED

    print(json.dumps(report, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
