from datetime import datetime, timezone

from network_audit.agent import AuditNftablesExecutor, write_applied_config
from network_audit.agent_protocol import AUDIT_CONFIG_VERSION, AuditAgentConfig, AuditPeerSnapshot
from network_audit.health import write_config_sync_snapshot
from network_policy.compiler import NFLOG_POLICY_DECISION_GROUP


config = AuditAgentConfig(
    version=AUDIT_CONFIG_VERSION,
    generation=1,
    interface_name="wg0",
    mode="all",
    peers=(
        AuditPeerSnapshot("wg0", "A" * 43 + "=", "managed-peer", "10.250.0.2"),
        AuditPeerSnapshot("wg0", "B" * 43 + "=", "unmanaged-peer", "10.250.0.3"),
    ),
    managed_tunnel_addresses=("10.250.0.2",),
    observation_nflog_group=11500,
    policy_allowed_nflog_group=NFLOG_POLICY_DECISION_GROUP,
    policy_denied_nflog_group=NFLOG_POLICY_DECISION_GROUP,
)

result = AuditNftablesExecutor().apply(config)
if not result["applied"]:
    raise SystemExit("audit table was not applied")
write_applied_config("/tmp/audit-config.json", config)
write_config_sync_snapshot(
    "/tmp/audit-sync-status.json",
    {
        "status": "applied",
        "updated_at": datetime.now(timezone.utc),
        "generation": config.generation,
        "error": None,
    },
)
