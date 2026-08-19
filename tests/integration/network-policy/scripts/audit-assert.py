from collections import defaultdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time

from network_audit.health import read_health_snapshot
from network_audit.service import NetworkAuditService


DATABASE_PATH = "/tmp/wgdashboard_audit.db"
HEALTH_PATH = Path("/tmp/audit-health.json")
now = datetime.now(timezone.utc)
QUERY = {
    "start_time": (now - timedelta(days=1)).isoformat(),
    "end_time": (now + timedelta(days=1)).isoformat(),
    "page_size": 100,
}


def records():
    service = NetworkAuditService(DATABASE_PATH)
    try:
        return service.query(QUERY)["records"]
    finally:
        service.engine.dispose()


deadline = time.monotonic() + 30
audit_records = []
while time.monotonic() < deadline:
    audit_records = records()
    decisions = {record["decision"] for record in audit_records}
    if {"policy_allowed", "policy_denied", "forward_observed"}.issubset(decisions):
        break
    time.sleep(1)

expected_decisions = {"policy_allowed", "policy_denied", "forward_observed"}
decisions = {record["decision"] for record in audit_records}
if not expected_decisions.issubset(decisions):
    raise SystemExit(f"missing audit decisions: expected {expected_decisions}, got {decisions}")

for decision in expected_decisions:
    matching = [record for record in audit_records if record["decision"] == decision]
    if not matching:
        raise SystemExit(f"no audit record for {decision}")
    if not any(record["connection_count"] >= 1 for record in matching):
        raise SystemExit(f"no connection count for {decision}")

for decision in ("policy_allowed", "forward_observed"):
    matching = [record for record in audit_records if record["decision"] == decision]
    if not any(record["bytes_from_peer"] > 0 for record in matching):
        raise SystemExit(f"no peer byte counter for {decision}")

if not any(record["tunnel_address"] == "10.250.0.2" for record in audit_records if record["decision"] == "policy_allowed"):
    raise SystemExit("managed allowed flow was not recorded")
if not any(record["tunnel_address"] == "10.250.0.2" for record in audit_records if record["decision"] == "policy_denied"):
    raise SystemExit("managed denied flow was not recorded")
if not any(record["tunnel_address"] == "10.250.0.3" for record in audit_records if record["decision"] == "forward_observed"):
    raise SystemExit("unmanaged forwarding flow was not recorded")

keys = defaultdict(int)
for record in audit_records:
    key = (
        record["configuration_name"],
        record["peer_public_key"],
        record["tunnel_address"],
        record["destination_address"],
        record["protocol"],
        record["destination_port"],
        record["decision"],
        record["window_started_at"],
    )
    keys[key] += 1
if any(count != 1 for count in keys.values()):
    raise SystemExit("duplicate audit decision rows were persisted")

health = read_health_snapshot(HEALTH_PATH)
if health.status.value != "healthy":
    raise SystemExit(f"collector health is {health.status.value}: {health.last_error}")
if health.nflog_events < 1 or health.conntrack_events < 1:
    raise SystemExit("collector did not receive both NFLOG and conntrack events")
if (
    health.config_generation != 1
    or health.config_sync_status.value != "applied"
    or health.config_sync_generation != 1
    or health.write_failures != 0
    or health.spool_records != 0
):
    raise SystemExit(f"unexpected collector health: {json.dumps(health.to_payload(), sort_keys=True)}")

print(json.dumps({"records": len(audit_records), "health": health.to_payload()}, sort_keys=True))
