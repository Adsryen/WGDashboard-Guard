# Network Audit Contract

## Scenario: WireGuard Forwarding Access Audit

### 1. Scope / Trigger

- Trigger: A collector records bounded WireGuard forwarding metadata into an independent SQLite database, and Dashboard administrators query the resulting UTC five-minute activity windows.
- Ownership boundary: `network_audit` owns only `db/wgdashboard_audit.db`; it must never use `DashboardConfig.engine` or alter the main Dashboard database.
- Privacy boundary: retain peer/configuration snapshots, tunnel and destination addresses, protocol, destination port, decision, timestamps, counts, and byte counters only. Do not persist packet payloads, URLs, DNS/TLS/HTTP metadata, credentials, cookies, or WireGuard private keys.
- HTTP boundary: Dashboard exposes read-only queries. Collectors call `NetworkAuditService.record_observation()` internally; there is no browser-facing audit write endpoint.

### 2. Signatures

- Internal write: `NetworkAuditService.record_observation(AuditObservation | dict)`.
- Internal cleanup: `NetworkAuditService.cleanup_retention(now: datetime | None = None)`.
- Flask: `POST /api/networkAudit/query` with a JSON `AuditQuery` payload.
- Flask: `GET /api/networkAudit/summary` with `AuditQuery` query-string fields.
- Database tables: `AuditSchemaVersions`, `AuditActivityWindows`, `AuditDailyAggregates`, and `AuditRetentionRuns`.
- Environment: `WGD_AUDIT_DATABASE_PATH` optionally overrides the default `db/wgdashboard_audit.db`.

### 3. Contracts

- An `AuditObservation` contains `configuration_name`, WireGuard `peer_public_key`, `peer_name_snapshot`, `tunnel_address`, `destination_address`, `protocol`, `destination_port`, `decision`, timezone-aware `observed_at`, `connection_increment`, `bytes_from_peer`, and `bytes_to_peer`.
- Decisions are exactly `forward_observed`, `policy_allowed`, or `policy_denied`. They describe gateway observation/verdicts, not remote-service or application-layer success.
- Activity rows are upserted by the fixed UTC five-minute window and the full historical snapshot dimension: configuration, peer key/name snapshot, tunnel address, destination address/family, protocol, normalized port key, and decision. The null ICMP port uses a non-null `PortKey` so SQLite uniqueness remains reliable.
- Query filters support a timezone-aware maximum 31-day range plus configuration, peer key/name, tunnel address, destination IP/CIDR, protocol, port, decision, page, and page size. Results sort by `WindowStartedAt DESC, ActivityWindowID DESC`; requests cannot address more than 5,000 results.
- Query/summary responses are readable only from a genuine Dashboard password/TOTP administrator session (`auth_source == "dashboard_login"`). API-key sessions, valid API-key request headers, client sessions, missing provenance, and anonymous callers receive `401` without data.
- Retention deletes only audit data: detail windows whose end is older than 180 days, and daily aggregates older than 24 calendar months. Every run records deleted row counts in `AuditRetentionRuns`.

### 4. Validation And Error Matrix

| Condition | Result |
| --- | --- |
| Invalid key, configuration, address/CIDR, protocol, port, decision, counter, timestamp, field, page, or page size | `AuditValidationError`; HTTP API returns `400` before querying or writing |
| Naive timestamp, inverted range, range over 31 days, page over 100, page size over 100, or requested offset beyond 5,000 rows | `AuditValidationError`; HTTP API returns `400` |
| Anonymous, client, API-key-created, unmarked legacy, or API-key-header request | HTTP `401` and `data: null` |
| Audit SQLite initialization, query, write, or cleanup fails | `NetworkAuditServiceError`; read API returns `503`; no impact on WireGuard forwarding or policy tables |
| Repeated observation in one dimension/window | One activity row is atomically updated with minimum first-seen, maximum last-seen, and accumulated counters |

### 5. Good / Base / Bad Cases

- Good: A collector reports TCP `443` observations for the same peer/destination at `12:01Z` and `12:04Z`. Querying the interval returns one `12:00Z` window with combined counts and bytes.
- Base: ICMP has `destination_port: null`; its stable empty `PortKey` lets repeated ICMP observations aggregate into one row and daily aggregate.
- Bad: A browser or external caller posts an audit observation, supplies a payload/URL field, or uses an API key to read audit data. No write route exists; validation rejects unknown fields and the read endpoint returns `401` for the API-key authentication path.

### 6. Tests Required

- Service test initialization is independent from main database tables, preserves schema/version tables, and supports repeat initialization.
- Service test combines same-window records, including null-port ICMP, and confirms day aggregates use the same counters without receiving detail-only columns.
- Service test covers historical snapshots, stable ordering, CIDR/protocol/port/decision filters, pagination limits, summary fields, and both retention boundaries.
- API test covers anonymous rejection, valid API-key-created session rejection, valid API-key header rejection even with an administrator cookie, authenticated Dashboard administrator success, validation `400`, and database-failure `503`.
- Regression test `tests/test_network_policy.py` continues to pass; audit work must not alter existing policy persistence/API behavior.

### 7. Gateway Collector And Runtime Contract

- Table ownership is split: only `network_audit.agent` manages `inet wgd_network_audit`; it must reject a pre-existing table that lacks the `wgd-audit-owner:v1` marker. `network_policy.agent` remains the sole owner of `inet wgd_network_policy`.
- The audit table observes `iifname "wg0" ct state new` with `wgd-audit:forward_observed` on NFLOG group `11500`. Policy allow/deny annotations use the fixed `wgd-audit:policy_allowed` / `wgd-audit:policy_denied` prefixes on group `11501`. Both verdict prefixes deliberately share one NFLOG group; the parsed prefix carries the decision.
- NFLOG group membership comes from the `nfgenmsg.res_id` header, not `NFULA_GID`. The decoder may read only the fixed prefix, IP header, protocol and ports needed for `FlowKey`; raw datagrams, packet buffers and application payload bytes must never cross into correlation, spool, service, health, logs or exceptions.
- Conntrack events normalize the original tuple, zone and original/reply byte counters before correlation. The collector emits at most one observation per new flow after the short decision TTL; `policy_denied` overrides `policy_allowed`, then `forward_observed` is the fallback.
- `AuditSpool` is SQLite-backed and bounded by record count, total bytes and per-record bytes. On capacity pressure it evicts oldest records; on service write failure it retries later. Neither condition may affect nftables verdicts or block a netfilter event source.
- The audit agent atomically writes `/run/wgd-network-audit/config.json` only after its owned table applies. Its socket must verify `SO_PEERCRED` and accept only root or a member of its configured `wgdaudit` group. The collector uses only that last-applied config and atomically writes `/run/wgd-network-audit/health.json`; it exposes no TCP, UDP or HTTP listener.
- Dashboard config sync builds the audit config from eligible live peers and `managed + bound + applied` policy records only. It atomically records its latest `applied` or `failed` state, attempted generation, timestamp, and bounded error in `db/wgdashboard_audit_sync.json`; the collector merges that read-only state into its health snapshot. Synchronization is best-effort after peer/policy changes: failure must preserve the active audit table and must not turn a successful policy action into a failure.
- Systemd units run separately: the agent has `CAP_NET_ADMIN` and is the only audit component allowed to call `nft`; the collector has netlink/raw capabilities plus write access only to its runtime, spool and audit SQLite locations.

### 8. Wrong Vs Correct

#### Wrong

```python
daily_values = {**values, "AggregateDate": observed_at.date()}
```

`values` contains `DestinationSortKey`, which belongs only to `AuditActivityWindows`; SQLAlchemy rejects that column when inserting `AuditDailyAggregates`.

#### Correct

```python
daily_values = {
    key: value for key, value in values.items() if key != "DestinationSortKey"
}
daily_values["AggregateDate"] = observed_at.date()
```

Only pass columns owned by the aggregate table. Keep the destination sort key exclusively on activity rows, where it supports indexed CIDR filtering.

#### Wrong

```python
if session.get("role") == "admin":
    return audit_service.query(query)
```

#### Correct

```python
if request.headers.get("wg-dashboard-apikey") is not None or session.get("auth_source") != "dashboard_login":
    return unauthorized_response
```

API-key authentication can otherwise create an administrative-looking session. Audit reads require local Dashboard-login provenance and must reject API-key-bearing requests without relying on shared process state.
