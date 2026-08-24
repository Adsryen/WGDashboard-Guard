# Network Audit Runtime

WGDashboard Network Audit records metadata for new traffic forwarded from configured WireGuard Peers. It never stores packet payloads, URLs, DNS/TLS content, credentials, or WireGuard private keys. The collector has no HTTP, TCP, or UDP listener and cannot invoke `nft`.

## Components and boundaries

- `wgd-network-audit-agent` is the only audit component allowed to manage `inet wgd_network_audit`. Its local Unix socket accepts only fixed, validated configuration requests from root or members of `wgdaudit`.
- `wgd-network-audit-collector` subscribes to local conntrack and NFLOG metadata, applies decision precedence, and writes validated observations through the internal audit database service.
- `wgd-network-audit-alerts` is a local polling runner. It reads the independent audit DB, the collector health snapshot, and the Dashboard INI, then sends deduplicated metadata-only email alerts. It has no HTTP listener and never manages nftables.
- The agent never changes `inet wgd_network_policy` or any other nftables table. The collector never changes nftables verdicts.
- The collector stores temporarily unavailable database writes in `/var/lib/wgd-network-audit/spool.db` and publishes `/run/wgd-network-audit/health.json`. Dashboard-to-agent synchronization status is written locally to `db/wgdashboard_audit_sync.json` and merged into the health snapshot.

## Installation after authorization

This task does **not** install, enable, restart, or otherwise deploy audit services to `192.168.0.115`. Run the following only after separate authorization for the target Linux gateway.

```bash
sudo groupadd --system wgdaudit
sudo install -D -m 0644 deploy/systemd/wgd-network-audit-agent.service /etc/systemd/system/wgd-network-audit-agent.service
sudo install -D -m 0644 deploy/systemd/wgd-network-audit-collector.service /etc/systemd/system/wgd-network-audit-collector.service
sudo install -D -m 0644 deploy/systemd/wgd-network-audit-alerts.service /etc/systemd/system/wgd-network-audit-alerts.service
sudo install -D -m 0644 deploy/systemd/wg-dashboard-audit.conf /etc/systemd/system/wg-dashboard.service.d/network-audit.conf
sudo install -D -m 0644 deploy/systemd/tmpfiles.d/wgd-network-audit.conf /etc/tmpfiles.d/wgd-network-audit.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/wgd-network-audit.conf
sudo systemctl daemon-reload
sudo systemctl enable --now wgd-network-audit-agent.service
sudo systemctl enable --now wgd-network-audit-collector.service
sudo systemctl enable --now wgd-network-audit-alerts.service
```

If the Dashboard service does not run as root, add its account to `wgdaudit` and restart it so it receives the supplemental group:

```bash
sudo usermod -aG wgdaudit <wgdashboard-service-user>
sudo systemctl restart wg-dashboard.service
```

The included units assume `/opt/WGDashboard/src` and its `venv/bin/python3` interpreter. Keep `WorkingDirectory`, `PYTHONPATH`, `ExecStart`, and the relative `db/wgdashboard_audit_sync.json` path aligned when using a different installation location or virtual environment.

The agent waits for its Unix socket before Dashboard startup. The `wg-dashboard` drop-in starts the agent whenever Dashboard starts, so the initial configuration synchronization does not race the collector.

## Verification and recovery

```bash
sudo systemctl status wgd-network-audit-agent.service wgd-network-audit-collector.service wgd-network-audit-alerts.service
sudo nft list table inet wgd_network_audit
sudo cat /run/wgd-network-audit/health.json
```

The audit table can be absent before the first successful Dashboard synchronization. A failed synchronization preserves the last owned audit table and appears as `config_sync_status: "failed"` with a bounded error summary in the health snapshot. A failed database write degrades health and retains observations in the bounded spool; it does not change forwarding behavior.

The administrator audit filters use case-insensitive substring matching for text fields. A complete IP address or CIDR in the destination filter keeps numeric range matching; other destination text is matched against the recorded address. The `Destination in tunnel network` filter uses the observed Peer's explicit `endpoint_allowed_ip` CIDRs (including comma-separated IPv4/IPv6 CIDRs) for the matching configuration, Peer, and tunnel address, and offers All, Yes, and No. Default routes such as `0.0.0.0/0` and `::/0` are excluded because they mean “all destinations”, not a specific tunnel network. For example, a Peer with `192.168.0.0/24` in that field classifies `192.168.0.175` as Yes, while a Peer whose only route is `0.0.0.0/0` does not classify an arbitrary public address as a tunnel-network destination. This is a destination-network classification; it does not replace the actual policy verdict. The separate `Matches policy allowed target` field and filter compare the active, bound, applied network-policy rule for the same configuration, Peer, and tunnel address, including destination CIDR, protocol, and port range. The server computes `destination_in_tunnel` and `destination_in_policy` for each response record; direct service calls without the corresponding snapshots return `null` and do not apply that filter. Results are five-minute activity windows, not HTTP requests: repeated flows with the same Peer, destination, protocol, port, and decision are combined and reported through `connection_count` and byte totals.

The collector records every new forwarded flow from an audited WireGuard Peer, including policy-denied attempts. A browser, mobile application, DNS resolver, IPv4/IPv6 fallback, background connectivity check, redirect, retry, or page subresource can therefore produce additional destination rows even when the user entered one address. The audit metadata does not identify the initiating URL or application request. Use the Peer, destination, protocol, port, decision, and time filters together when investigating a denied attempt.

To stop collection without changing network policy, disable the collector first, then the audit agent. Do not flush `inet wgd_network_policy` or unrelated nftables tables during audit recovery.

## Alert operation

Configure one audit alert recipient in the administrator Network Access Audit page, send a successful test email, then enable alerts. The recipient is independent from `Email.send_from`; it is a single mailbox, not a list. Alert settings default to 10 denied connections or 20 distinct destination IP/port pairs for one Peer within five minutes, with a 30-minute cooldown per alert identity.

The alert runner can be exercised without sending a loop:

```bash
sudo -u root env PYTHONPATH=/opt/WGDashboard/src CONFIGURATION_PATH=/opt/WGDashboard/src \
  /opt/WGDashboard/src/venv/bin/python3 -m network_audit.alerts \
  --database /opt/WGDashboard/src/db/wgdashboard_audit.db \
  --health /run/wgd-network-audit/health.json \
  --config /opt/WGDashboard/src/wg-dashboard.ini --once
```

Alert delivery failures, stale or failed collector health, and storage write failures are persisted in the independent audit database and shown on the administrator audit page. Stopping the alert runner stops email delivery only; it does not stop collection or forwarding.
