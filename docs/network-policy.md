# Network Policy Agent

WGDashboard Network Policy controls only decrypted WireGuard traffic forwarded through the gateway. It does not inspect or block the WireGuard UDP listener, handshake packets, or services addressed to the gateway itself, including SSH on port 22.

## Security model

- The Dashboard process stores and validates declarative policies. It has no permission to invoke `nft` directly.
- `wgd-network-policy-agent` is the only privileged component. It accepts fixed, versioned JSON requests over `/run/wgd-network-policy/agent.sock`.
- The Agent accepts only capability checks, status, preview, apply, and rollback. It never accepts a command line, an nftables expression, a table name, or an interface name outside a validated policy.
- The Agent writes only `inet wgd_network_policy`. It never flushes or modifies Docker, 1Panel, UFW, firewalld, or other nftables tables.
- A Peer enters default-deny forwarding only after its policy has been successfully applied. Unmanaged Peers keep the gateway's previous forwarding behavior.

## Install on Linux

The initial provider requires nftables and a Linux host. Install the Dashboard and this source tree before enabling the Agent.

```bash
sudo groupadd --system wgdpolicy
sudo install -D -m 0644 deploy/systemd/wgd-network-policy-agent.service /etc/systemd/system/wgd-network-policy-agent.service
sudo install -D -m 0644 deploy/systemd/tmpfiles.d/wgd-network-policy-agent.conf /etc/tmpfiles.d/wgd-network-policy-agent.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/wgd-network-policy-agent.conf
sudo systemctl daemon-reload
sudo systemctl enable --now wgd-network-policy-agent.service
```

If WGDashboard does not run as root, add its service account to `wgdpolicy`, then restart that service so it receives the new group membership:

```bash
sudo usermod -aG wgdpolicy <wgdashboard-service-user>
sudo systemctl restart wg-dashboard.service
```

The included unit assumes the source checkout is `/opt/WGDashboard` and Python is `/usr/bin/python3`. Adjust `WorkingDirectory`, `PYTHONPATH`, and `ExecStart` together for another installation location or virtual environment. The Dashboard must use the default socket path, or set `WGD_NETWORK_POLICY_SOCKET` to the same absolute path.

Verify readiness without changing firewall rules:

```bash
sudo systemctl status wgd-network-policy-agent.service
sudo nft list table inet wgd_network_policy
```

The table may not exist until the first successful policy application. In that case, use the Dashboard capability endpoint and dry-run preview first.

## Applying a Peer policy

1. Open a Peer menu, select **Network Policy**, and choose one of that Peer’s single-host `AllowedIPs`.
2. Add explicit TCP, UDP, or ICMP destination rules. ICMP is allowed to every destination by default; enable **Restrict ICMP diagnostics** only when ICMP must be limited to explicit ICMP destination rules. An empty rule list denies every TCP/UDP forwarded destination for the Peer.
3. Select **Preview** and inspect the generated nftables rules and hash.
4. Select **Apply**. The Agent runs `nft --check`, replaces only its own table, rereads it, and verifies the hash.

The following policy is represented by five allow rules plus one default drop for the Peer: TCP and UDP all ports to `192.168.0.170` and `192.168.10.127`, then TCP `8118` to `192.168.10.117`.

## Failure and recovery

- A failed check or apply leaves the previously loaded table and the previous active policy intact. The failed candidate is recorded in policy history.
- Before a managed Peer is deleted or its single-host `AllowedIPs` changes, its existing allow rules are replaced with a default drop. This prevents a later Peer reusing the old tunnel address from inheriting access. The policy is retained as an orphaned audit record and must be explicitly configured again for the new binding.
- Use the history restore button to reapply a prior revision.
- For an emergency return to the host's pre-feature forwarding behavior, stop the Agent and delete only the owned table:

```bash
sudo systemctl stop wgd-network-policy-agent.service
sudo nft delete table inet wgd_network_policy
```

Do not run `nft flush ruleset`, and do not delete Docker or 1Panel tables/chains.

## Validation before production use

Run backend tests and build the frontend in a development checkout. Test actual forwarding behavior in an isolated network namespace or non-production gateway before applying the first production policy. In particular, prove the intended allowed flow, a denied destination, return traffic, an unmanaged Peer, the WireGuard UDP listener, and gateway SSH remain reachable as designed.
