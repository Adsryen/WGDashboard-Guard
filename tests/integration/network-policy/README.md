# Network Policy Docker Integration Test

This Compose fixture creates a disposable Linux network namespace. It does not contact a WireGuard endpoint, use a production configuration, or alter the host nftables ruleset.

The `gateway` container bridges its Peer-facing Docker interface as `wg0`, enables forwarding, and applies the real `src/network_policy` compiler output. The synthetic networks deliberately use `10.250.0.0/24` through `10.253.0.0/24` to avoid the deployment LAN ranges.

```text
managed-peer 10.250.0.2 ----> gateway wg0 10.250.0.10 ----> target-a 10.251.0.170
unmanaged-peer 10.250.0.3                                  -> target-b 10.252.0.127
                                                              -> target-c 10.252.0.117
                                                              -> target-denied 10.253.0.200
```

Run the complete, self-cleaning check from PowerShell:

```powershell
./tests/integration/network-policy/run.ps1
```

On Linux or WSL:

```sh
./tests/integration/network-policy/run.sh
```

The test verifies that the managed Peer can use TCP and UDP to `target-a` and `target-b`, and TCP `8118` to `target-c`. It verifies drops for an unlisted target, the wrong TCP port, and the wrong protocol. The unmanaged Peer remains able to forward to `target-denied`.

It also proves the managed Peer can still open the gateway-local SSH listener and receive a response from the gateway-local UDP `51820` listener. Those packets terminate in `INPUT`; they do not match the policy's `FORWARD` chain.

Before applying the policy, the fixture creates a separate `inet docker_sentinel` nftables table and applies the audit agent's independent `inet wgd_network_audit` observation table. The test checks the sentinel's exact contents after a successful policy apply and after a deliberately failed policy load, and verifies the audit table is unchanged. This demonstrates that policy apply updates only `inet wgd_network_policy` and preserves both the audit table and unrelated tables.

For interactive inspection, start the topology without cleanup:

```powershell
docker compose --project-name wgd-network-policy-it --file tests/integration/network-policy/compose.yaml up --build -d
docker compose --project-name wgd-network-policy-it --file tests/integration/network-policy/compose.yaml logs -f managed-peer unmanaged-peer
```

Remove the isolated containers and networks afterwards:

```powershell
docker compose --project-name wgd-network-policy-it --file tests/integration/network-policy/compose.yaml down --volumes --remove-orphans
```
