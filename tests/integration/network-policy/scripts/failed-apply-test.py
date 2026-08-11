"""Ensure an apply failure after nft --check leaves the owned table unchanged."""

from pathlib import Path
import subprocess

from network_policy.agent import NftablesError, NftablesExecutor
from network_policy.validation import validate_policy


def table_contents() -> str:
    return subprocess.run(
        ["nft", "list", "table", "inet", "wgd_network_policy"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout


policy = validate_policy(
    {
        "configuration_name": "wg0",
        "interface_name": "wg0",
        "peer_public_key": "a" * 43 + "=",
        "tunnel_address": "10.250.0.2",
        "managed": True,
        "rules": [
            {"destination": "10.251.0.170", "protocol": "tcp", "ports": None},
            {"destination": "10.252.0.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}},
        ],
    }
)

before = table_contents()
executor = NftablesExecutor()
executor.nft_path = str(Path("/tests/nft-failing-wrapper.sh"))
try:
    executor.apply([policy])
except NftablesError:
    pass
else:
    raise SystemExit("the forced nft apply failure unexpectedly succeeded")

if table_contents() != before:
    raise SystemExit("failed apply changed the owned nftables table")
