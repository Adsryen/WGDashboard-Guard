from network_policy.agent import NftablesExecutor
from network_policy.validation import validate_policy


policy = validate_policy(
    {
        "configuration_name": "wg0",
        "interface_name": "wg0",
        "peer_public_key": "a" * 43 + "=",
        "tunnel_address": "10.250.0.2",
        "managed": True,
        "rules": [
            {"destination": "10.251.0.170", "protocol": "tcp", "ports": None},
            {"destination": "10.251.0.170", "protocol": "udp", "ports": None},
            {"destination": "10.252.0.127", "protocol": "tcp", "ports": None},
            {"destination": "10.252.0.127", "protocol": "udp", "ports": None},
            {
                "destination": "10.252.0.117",
                "protocol": "tcp",
                "ports": {"from": 8118, "to": 8118},
            },
        ],
    }
)

result = NftablesExecutor().apply([policy])
if not result["applied"]:
    raise SystemExit("initial policy was not applied")
