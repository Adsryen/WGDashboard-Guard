"""Dashboard use cases for policy preview, application, history, and rollback."""

from __future__ import annotations

import hashlib
import os
import socket
from typing import Any

from .agent_protocol import AgentProtocolError, AgentRequest, MAX_MESSAGE_BYTES, decode_message, encode_message
from .compiler import policy_hash
from .models import NetworkPolicyRepository
from .validation import NetworkPolicy, PolicyValidationError, validate_policy


DEFAULT_SOCKET_PATH = "/run/wgd-network-policy/agent.sock"


class NetworkPolicyServiceError(RuntimeError):
    """A user-facing policy operation failed without changing active policy state."""


class PolicyAgentClient:
    def __init__(self, socket_path: str | None = None):
        self.socket_path = socket_path or os.getenv("WGD_NETWORK_POLICY_SOCKET", DEFAULT_SOCKET_PATH)

    def request(self, action: str, policies: list[NetworkPolicy] | None = None) -> dict[str, Any]:
        request = AgentRequest(action=action, policies=tuple(policies or ()))
        if action in {"dry_run", "apply", "rollback"} and policies is None:
            raise NetworkPolicyServiceError("policy action requires a policy list")
        if not hasattr(socket, "AF_UNIX"):
            raise NetworkPolicyServiceError("network policy agent is only available on Unix hosts")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(20)
                connection.connect(self.socket_path)
                connection.sendall(encode_message(request.to_payload()))
                chunks: list[bytes] = []
                received = 0
                while True:
                    chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES - received + 1))
                    if not chunk:
                        break
                    received += len(chunk)
                    if received > MAX_MESSAGE_BYTES:
                        raise NetworkPolicyServiceError("policy agent response exceeds size limit")
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, socket.timeout) as error:
            raise NetworkPolicyServiceError(f"network policy agent is unavailable: {error}") from error
        try:
            response = decode_message(b"".join(chunks).split(b"\n", 1)[0])
        except AgentProtocolError as error:
            raise NetworkPolicyServiceError(str(error)) from error
        if response.get("status") is not True:
            raise NetworkPolicyServiceError(str(response.get("message") or "policy agent rejected the request"))
        data = response.get("data")
        if not isinstance(data, dict):
            raise NetworkPolicyServiceError("policy agent returned an invalid response")
        return data


class NetworkPolicyService:
    def __init__(self, engine, agent_client: PolicyAgentClient | None = None):
        self.repository = NetworkPolicyRepository(engine)
        self.agent_client = agent_client or PolicyAgentClient()

    @staticmethod
    def actor_from_session(session_id: str | None) -> str:
        if not session_id:
            return "dashboard-session:unknown"
        return f"dashboard-session:{hashlib.sha256(session_id.encode('utf-8')).hexdigest()[:16]}"

    def capabilities(self) -> dict[str, Any]:
        return self.agent_client.request("capabilities")

    def details(self, configuration_name: str, peer_public_key: str, tunnel_address: str) -> dict[str, Any]:
        return self.repository.details(configuration_name, peer_public_key, tunnel_address)

    def overview(self, peers: list[dict[str, Any]]) -> dict[str, Any]:
        """Join live Peers with persisted policies without making unmanaged Peers restrictive."""
        records = self.repository.current_records()
        bindings = {
            (record["policy"].configuration_name, record["policy"].peer_public_key, record["policy"].tunnel_address): record
            for record in records
        }
        rows: list[dict[str, Any]] = []
        live_bindings = set()

        for peer in peers:
            binding = (peer["configuration_name"], peer["peer_public_key"], peer.get("tunnel_address") or "")
            if not peer.get("eligible"):
                rows.append({**peer, "policy_status": "ineligible", "rules": [], "rule_count": 0})
                continue

            live_bindings.add(binding)
            record = bindings.get(binding)
            if record is None:
                rows.append({**peer, "policy_status": "unmanaged", "rules": [], "rule_count": 0})
                continue

            policy = record["policy"]
            if record["binding_status"] != "bound":
                status = "orphaned"
            elif record["managed"]:
                status = "managed"
            else:
                status = "disabled"
            rows.append(
                {
                    **peer,
                    "policy_status": status,
                    "rules": [rule.to_payload() for rule in policy.rules],
                    "rule_count": len(policy.rules),
                    "version": record["version"],
                    "last_apply_status": record["last_apply_status"],
                    "last_apply_at": record["last_apply_at"],
                    "updated_at": record["updated_at"],
                }
            )

        for record in records:
            policy = record["policy"]
            binding = (policy.configuration_name, policy.peer_public_key, policy.tunnel_address)
            if binding in live_bindings:
                continue
            rows.append(
                {
                    "configuration_name": policy.configuration_name,
                    "peer_public_key": policy.peer_public_key,
                    "peer_name": "",
                    "peer_status": "unknown",
                    "allowed_ip": policy.tunnel_address,
                    "tunnel_address": policy.tunnel_address,
                    "eligible": False,
                    "peer_present": False,
                    "policy_status": "orphaned",
                    "rules": [rule.to_payload() for rule in policy.rules],
                    "rule_count": len(policy.rules),
                    "version": record["version"],
                    "last_apply_status": record["last_apply_status"],
                    "last_apply_at": record["last_apply_at"],
                    "updated_at": record["updated_at"],
                }
            )

        active = [record["policy"] for record in records if record["managed"] and record["binding_status"] == "bound"]
        runtime = {"status": "not_applicable"}
        if active:
            expected_hash = policy_hash(active)
            try:
                status = self.agent_client.request("status")
                runtime = {
                    "status": "in_sync" if status.get("ruleset_hash") == expected_hash else "out_of_sync",
                    "hash": expected_hash,
                }
            except NetworkPolicyServiceError as error:
                runtime = {"status": "unavailable", "message": str(error)}

        return {
            "rows": sorted(rows, key=lambda row: (row["configuration_name"], row["peer_name"] or row["peer_public_key"], row["tunnel_address"])),
            "runtime": runtime,
        }

    def _desired_policies(self, policy: NetworkPolicy, policy_id: str | None = None) -> list[NetworkPolicy]:
        policies = self.repository.active_except({policy_id} if policy_id else None)
        if policy.managed:
            policies.append(policy)
        return policies

    def dry_run(self, payload: Any) -> dict[str, Any]:
        policy = validate_policy(payload)
        current = self.repository.get_current(
            policy.configuration_name, policy.peer_public_key, policy.tunnel_address
        )
        desired = self._desired_policies(policy, current[0] if current else None)
        return self.agent_client.request("dry_run", desired)

    def apply(self, payload: Any, actor: str, action: str = "apply") -> dict[str, Any]:
        policy = validate_policy(payload)
        candidate = self.repository.create_candidate(policy, actor, action)
        desired = self._desired_policies(policy, candidate.policy_id)
        try:
            result = self.agent_client.request("rollback" if action == "rollback" else "apply", desired)
        except (NetworkPolicyServiceError, PolicyValidationError, ValueError) as error:
            self.repository.mark_failed(candidate, action, str(error))
            raise NetworkPolicyServiceError(str(error)) from error
        self.repository.mark_applied(candidate, action, result.get("hash"))
        return {"policy": policy.to_payload(), "revision_id": candidate.revision_id, "agent": result}

    def deactivate(self, payload: Any, actor: str) -> dict[str, Any]:
        policy = validate_policy(payload)
        disabled = NetworkPolicy(
            configuration_name=policy.configuration_name,
            interface_name=policy.interface_name,
            peer_public_key=policy.peer_public_key,
            tunnel_address=policy.tunnel_address,
            managed=False,
            rules=(),
        )
        return self.apply(disabled.to_payload(), actor, action="deactivate")

    def rollback(self, revision_id: str, actor: str) -> dict[str, Any]:
        policy = self.repository.revision_policy(revision_id)
        if policy is None:
            raise NetworkPolicyServiceError("policy revision does not exist")
        return self.apply(policy.to_payload(), actor, action="rollback")

    def revision_policy(self, revision_id: str) -> NetworkPolicy | None:
        return self.repository.revision_policy(revision_id)

    def suspend_bindings(self, configuration_name: str, peer_public_keys: list[str], actor: str) -> None:
        """Remove stale allows before a Peer is deleted or its tunnel address changes."""
        current = self.repository.current_managed_for_peers(configuration_name, peer_public_keys)
        if not current:
            return

        candidates = []
        for policy_id, policy in current:
            suspended = NetworkPolicy(
                configuration_name=policy.configuration_name,
                interface_name=policy.interface_name,
                peer_public_key=policy.peer_public_key,
                tunnel_address=policy.tunnel_address,
                managed=True,
                rules=(),
            )
            candidate = self.repository.create_candidate(suspended, actor, action="suspend")
            if candidate.policy_id != policy_id:
                raise NetworkPolicyServiceError("policy binding changed while preparing suspension")
            candidates.append(candidate)

        desired = self.repository.active_except({candidate.policy_id for candidate in candidates})
        desired.extend(candidate.policy for candidate in candidates)
        try:
            result = self.agent_client.request("apply", desired)
        except NetworkPolicyServiceError as error:
            for candidate in candidates:
                self.repository.mark_failed(candidate, "suspend", str(error))
            raise
        for candidate in candidates:
            self.repository.mark_applied(candidate, "suspend", result.get("hash"), binding_status="orphaned")
