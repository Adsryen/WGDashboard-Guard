"""Internal, local-only synchronization of live WireGuard bindings to the audit agent."""

from __future__ import annotations

import hashlib
import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol, Sequence

from network_policy.compiler import NFLOG_POLICY_DECISION_GROUP

from .agent import DEFAULT_SOCKET_PATH
from .agent_protocol import (
    AUDIT_CONFIG_VERSION,
    MAX_MESSAGE_BYTES,
    AuditAgentConfig,
    AuditAgentProtocolError,
    AuditAgentRequest,
    AuditMode,
    AuditPeerSnapshot,
    decode_message,
    encode_message,
)
from .health import ConfigSyncStatus, write_config_sync_snapshot
from .validation import AuditValidationError


DEFAULT_INTERFACE_NAME = "wg0"
OBSERVATION_NFLOG_GROUP = 11500
DEFAULT_SYNC_STATUS_PATH = "db/wgdashboard_audit_sync.json"
MAX_SYNC_ERROR_LENGTH = 255


class NetworkAuditSyncError(RuntimeError):
    """The dashboard could not synchronize a validated config to the local audit agent."""


class AuditAgentRequester(Protocol):
    def request(self, action: str, config: AuditAgentConfig | None = None) -> dict[str, Any]:
        """Send one fixed local audit-agent request."""


class AuditAgentClient:
    """Unix-socket client; it accepts config objects, never nftables programs or shell input."""

    def __init__(self, socket_path: str | None = None):
        self.socket_path = socket_path or os.getenv("WGD_NETWORK_AUDIT_SOCKET", DEFAULT_SOCKET_PATH)

    def request(self, action: str, config: AuditAgentConfig | None = None) -> dict[str, Any]:
        try:
            request = AuditAgentRequest(action, config)
        except AuditAgentProtocolError as error:
            raise NetworkAuditSyncError(str(error)) from error
        if not hasattr(socket, "AF_UNIX"):
            raise NetworkAuditSyncError("network audit agent is only available on Unix hosts")
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
                        raise NetworkAuditSyncError("audit agent response exceeds size limit")
                    chunks.append(chunk)
                    if b"\n" in chunk:
                        break
        except (OSError, socket.timeout) as error:
            raise NetworkAuditSyncError("network audit agent is unavailable") from error
        try:
            response = decode_message(b"".join(chunks).split(b"\n", 1)[0])
        except AuditAgentProtocolError as error:
            raise NetworkAuditSyncError(str(error)) from error
        if response.get("status") is not True:
            raise NetworkAuditSyncError(str(response.get("message") or "audit agent rejected the request"))
        data = response.get("data")
        if not isinstance(data, dict):
            raise NetworkAuditSyncError("audit agent returned an invalid response")
        return data


class AuditConfigSynchronizer:
    """Builds one auditable config solely from live peers and applied policy bindings."""

    def __init__(
        self,
        agent_client: AuditAgentRequester | None = None,
        *,
        interface_name: str = DEFAULT_INTERFACE_NAME,
        mode: AuditMode | str = AuditMode.ALL,
        sync_status_path: str | Path | None = None,
    ) -> None:
        self.agent_client = agent_client or AuditAgentClient()
        self.interface_name = interface_name
        self.sync_status_path = Path(
            sync_status_path or os.getenv("WGD_NETWORK_AUDIT_SYNC_STATUS", DEFAULT_SYNC_STATUS_PATH)
        )
        try:
            self.mode = AuditMode(mode)
        except ValueError as error:
            raise ValueError("mode must be all or managed") from error

    def sync(self, live_peers: Sequence[Mapping[str, Any]], policy_records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
        try:
            config = self.build_config(live_peers, policy_records)
        except NetworkAuditSyncError as error:
            self._write_sync_status(ConfigSyncStatus.FAILED, 0, str(error))
            raise
        try:
            result = self.agent_client.request("apply", config)
        except NetworkAuditSyncError as error:
            self._write_sync_status(ConfigSyncStatus.FAILED, config.generation, str(error))
            raise
        self._write_sync_status(ConfigSyncStatus.APPLIED, config.generation, None)
        return result

    def _write_sync_status(self, status: ConfigSyncStatus, generation: int, error: str | None) -> None:
        bounded_error = error[:MAX_SYNC_ERROR_LENGTH] if error is not None else None
        try:
            write_config_sync_snapshot(
                self.sync_status_path,
                {
                    "status": status.value,
                    "updated_at": datetime.now(timezone.utc),
                    "generation": generation,
                    "error": bounded_error,
                },
            )
        except OSError:
            return

    def build_config(
        self,
        live_peers: Sequence[Mapping[str, Any]],
        policy_records: Sequence[Mapping[str, Any]],
    ) -> AuditAgentConfig:
        peers = self._live_peer_snapshots(live_peers)
        managed_addresses = self._managed_addresses(policy_records, peers)
        payload = {
            "version": AUDIT_CONFIG_VERSION,
            "generation": 0,
            "interface_name": self.interface_name,
            "mode": self.mode.value,
            "peers": [peer.to_payload() for peer in peers],
            "managed_tunnel_addresses": list(managed_addresses),
            "observation_nflog_group": OBSERVATION_NFLOG_GROUP,
            "policy_allowed_nflog_group": NFLOG_POLICY_DECISION_GROUP,
            "policy_denied_nflog_group": NFLOG_POLICY_DECISION_GROUP,
        }
        generation = int.from_bytes(
            hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()[:8],
            "big",
        )
        return AuditAgentConfig(
            version=AUDIT_CONFIG_VERSION,
            generation=generation,
            interface_name=self.interface_name,
            mode=self.mode,
            peers=tuple(peers),
            managed_tunnel_addresses=managed_addresses,
            observation_nflog_group=OBSERVATION_NFLOG_GROUP,
            policy_allowed_nflog_group=NFLOG_POLICY_DECISION_GROUP,
            policy_denied_nflog_group=NFLOG_POLICY_DECISION_GROUP,
        )

    def _live_peer_snapshots(self, live_peers: Sequence[Mapping[str, Any]]) -> tuple[AuditPeerSnapshot, ...]:
        snapshots: list[AuditPeerSnapshot] = []
        addresses: set[str] = set()
        for peer in live_peers:
            if peer.get("configuration_name") != self.interface_name or peer.get("eligible") is not True:
                continue
            try:
                snapshot = AuditPeerSnapshot(
                    configuration_name=peer.get("configuration_name"),
                    public_key=peer.get("peer_public_key"),
                    peer_name=peer.get("peer_name") or "",
                    tunnel_address=peer.get("tunnel_address"),
                )
            except AuditValidationError as error:
                raise NetworkAuditSyncError("live peer snapshot is invalid") from error
            if snapshot.tunnel_address not in addresses:
                snapshots.append(snapshot)
                addresses.add(snapshot.tunnel_address)
        return tuple(sorted(snapshots, key=lambda peer: (peer.tunnel_address, peer.public_key)))

    def _managed_addresses(
        self,
        policy_records: Sequence[Mapping[str, Any]],
        peers: tuple[AuditPeerSnapshot, ...],
    ) -> tuple[str, ...]:
        live_addresses = {peer.tunnel_address for peer in peers}
        managed = set()
        for record in policy_records:
            policy = record.get("policy")
            if (
                not getattr(policy, "managed", False)
                or getattr(policy, "configuration_name", None) != self.interface_name
                or getattr(policy, "interface_name", None) != self.interface_name
                or record.get("binding_status") != "bound"
                or record.get("last_apply_status") != "applied"
            ):
                continue
            if policy.tunnel_address in live_addresses:
                managed.add(policy.tunnel_address)
        return tuple(sorted(managed))
