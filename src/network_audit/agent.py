"""Restricted nftables agent for the independently owned audit table."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
from typing import Callable, Sequence

from .agent_protocol import (
    AuditAgentConfig,
    AuditAgentProtocolError,
    AuditAgentRequest,
    AuditMode,
    MAX_MESSAGE_BYTES,
    decode_message,
    encode_message,
)

try:
    import grp
except ImportError:  # pragma: no cover - Windows cannot host the Unix socket agent.
    grp = None


TABLE_FAMILY = "inet"
TABLE_NAME = "wgd_network_audit"
CHAIN_NAME = "forward_observation"
CHAIN_PRIORITY = "filter - 20"
OWNER_MARKER = "wgd-audit-owner:v1"
RENDERER_VERSION = 1
DEFAULT_SOCKET_PATH = "/run/wgd-network-audit/agent.sock"
DEFAULT_CONFIG_PATH = "/run/wgd-network-audit/config.json"
CommandRunner = Callable[[Sequence[str], str | None], subprocess.CompletedProcess[str]]


class AuditNftablesError(RuntimeError):
    """A fixed audit-table nftables operation failed."""


def _run_command(command: Sequence[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        input=input_text,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
    )


def _validate_table_name(table_name: str) -> None:
    if table_name != TABLE_NAME and not table_name.endswith("_check"):
        raise ValueError("unsupported nftables table name")


def audit_config_hash(config: AuditAgentConfig) -> str:
    canonical = json.dumps(
        {"renderer_version": RENDERER_VERSION, "config": config.to_payload()},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def compile_ruleset(config: AuditAgentConfig, table_name: str = TABLE_NAME) -> tuple[str, str]:
    _validate_table_name(table_name)
    digest = audit_config_hash(config)
    lines = [
        f"flush table {TABLE_FAMILY} {table_name}",
        (
            f"add chain {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f"{{ type filter hook forward priority {CHAIN_PRIORITY}; policy accept; "
            f"comment \"{OWNER_MARKER} wgd-audit:{digest}\"; }}"
        ),
    ]
    managed_addresses = set(config.managed_tunnel_addresses)
    observed_addresses = (
        managed_addresses
        if config.mode == AuditMode.MANAGED
        else {peer.tunnel_address for peer in config.peers} - managed_addresses
    )
    for address in sorted(observed_addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value)))):
        family = "ip" if ipaddress.ip_address(address).version == 4 else "ip6"
        lines.append(
            f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f'iifname "{config.interface_name}" {family} saddr {address} ct state new '
            f'log prefix "wgd-audit:forward_observed" group {config.observation_nflog_group} '
            f'comment "wgd-audit:{digest}"'
        )
    return "\n".join(lines) + "\n", digest


def compile_audit_check_ruleset(config: AuditAgentConfig) -> tuple[str, str]:
    body, digest = compile_ruleset(config, f"{TABLE_NAME}_check")
    return f"add table {TABLE_FAMILY} {TABLE_NAME}_check\n{body}", digest


def write_applied_config(path: str | Path, config: AuditAgentConfig) -> None:
    """Atomically publish the config corresponding to the last applied audit table."""
    target = Path(path)
    target.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
            os.fchmod(config_file.fileno(), 0o640)
            json.dump(config.to_payload(), config_file, sort_keys=True, separators=(",", ":"))
            config_file.flush()
            os.fsync(config_file.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_applied_config(path: str | Path) -> AuditAgentConfig:
    with Path(path).open(encoding="utf-8") as config_file:
        return AuditAgentConfig.from_payload(json.load(config_file))


@dataclass(frozen=True)
class NftablesCapabilities:
    supported: bool
    message: str
    version: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {"supported": self.supported, "message": self.message, "version": self.version}


class AuditNftablesExecutor:
    """The only component in this package allowed to invoke nft."""

    def __init__(self, runner: CommandRunner = _run_command):
        self.runner = runner
        self.nft_path = shutil.which("nft")

    def capabilities(self) -> NftablesCapabilities:
        if self.nft_path is None:
            return NftablesCapabilities(False, "nftables executable was not found")
        try:
            result = self.runner([self.nft_path, "--version"], None)
        except (OSError, subprocess.TimeoutExpired) as error:
            return NftablesCapabilities(False, f"nftables cannot be executed: {error}")
        if result.returncode != 0:
            return NftablesCapabilities(False, "nftables version check failed")
        return NftablesCapabilities(True, "nftables is available", result.stdout.strip())

    def _require_supported(self) -> None:
        capabilities = self.capabilities()
        if not capabilities.supported:
            raise AuditNftablesError(capabilities.message)

    def _invoke(self, arguments: Sequence[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        if self.nft_path is None:
            raise AuditNftablesError("nftables executable was not found")
        try:
            result = self.runner([self.nft_path, *arguments], input_text)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AuditNftablesError(f"nftables invocation failed: {error}") from error
        if result.returncode != 0:
            message = result.stderr.strip() or result.stdout.strip() or "unknown nftables error"
            raise AuditNftablesError(message)
        return result

    def _check(self, config: AuditAgentConfig) -> tuple[str, str]:
        ruleset, digest = compile_audit_check_ruleset(config)
        self._invoke(["--check", "-f", "-"], ruleset)
        return ruleset, digest

    def _ensure_owned_table(self) -> None:
        if self.nft_path is None:
            raise AuditNftablesError("nftables executable was not found")
        try:
            existing = self.runner([self.nft_path, "list", "table", TABLE_FAMILY, TABLE_NAME], None)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AuditNftablesError(f"cannot query owned nftables table: {error}") from error
        if existing.returncode == 0:
            if OWNER_MARKER not in existing.stdout:
                raise AuditNftablesError("refusing to replace an unowned audit table")
            return
        self._invoke(["add", "table", TABLE_FAMILY, TABLE_NAME])

    def dry_run(self, config: AuditAgentConfig) -> dict[str, object]:
        self._require_supported()
        ruleset, digest = self._check(config)
        return {"ruleset": ruleset, "hash": digest, "applied": False}

    def apply(self, config: AuditAgentConfig) -> dict[str, object]:
        self._require_supported()
        _, digest = self._check(config)
        self._ensure_owned_table()
        ruleset, _ = compile_ruleset(config)
        self._invoke(["-f", "-"], ruleset)
        loaded = self._invoke(["list", "table", TABLE_FAMILY, TABLE_NAME]).stdout
        if OWNER_MARKER not in loaded or f"wgd-audit:{digest}" not in loaded:
            raise AuditNftablesError("loaded audit ruleset hash could not be verified")
        return {"hash": digest, "applied": True}

    def status(self) -> dict[str, object]:
        capabilities = self.capabilities()
        if not capabilities.supported:
            return {"capabilities": capabilities.to_payload(), "table_present": False}
        result = self.runner([self.nft_path, "list", "table", TABLE_FAMILY, TABLE_NAME], None)
        if result.returncode != 0:
            return {"capabilities": capabilities.to_payload(), "table_present": False}
        return {
            "capabilities": capabilities.to_payload(),
            "table_present": True,
            "owned": OWNER_MARKER in result.stdout,
            "ruleset": result.stdout,
        }

    def remove(self) -> dict[str, object]:
        self._require_supported()
        if self.nft_path is None:
            raise AuditNftablesError("nftables executable was not found")
        result = self.runner([self.nft_path, "list", "table", TABLE_FAMILY, TABLE_NAME], None)
        if result.returncode != 0:
            return {"removed": False, "table_present": False}
        if OWNER_MARKER not in result.stdout:
            raise AuditNftablesError("refusing to remove an unowned audit table")
        self._invoke(["delete", "table", TABLE_FAMILY, TABLE_NAME])
        return {"removed": True, "table_present": False}


class AuditAgent:
    """Maps a fixed local protocol to the owned audit-table executor."""

    def __init__(
        self,
        executor: AuditNftablesExecutor | None = None,
        config_path: str | Path = DEFAULT_CONFIG_PATH,
    ):
        self.executor = executor or AuditNftablesExecutor()
        self.config_path = Path(config_path)

    def handle(self, request: AuditAgentRequest) -> dict[str, object]:
        if request.action == "capabilities":
            return {"capabilities": self.executor.capabilities().to_payload()}
        if request.action == "status":
            return self.executor.status()
        if request.action == "remove":
            result = self.executor.remove()
            if result.get("removed") is True and self.config_path.exists():
                self.config_path.unlink()
            return result
        if request.action == "dry_run":
            return self.executor.dry_run(request.config)
        if request.action == "apply":
            result = self.executor.apply(request.config)
            write_applied_config(self.config_path, request.config)
            return result
        raise AuditAgentProtocolError("unsupported action")


class AuditAgentServer:
    """A group-restricted local socket server; filesystem ownership is the boundary."""

    def __init__(self, socket_path: str, socket_group: str, agent: AuditAgent | None = None):
        self.socket_path = Path(socket_path)
        self.socket_group = socket_group
        self.agent = agent or AuditAgent()

    def _prepare_socket_path(self) -> None:
        self.socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        if self.socket_path.exists():
            mode = self.socket_path.stat().st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(f"refusing to replace non-socket path: {self.socket_path}")
            self.socket_path.unlink()

    def _set_socket_permissions(self) -> None:
        if grp is None:
            raise RuntimeError("network audit agent requires a Unix host")
        try:
            group_id = grp.getgrnam(self.socket_group).gr_gid
        except KeyError as error:
            raise RuntimeError(f"socket group does not exist: {self.socket_group}") from error
        os.chown(self.socket_path, 0, group_id)
        os.chmod(self.socket_path, 0o660)

    def _socket_group_id(self) -> int:
        if grp is None:
            raise RuntimeError("network audit agent requires a Unix host")
        try:
            return grp.getgrnam(self.socket_group).gr_gid
        except KeyError as error:
            raise RuntimeError(f"socket group does not exist: {self.socket_group}") from error

    @staticmethod
    def _peer_groups(process_id: int, primary_group_id: int) -> set[int]:
        groups = {primary_group_id}
        try:
            for line in Path(f"/proc/{process_id}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("Groups:"):
                    groups.update(int(group_id) for group_id in line.split()[1:])
                    break
        except (OSError, ValueError):
            return groups
        return groups

    @staticmethod
    def _credentials_are_authorized(user_id: int, group_ids: set[int], socket_group_id: int) -> bool:
        return user_id == 0 or socket_group_id in group_ids

    def _peer_is_authorized(self, connection: socket.socket) -> bool:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AuditAgentProtocolError("Unix peer credentials are unavailable")
        credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        process_id, user_id, primary_group_id = struct.unpack("3i", credentials)
        return self._credentials_are_authorized(
            user_id,
            self._peer_groups(process_id, primary_group_id),
            self._socket_group_id(),
        )

    @staticmethod
    def _read_message(connection: socket.socket) -> bytes:
        chunks: list[bytes] = []
        received = 0
        while True:
            chunk = connection.recv(min(4096, MAX_MESSAGE_BYTES - received + 1))
            if not chunk:
                break
            received += len(chunk)
            if received > MAX_MESSAGE_BYTES:
                raise AuditAgentProtocolError("message exceeds size limit")
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks).split(b"\n", 1)[0]

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            if not self._peer_is_authorized(connection):
                raise AuditAgentProtocolError("audit agent socket peer is not authorized")
            request = AuditAgentRequest.from_payload(decode_message(self._read_message(connection)))
            response = {"status": True, "message": None, "data": self.agent.handle(request)}
        except (AuditAgentProtocolError, AuditNftablesError, ValueError, RuntimeError) as error:
            response = {"status": False, "message": str(error), "data": None}
        connection.sendall(encode_message(response))

    def serve_forever(self) -> None:
        self._prepare_socket_path()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            self._set_socket_permissions()
            listener.listen(16)
            while True:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(20)
                    self._handle_connection(connection)
        finally:
            listener.close()
            if self.socket_path.exists() and stat.S_ISSOCK(self.socket_path.stat().st_mode):
                self.socket_path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description="WGDashboard Network Audit Agent")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--socket-group", default="wgdaudit")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    args = parser.parse_args()
    AuditAgentServer(args.socket, args.socket_group, AuditAgent(config_path=args.config)).serve_forever()


if __name__ == "__main__":
    main()
