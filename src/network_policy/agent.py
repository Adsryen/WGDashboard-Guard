"""Privileged, deliberately small nftables Policy Agent.

Run this process separately from the Dashboard Web process. It only accepts
versioned JSON requests over a Unix socket and never receives shell commands.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
from typing import Callable, Sequence

from .agent_protocol import AgentProtocolError, AgentRequest, MAX_MESSAGE_BYTES, decode_message, encode_message
from .compiler import TABLE_FAMILY, TABLE_NAME, compile_check_ruleset, compile_ruleset

try:
    import grp
except ImportError:  # pragma: no cover - Windows cannot host the Unix socket Agent.
    grp = None


DEFAULT_SOCKET_PATH = "/run/wgd-network-policy/agent.sock"
CommandRunner = Callable[[Sequence[str], str | None], subprocess.CompletedProcess[str]]


class NftablesError(RuntimeError):
    """A fixed nftables operation failed."""


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


@dataclass(frozen=True)
class NftablesCapabilities:
    supported: bool
    message: str
    version: str | None = None

    def to_payload(self) -> dict:
        return {"supported": self.supported, "message": self.message, "version": self.version}


class NftablesExecutor:
    """The only component that invokes nft, always with a fixed argument list."""

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
            raise NftablesError(capabilities.message)

    def _invoke(self, arguments: Sequence[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        if self.nft_path is None:
            raise NftablesError("nftables executable was not found")
        try:
            result = self.runner([self.nft_path, *arguments], input_text)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise NftablesError(f"nftables invocation failed: {error}") from error
        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip() or "unknown nftables error"
            raise NftablesError(error)
        return result

    def _check(self, policies) -> tuple[str, str]:
        ruleset, digest = compile_check_ruleset(policies)
        self._invoke(["--check", "-f", "-"], ruleset)
        return ruleset, digest

    def _ensure_owned_table(self) -> None:
        if self.nft_path is None:
            raise NftablesError("nftables executable was not found")
        try:
            existing = self.runner([self.nft_path, "list", "table", TABLE_FAMILY, TABLE_NAME], None)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise NftablesError(f"cannot query owned nftables table: {error}") from error
        if existing.returncode == 0:
            return
        self._invoke(["add", "table", TABLE_FAMILY, TABLE_NAME])

    def dry_run(self, policies) -> dict:
        self._require_supported()
        ruleset, digest = self._check(policies)
        return {"ruleset": ruleset, "hash": digest, "applied": False}

    def apply(self, policies) -> dict:
        self._require_supported()
        _, digest = self._check(policies)
        self._ensure_owned_table()
        ruleset, _ = compile_ruleset(policies)
        self._invoke(["-f", "-"], ruleset)
        loaded = self._invoke(["list", "table", TABLE_FAMILY, TABLE_NAME]).stdout
        if policies and f"wgd-policy:{digest}" not in loaded:
            raise NftablesError("loaded ruleset hash could not be verified")
        return {"hash": digest, "applied": True}

    def status(self) -> dict:
        capabilities = self.capabilities()
        if not capabilities.supported:
            return {"capabilities": capabilities.to_payload(), "table_present": False}
        try:
            result = self.runner([self.nft_path, "list", "table", TABLE_FAMILY, TABLE_NAME], None)
        except (OSError, subprocess.TimeoutExpired) as error:
            return {"capabilities": capabilities.to_payload(), "table_present": False, "message": str(error)}
        loaded_hash = None
        if result.returncode == 0:
            match = re.search(r'wgd-policy:([a-f0-9]{64})', result.stdout)
            loaded_hash = match.group(1) if match else None
        return {
            "capabilities": capabilities.to_payload(),
            "table_present": result.returncode == 0,
            "ruleset_hash": loaded_hash,
        }


class PolicyAgent:
    def __init__(self, executor: NftablesExecutor | None = None):
        self.executor = executor or NftablesExecutor()

    def handle(self, request: AgentRequest) -> dict:
        if request.action == "capabilities":
            return {"capabilities": self.executor.capabilities().to_payload()}
        if request.action == "status":
            return self.executor.status()
        if request.action == "dry_run":
            return self.executor.dry_run(request.policies)
        if request.action in {"apply", "rollback"}:
            return self.executor.apply(request.policies)
        raise AgentProtocolError("unsupported action")


class PolicyAgentServer:
    """Synchronous local socket server; socket ownership is the access boundary."""

    def __init__(self, socket_path: str, socket_group: str, agent: PolicyAgent | None = None):
        self.socket_path = Path(socket_path)
        self.socket_group = socket_group
        self.agent = agent or PolicyAgent()

    def _prepare_socket_path(self) -> None:
        self.socket_path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        if self.socket_path.exists():
            mode = self.socket_path.stat().st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(f"refusing to replace non-socket path: {self.socket_path}")
            self.socket_path.unlink()

    def _set_socket_permissions(self) -> None:
        if grp is None:
            raise RuntimeError("network policy agent requires a Unix host")
        try:
            group_id = grp.getgrnam(self.socket_group).gr_gid
        except KeyError as error:
            raise RuntimeError(f"socket group does not exist: {self.socket_group}") from error
        os.chown(self.socket_path, 0, group_id)
        os.chmod(self.socket_path, 0o660)

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
                raise AgentProtocolError("message exceeds size limit")
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        return b"".join(chunks).split(b"\n", 1)[0]

    def _handle_connection(self, connection: socket.socket) -> None:
        try:
            request = AgentRequest.from_payload(decode_message(self._read_message(connection)))
            response = {"status": True, "message": None, "data": self.agent.handle(request)}
        except (AgentProtocolError, NftablesError, ValueError, RuntimeError) as error:
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
    parser = argparse.ArgumentParser(description="WGDashboard Network Policy Agent")
    parser.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--socket-group", default="wgdpolicy")
    args = parser.parse_args()
    PolicyAgentServer(args.socket, args.socket_group).serve_forever()


if __name__ == "__main__":
    main()
