"""Versioned, restricted JSON protocol shared by Dashboard and Policy Agent."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from .validation import NetworkPolicy, PolicyValidationError, validate_policies


PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1_048_576
POLICY_ACTIONS = {"dry_run", "apply", "rollback"}
ALL_ACTIONS = POLICY_ACTIONS | {"capabilities", "status"}


class AgentProtocolError(ValueError):
    """The request did not conform to the fixed Policy Agent protocol."""


@dataclass(frozen=True)
class AgentRequest:
    action: str
    policies: tuple[NetworkPolicy, ...] = ()

    @classmethod
    def from_payload(cls, payload: Any) -> "AgentRequest":
        if not isinstance(payload, dict):
            raise AgentProtocolError("request must be an object")
        if payload.get("version") != PROTOCOL_VERSION:
            raise AgentProtocolError("unsupported protocol version")
        action = payload.get("action")
        if action not in ALL_ACTIONS:
            raise AgentProtocolError("unsupported action")
        if action in POLICY_ACTIONS:
            try:
                policies = validate_policies(payload.get("policies"))
            except PolicyValidationError as error:
                raise AgentProtocolError(str(error)) from error
        elif "policies" in payload:
            raise AgentProtocolError("action does not accept policies")
        else:
            policies = ()
        return cls(action=action, policies=policies)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"version": PROTOCOL_VERSION, "action": self.action}
        if self.action in POLICY_ACTIONS:
            payload["policies"] = [policy.to_payload() for policy in self.policies]
        return payload


def encode_message(payload: dict[str, Any]) -> bytes:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise AgentProtocolError("message exceeds size limit")
    return encoded


def decode_message(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_MESSAGE_BYTES:
        raise AgentProtocolError("invalid message size")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentProtocolError("invalid JSON message") from error
    if not isinstance(payload, dict):
        raise AgentProtocolError("message must be an object")
    return payload
