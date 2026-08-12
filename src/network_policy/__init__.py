"""Declarative WireGuard peer forwarding policies."""

from .validation import NetworkPolicy, NetworkPolicyRule, PolicyValidationError, validate_policy

__all__ = [
    "NetworkPolicy",
    "NetworkPolicyRule",
    "PolicyValidationError",
    "validate_policy",
]
