"""Collector orchestration and safe adapter capability checks."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import importlib.util
import ipaddress
import queue
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

from .agent_protocol import AuditAgentConfig
from .agent import DEFAULT_CONFIG_PATH, read_applied_config
from .correlation import FlowCorrelator
from .health import (
    ConfigSyncStatus,
    HealthSnapshot,
    HealthStatus,
    read_config_sync_snapshot,
    write_health_snapshot,
)
from .models import ConntrackEvent, FlowKey, NflogEvent
from .spool import AuditSpool
from .validation import AuditObservation, AuditValidationError


@dataclass(frozen=True)
class AdapterCapability:
    available: bool
    detail: str | None = None


class CollectorCapabilityError(RuntimeError):
    """Raised when a required local netfilter event source is unavailable."""


class MetadataDecodeError(ValueError):
    """A netlink message did not contain the bounded metadata this collector needs."""


_NLMSG_HEADER = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("!BBH")
_NLA_HEADER = struct.Struct("=HH")
_NLA_TYPE_MASK = 0x3FFF
_NFULA_PAYLOAD = 9
_NFULA_PREFIX = 10
_NLM_F_CREATE = 0x400
_IPCTNL_MSG_CT_NEW = 0
_IPCTNL_MSG_CT_DELETE = 2
_DECISION_PREFIXES = {
    "wgd-audit:forward_observed": "forward_observed",
    "wgd-audit:policy_allowed": "policy_allowed",
    "wgd-audit:policy_denied": "policy_denied",
}


def _align(length: int) -> int:
    return (length + 3) & ~3


def _netlink_attributes(message: bytes) -> Iterator[tuple[int, bytes]]:
    offset = 0
    while offset < len(message):
        if len(message) - offset < _NLA_HEADER.size:
            raise MetadataDecodeError("truncated netlink attribute header")
        length, attribute_type = _NLA_HEADER.unpack_from(message, offset)
        if length < _NLA_HEADER.size or offset + length > len(message):
            raise MetadataDecodeError("invalid netlink attribute length")
        yield attribute_type & _NLA_TYPE_MASK, message[offset + _NLA_HEADER.size:offset + length]
        offset += _align(length)
    if offset != len(message):
        raise MetadataDecodeError("invalid netlink attribute alignment")


def _parse_packet_flow(packet: bytes) -> FlowKey:
    if not packet:
        raise MetadataDecodeError("NFLOG packet metadata is missing")
    version = packet[0] >> 4
    if version == 4:
        if len(packet) < 20:
            raise MetadataDecodeError("truncated IPv4 header")
        header_length = (packet[0] & 0x0F) * 4
        fragment_offset = struct.unpack_from("!H", packet, 6)[0] & 0x1FFF
        if header_length < 20 or len(packet) < header_length or fragment_offset:
            raise MetadataDecodeError("unsupported IPv4 packet layout")
        protocol_number = packet[9]
        source_address = str(ipaddress.IPv4Address(packet[12:16]))
        destination_address = str(ipaddress.IPv4Address(packet[16:20]))
        transport_offset = header_length
    elif version == 6:
        if len(packet) < 40:
            raise MetadataDecodeError("truncated IPv6 header")
        protocol_number = packet[6]
        source_address = str(ipaddress.IPv6Address(packet[8:24]))
        destination_address = str(ipaddress.IPv6Address(packet[24:40]))
        transport_offset = 40
    else:
        raise MetadataDecodeError("unsupported IP version")

    protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}.get(protocol_number)
    if protocol is None:
        raise MetadataDecodeError("unsupported IP protocol")
    if protocol == "icmp":
        return FlowKey(source_address, destination_address, protocol, None, None)
    if len(packet) < transport_offset + 4:
        raise MetadataDecodeError("truncated transport header")
    source_port, destination_port = struct.unpack_from("!HH", packet, transport_offset)
    return FlowKey(source_address, destination_address, protocol, source_port, destination_port)


def decode_nflog_datagram(
    datagram: bytes,
    *,
    accepted_groups: set[int],
    now: datetime | None = None,
) -> list[NflogEvent]:
    """Decode only fixed NFLOG metadata and discard every raw packet buffer immediately."""
    current_time = _normalized_time(now)
    events: list[NflogEvent] = []
    offset = 0
    while offset < len(datagram):
        if len(datagram) - offset < _NLMSG_HEADER.size + _NFGENMSG.size:
            return events
        message_length, _message_type, _flags, _sequence, _pid = _NLMSG_HEADER.unpack_from(datagram, offset)
        if message_length < _NLMSG_HEADER.size + _NFGENMSG.size or offset + message_length > len(datagram):
            return events
        family, _version, group = _NFGENMSG.unpack_from(datagram, offset + _NLMSG_HEADER.size)
        message = datagram[offset + _NLMSG_HEADER.size + _NFGENMSG.size:offset + message_length]
        try:
            attributes = dict(_netlink_attributes(message))
            prefix = attributes.get(_NFULA_PREFIX, b"").split(b"\x00", 1)[0].decode("ascii")
            packet = attributes.get(_NFULA_PAYLOAD)
            decision = _DECISION_PREFIXES.get(prefix)
            if family in (socket.AF_INET, socket.AF_INET6) and group in accepted_groups and decision is not None and packet is not None:
                events.append(NflogEvent(_parse_packet_flow(packet), decision, current_time))
        except (MetadataDecodeError, UnicodeDecodeError, AuditValidationError):
            pass
        offset += _align(message_length)
    return events


def _attribute_value(message: Any, name: str) -> Any:
    if hasattr(message, "get_attr"):
        return message.get_attr(name)
    if isinstance(message, Mapping):
        if name in message:
            return message[name]
        attributes = message.get("attrs", ())
        if isinstance(attributes, (list, tuple)):
            for entry in attributes:
                if isinstance(entry, (list, tuple)) and len(entry) == 2 and entry[0] == name:
                    return entry[1]
    return None


def _conntrack_protocol(value: Any) -> str:
    protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}.get(value)
    if protocol is None:
        raise MetadataDecodeError("unsupported conntrack protocol")
    return protocol


def decode_conntrack_message(message: Any, *, now: datetime | None = None) -> ConntrackEvent:
    """Normalize pyroute2 conntrack metadata without retaining its netlink object."""
    original_tuple = _attribute_value(message, "CTA_TUPLE_ORIG")
    ip_tuple = _attribute_value(original_tuple, "CTA_TUPLE_IP")
    protocol_tuple = _attribute_value(original_tuple, "CTA_TUPLE_PROTO")
    source_address = _attribute_value(ip_tuple, "CTA_IP_V4_SRC") or _attribute_value(ip_tuple, "CTA_IP_V6_SRC")
    destination_address = _attribute_value(ip_tuple, "CTA_IP_V4_DST") or _attribute_value(ip_tuple, "CTA_IP_V6_DST")
    protocol = _conntrack_protocol(_attribute_value(protocol_tuple, "CTA_PROTO_NUM"))
    if not isinstance(source_address, str) or not isinstance(destination_address, str):
        raise MetadataDecodeError("conntrack tuple addresses are missing")
    if protocol == "icmp":
        source_port = destination_port = None
    else:
        source_port = _attribute_value(protocol_tuple, "CTA_PROTO_SRC_PORT")
        destination_port = _attribute_value(protocol_tuple, "CTA_PROTO_DST_PORT")
    original_counters = _attribute_value(message, "CTA_COUNTERS_ORIG")
    reply_counters = _attribute_value(message, "CTA_COUNTERS_REPLY")
    header = message.get("header", {}) if isinstance(message, Mapping) else getattr(message, "header", {})
    message_type = header.get("type", _IPCTNL_MSG_CT_NEW) & 0xFF if isinstance(header, Mapping) else _IPCTNL_MSG_CT_NEW
    flags = header.get("flags", 0) if isinstance(header, Mapping) else 0
    event_type = (
        "destroy" if message_type == _IPCTNL_MSG_CT_DELETE
        else "new" if flags & _NLM_F_CREATE
        else "update"
    )
    return ConntrackEvent(
        event_type,
        FlowKey(source_address, destination_address, protocol, source_port, destination_port, _attribute_value(message, "CTA_ZONE") or 0),
        _normalized_time(now),
        _attribute_value(original_counters, "CTA_COUNTERS_BYTES") or 0,
        _attribute_value(reply_counters, "CTA_COUNTERS_BYTES") or 0,
    )


def _normalized_time(value: datetime | None) -> datetime:
    current_time = value or datetime.now(timezone.utc)
    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("timestamps must include a timezone")
    return current_time.astimezone(timezone.utc)


def _netlink_multicast_mask(groups: tuple[int, ...]) -> int:
    """Convert one-based netlink multicast group numbers to a membership bitmask."""
    mask = 0
    for group in groups:
        if group < 1:
            raise ValueError("netlink multicast groups must be positive")
        mask |= 1 << (group - 1)
    return mask


class ConntrackEventAdapter(Protocol):
    def capability(self) -> AdapterCapability:
        """Return whether this host can subscribe to conntrack events."""

    def events(self) -> Iterator[ConntrackEvent]:
        """Yield normalized metadata-only conntrack events."""


class NflogEventAdapter(Protocol):
    def capability(self) -> AdapterCapability:
        """Return whether this host can open the configured NFLOG family."""

    def events(self) -> Iterator[NflogEvent]:
        """Yield normalized metadata-only NFLOG events."""


class Pyroute2ConntrackAdapter:
    """Read conntrack multicast datagrams with pyroute2's schema-only decoder."""

    NETLINK_NETFILTER = 12

    def capability(self) -> AdapterCapability:
        if importlib.util.find_spec("pyroute2") is None:
            return AdapterCapability(False, "pyroute2 is not installed")
        try:
            from pyroute2.netlink.nfnetlink import (  # type: ignore[import-not-found]
                NFNLGRP_CONNTRACK_DESTROY,
                NFNLGRP_CONNTRACK_NEW,
                NFNLGRP_CONNTRACK_UPDATE,
            )
            from pyroute2.netlink.nfnetlink.nfctsocket import AsyncNFCTSocket  # type: ignore[import-not-found]
        except ImportError:
            return AdapterCapability(False, "pyroute2 lacks conntrack netlink support")
        if not all((NFNLGRP_CONNTRACK_NEW, NFNLGRP_CONNTRACK_UPDATE, NFNLGRP_CONNTRACK_DESTROY)):
            return AdapterCapability(False, "pyroute2 conntrack multicast groups are unavailable")
        if not callable(AsyncNFCTSocket):
            return AdapterCapability(False, "pyroute2 conntrack decoder is unavailable")
        if not hasattr(socket, "AF_NETLINK"):
            return AdapterCapability(False, "AF_NETLINK is unsupported on this platform")
        try:
            conntrack_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, self.NETLINK_NETFILTER)
        except OSError as error:
            return AdapterCapability(False, f"conntrack socket unavailable: {error.errno}")
        conntrack_socket.close()
        return AdapterCapability(True)

    def events(self) -> Iterator[ConntrackEvent]:
        capability = self.capability()
        if not capability.available:
            raise CollectorCapabilityError(capability.detail or "conntrack is unavailable")
        from pyroute2.netlink.nfnetlink import (  # type: ignore[import-not-found]
            NFNLGRP_CONNTRACK_DESTROY,
            NFNLGRP_CONNTRACK_NEW,
            NFNLGRP_CONNTRACK_UPDATE,
        )
        from pyroute2.netlink.nfnetlink.nfctsocket import AsyncNFCTSocket  # type: ignore[import-not-found]

        parser = AsyncNFCTSocket()
        groups = _netlink_multicast_mask(
            (NFNLGRP_CONNTRACK_NEW, NFNLGRP_CONNTRACK_UPDATE, NFNLGRP_CONNTRACK_DESTROY)
        )
        conntrack_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, self.NETLINK_NETFILTER)
        try:
            conntrack_socket.bind((0, groups))
            while True:
                for message in parser.marshal.parse(conntrack_socket.recv(65536), 0):
                    try:
                        yield decode_conntrack_message(message)
                    except (MetadataDecodeError, AuditValidationError):
                        continue
        except OSError as error:
            raise CollectorCapabilityError("conntrack subscription is unavailable") from error
        finally:
            conntrack_socket.close()
            parser.close()


class NflogSocketAdapter:
    """Bounded raw NFLOG decoder that releases packet bytes before yielding events."""

    NETLINK_NETFILTER = 12
    _NLMSG_ERROR = 2
    _NLM_F_REQUEST = 1
    _NLM_F_ACK = 4
    _NFNL_SUBSYS_ULOG = 4
    _NFULNL_MSG_CONFIG = 1
    _NFULA_CFG_CMD = 1
    _NFULA_CFG_MODE = 2
    _NFULNL_CFG_CMD_BIND = 1
    _NFULNL_CFG_CMD_PF_BIND = 3
    _NFULNL_COPY_PACKET = 2

    def __init__(self, accepted_groups: set[int] | None = None):
        self.accepted_groups = set(accepted_groups or ())

    def capability(self) -> AdapterCapability:
        if not hasattr(socket, "AF_NETLINK"):
            return AdapterCapability(False, "AF_NETLINK is unsupported on this platform")
        try:
            nflog_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, self.NETLINK_NETFILTER)
        except OSError as error:
            return AdapterCapability(False, f"NFLOG socket unavailable: {error.errno}")
        nflog_socket.close()
        return AdapterCapability(True)

    def events(self) -> Iterator[NflogEvent]:
        if not self.accepted_groups:
            raise CollectorCapabilityError("NFLOG group configuration is unavailable")
        capability = self.capability()
        if not capability.available:
            raise CollectorCapabilityError(capability.detail or "NFLOG is unavailable")
        nflog_socket = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, self.NETLINK_NETFILTER)
        try:
            nflog_socket.bind((0, 0))
            self._configure_socket(nflog_socket)
            while True:
                for event in decode_nflog_datagram(
                    nflog_socket.recv(65536), accepted_groups=self.accepted_groups
                ):
                    yield event
        except OSError as error:
            raise CollectorCapabilityError("NFLOG subscription is unavailable") from error
        finally:
            nflog_socket.close()

    @staticmethod
    def _attribute(attribute_type: int, value: bytes) -> bytes:
        length = _NLA_HEADER.size + len(value)
        return _NLA_HEADER.pack(length, attribute_type) + value + (b"\x00" * (_align(length) - length))

    def _configuration_message(self, *, family: int, resource_id: int, attributes: list[bytes], sequence: int) -> bytes:
        body = _NFGENMSG.pack(family, 0, resource_id) + b"".join(attributes)
        return _NLMSG_HEADER.pack(
            _NLMSG_HEADER.size + len(body),
            (self._NFNL_SUBSYS_ULOG << 8) | self._NFULNL_MSG_CONFIG,
            self._NLM_F_REQUEST | self._NLM_F_ACK,
            sequence,
            0,
        ) + body

    @staticmethod
    def _configuration_attributes(message: bytes) -> Iterator[tuple[int, bytes]]:
        if len(message) < _NLMSG_HEADER.size + _NFGENMSG.size:
            raise MetadataDecodeError("truncated NFLOG configuration message")
        message_length, _message_type, _flags, _sequence, _pid = _NLMSG_HEADER.unpack_from(message)
        if message_length != len(message):
            raise MetadataDecodeError("invalid NFLOG configuration message length")
        return _netlink_attributes(message[_NLMSG_HEADER.size + _NFGENMSG.size:])

    def _configure_socket(self, nflog_socket: socket.socket) -> None:
        sequence = 1
        for family in (socket.AF_INET, socket.AF_INET6):
            command = self._configuration_message(
                family=family,
                resource_id=0,
                attributes=[self._attribute(self._NFULA_CFG_CMD, bytes((self._NFULNL_CFG_CMD_PF_BIND,)))],
                sequence=sequence,
            )
            self._send_and_expect_ack(nflog_socket, command, sequence)
            sequence += 1
        for group in sorted(self.accepted_groups):
            command = self._configuration_message(
                family=socket.AF_UNSPEC,
                resource_id=group,
                attributes=[
                    self._attribute(self._NFULA_CFG_CMD, bytes((self._NFULNL_CFG_CMD_BIND,))),
                    self._attribute(self._NFULA_CFG_MODE, struct.pack("!IBx", 64, self._NFULNL_COPY_PACKET)),
                ],
                sequence=sequence,
            )
            self._send_and_expect_ack(nflog_socket, command, sequence)
            sequence += 1

    def _send_and_expect_ack(self, nflog_socket: socket.socket, message: bytes, sequence: int) -> None:
        nflog_socket.sendto(message, (0, 0))
        response = nflog_socket.recv(65536)
        if len(response) < _NLMSG_HEADER.size + 4:
            raise CollectorCapabilityError("NFLOG configuration acknowledgement is invalid")
        response_length, response_type, _flags, response_sequence, _pid = _NLMSG_HEADER.unpack_from(response)
        if response_length > len(response) or response_type != self._NLMSG_ERROR or response_sequence != sequence:
            raise CollectorCapabilityError("NFLOG configuration acknowledgement is invalid")
        error_code = struct.unpack_from("=i", response, _NLMSG_HEADER.size)[0]
        if error_code != 0:
            raise CollectorCapabilityError("NFLOG configuration was rejected")


class AuditCollector:
    """Moves correlated observations through the bounded spool into the audit service."""

    def __init__(
        self,
        config: AuditAgentConfig,
        spool: AuditSpool,
        writer: Callable[[AuditObservation], None],
        *,
        correlator: FlowCorrelator | None = None,
        health_path: str | Path | None = None,
        sync_status_path: str | Path | None = None,
        retry_delay: timedelta = timedelta(seconds=5),
        now: datetime | None = None,
    ) -> None:
        if retry_delay <= timedelta(0):
            raise ValueError("retry_delay must be greater than zero")
        self.config = config
        self.spool = spool
        self.writer = writer
        self.correlator = correlator or FlowCorrelator()
        self.health_path = Path(health_path) if health_path is not None else None
        self.sync_status_path = Path(sync_status_path) if sync_status_path is not None else None
        self.retry_delay = retry_delay
        self.started_at = self._current_time(now)
        self.last_event_at: datetime | None = None
        self.last_persisted_at: datetime | None = None
        self.nflog_events = 0
        self.conntrack_events = 0
        self.write_failures = 0
        self.last_error: str | None = None
        self.status = HealthStatus.STARTING

    def handle_conntrack(self, event: ConntrackEvent) -> None:
        self.conntrack_events += 1
        self.last_event_at = event.observed_at
        self._enqueue(self.correlator.consume_conntrack(event, self.config), now=event.observed_at)

    def handle_nflog(self, event: NflogEvent) -> None:
        self.nflog_events += 1
        self.last_event_at = event.observed_at
        self._enqueue(self.correlator.consume_nflog(event), now=event.observed_at)

    def expire(self, now: datetime | None = None) -> int:
        current_time = self._current_time(now)
        observations = self.correlator.expire(current_time)
        self._enqueue(observations, now=current_time)
        return len(observations)

    def flush(self, now: datetime | None = None, limit: int = 100) -> int:
        current_time = self._current_time(now)
        persisted = 0
        for item in self.spool.due_items(now=current_time, limit=limit):
            try:
                self.writer(item.observation)
            except Exception:
                self.spool.retry(item.item_id, current_time + self.retry_delay)
                self.write_failures += 1
                self.last_error = "audit database unavailable"
                self.status = HealthStatus.DEGRADED
                break
            self.spool.acknowledge(item.item_id)
            self.last_persisted_at = current_time
            persisted += 1
        if persisted and self.status != HealthStatus.FAILED:
            self.status = HealthStatus.HEALTHY
            self.last_error = None
        return persisted

    def mark_failed(self, detail: str) -> None:
        self.status = HealthStatus.FAILED
        self.last_error = self._safe_error(detail)

    def mark_degraded(self, detail: str) -> None:
        if self.status != HealthStatus.FAILED:
            self.status = HealthStatus.DEGRADED
            self.last_error = self._safe_error(detail)

    def health_snapshot(self) -> HealthSnapshot:
        spool_stats = self.spool.stats()
        sync_status = self._config_sync_status()
        status = self.status
        last_error = self.last_error
        if sync_status["status"] == ConfigSyncStatus.FAILED and status != HealthStatus.FAILED:
            status = HealthStatus.DEGRADED
            last_error = last_error or sync_status["error"]
        return HealthSnapshot(
            status=status,
            started_at=self.started_at,
            last_event_at=self.last_event_at,
            last_persisted_at=self.last_persisted_at,
            spool_records=spool_stats.records,
            spool_bytes=spool_stats.bytes,
            dropped_records=spool_stats.dropped_records,
            nflog_events=self.nflog_events,
            conntrack_events=self.conntrack_events,
            correlation_timeouts=self.correlator.stats.correlation_timeouts,
            incomplete_flows=self.correlator.stats.incomplete_flows,
            write_failures=self.write_failures,
            last_error=last_error,
            config_generation=self.config.generation,
            config_sync_status=sync_status["status"],
            config_sync_at=sync_status["updated_at"],
            config_sync_generation=sync_status["generation"],
            config_sync_error=sync_status["error"],
        )

    def write_health(self) -> HealthSnapshot:
        snapshot = self.health_snapshot()
        if self.health_path is not None:
            write_health_snapshot(self.health_path, snapshot)
        return snapshot

    def _enqueue(self, observations: list[AuditObservation], now: datetime) -> None:
        for observation in observations:
            self.spool.enqueue(observation, now=now)

    def _config_sync_status(self) -> dict[str, object]:
        unknown = {"status": ConfigSyncStatus.UNKNOWN, "updated_at": None, "generation": 0, "error": None}
        if self.sync_status_path is None:
            return unknown
        try:
            return read_config_sync_snapshot(self.sync_status_path) or unknown
        except (OSError, AuditValidationError):
            return {
                "status": ConfigSyncStatus.FAILED,
                "updated_at": None,
                "generation": 0,
                "error": "audit config sync status unavailable",
            }

    @staticmethod
    def _safe_error(detail: str) -> str:
        known_failures = {
            "conntrack unavailable",
            "nflog unavailable",
            "collector configuration unavailable",
        }
        if detail in known_failures:
            return detail
        return "collector failed"

    @staticmethod
    def _current_time(value: datetime | None) -> datetime:
        current_time = value or datetime.now(timezone.utc)
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return current_time.astimezone(timezone.utc)


class _AuditServiceWriter:
    """Lazily reconnect to the isolated audit database without stopping collection."""

    def __init__(self) -> None:
        self._service: Any | None = None

    def __call__(self, observation: AuditObservation) -> None:
        from .service import NetworkAuditService, NetworkAuditServiceError

        try:
            if self._service is None:
                self._service = NetworkAuditService()
            self._service.record_observation(observation)
        except NetworkAuditServiceError:
            self._service = None
            raise


class AuditCollectorRuntime:
    """Runs local event adapters without ever feeding data-plane work back into netfilter."""

    def __init__(
        self,
        collector: AuditCollector,
        conntrack: ConntrackEventAdapter,
        nflog: NflogEventAdapter,
        *,
        health_interval: timedelta = timedelta(seconds=5),
        queue_size: int = 2_048,
    ) -> None:
        if health_interval < timedelta(0):
            raise ValueError("health_interval cannot be negative")
        if queue_size < 1:
            raise ValueError("queue_size must be greater than zero")
        self.collector = collector
        self.conntrack = conntrack
        self.nflog = nflog
        self.health_interval = health_interval
        self.queue_size = queue_size

    def run(self) -> None:
        self._require_capabilities()
        event_queue: queue.Queue[tuple[str, ConntrackEvent | NflogEvent]] = queue.Queue(maxsize=self.queue_size)
        failures: queue.Queue[None] = queue.Queue(maxsize=2)
        workers = (
            threading.Thread(target=self._produce, args=("conntrack", self.conntrack, event_queue, failures), daemon=True),
            threading.Thread(target=self._produce, args=("nflog", self.nflog, event_queue, failures), daemon=True),
        )
        for worker in workers:
            worker.start()
        self.collector.status = HealthStatus.HEALTHY
        next_maintenance = time.monotonic()
        try:
            while True:
                if not failures.empty():
                    raise CollectorCapabilityError("collector event source stopped")
                timeout = max(0.05, next_maintenance - time.monotonic())
                try:
                    source, event = event_queue.get(timeout=timeout)
                except queue.Empty:
                    source = None
                    event = None
                if source == "conntrack" and isinstance(event, ConntrackEvent):
                    self.collector.handle_conntrack(event)
                elif source == "nflog" and isinstance(event, NflogEvent):
                    self.collector.handle_nflog(event)
                if time.monotonic() >= next_maintenance:
                    self.collector.expire()
                    self.collector.flush()
                    self.collector.write_health()
                    next_maintenance = time.monotonic() + self.health_interval.total_seconds()
        except (KeyboardInterrupt, SystemExit):
            self.collector.write_health()
            return
        except Exception as error:
            self.collector.mark_failed("collector failed")
            self.collector.write_health()
            if isinstance(error, CollectorCapabilityError):
                raise
            raise CollectorCapabilityError("collector failed") from error

    def _require_capabilities(self) -> None:
        unavailable = []
        for adapter in (self.conntrack, self.nflog):
            capability = adapter.capability()
            if not capability.available:
                unavailable.append(capability)
        if unavailable:
            self.collector.mark_failed("collector failed")
            self.collector.write_health()
            raise CollectorCapabilityError("collector event sources are unavailable")

    def _produce(
        self,
        source: str,
        adapter: ConntrackEventAdapter | NflogEventAdapter,
        event_queue: queue.Queue[tuple[str, ConntrackEvent | NflogEvent]],
        failures: queue.Queue[None],
    ) -> None:
        try:
            for event in adapter.events():
                try:
                    event_queue.put((source, event), timeout=0.1)
                except queue.Full:
                    self.collector.mark_degraded("collector failed")
        except Exception:
            try:
                failures.put_nowait(None)
            except queue.Full:
                pass


DEFAULT_SPOOL_PATH = "/var/lib/wgd-network-audit/spool.db"
DEFAULT_HEALTH_PATH = "/run/wgd-network-audit/health.json"
DEFAULT_SYNC_STATUS_PATH = "db/wgdashboard_audit_sync.json"


def run_collector(
    *,
    config_path: str | Path = DEFAULT_CONFIG_PATH,
    spool_path: str | Path = DEFAULT_SPOOL_PATH,
    health_path: str | Path = DEFAULT_HEALTH_PATH,
    sync_status_path: str | Path = DEFAULT_SYNC_STATUS_PATH,
) -> None:
    """Run the local collector using only the agent's last successfully applied config."""
    spool = AuditSpool(spool_path)
    try:
        config = read_applied_config(config_path)

        collector = AuditCollector(
            config,
            spool,
            _AuditServiceWriter(),
            health_path=health_path,
            sync_status_path=sync_status_path,
        )
        groups = {
            config.observation_nflog_group,
            config.policy_allowed_nflog_group,
            config.policy_denied_nflog_group,
        }
        AuditCollectorRuntime(
            collector,
            Pyroute2ConntrackAdapter(),
            NflogSocketAdapter(groups),
        ).run()
    except CollectorCapabilityError:
        raise
    except (OSError, ValueError) as error:
        write_health_snapshot(
            health_path,
            HealthSnapshot(HealthStatus.FAILED, datetime.now(timezone.utc), last_error="collector configuration unavailable"),
        )
        raise CollectorCapabilityError("collector configuration is unavailable") from error
    finally:
        spool.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="WGDashboard Network Audit Collector")
    parser.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--spool", default=DEFAULT_SPOOL_PATH)
    parser.add_argument("--health", default=DEFAULT_HEALTH_PATH)
    parser.add_argument("--sync-status", default=DEFAULT_SYNC_STATUS_PATH)
    args = parser.parse_args()
    run_collector(
        config_path=args.config,
        spool_path=args.spool,
        health_path=args.health,
        sync_status_path=args.sync_status,
    )


if __name__ == "__main__":
    main()
