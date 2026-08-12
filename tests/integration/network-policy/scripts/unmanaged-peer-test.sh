#!/bin/sh
set -eu

ip route replace 10.253.0.0/24 via 10.250.0.10
python3 /tests/tcp-probe.py 10.253.0.200 19090

# NAT redirect preserves the original destination address, so the responder
# listens on all local addresses. The owned input chain blocks direct access.
if python3 /tests/tcp-probe.py 10.250.0.10 61573; then
    echo "denial responder is reachable by an unmanaged peer" >&2
    exit 1
fi
