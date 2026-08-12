#!/bin/sh
set -eu

for network in 10.251.0.0/24 10.252.0.0/24 10.253.0.0/24; do
    ip route replace "$network" via 10.250.0.10
done

expect_tcp() {
    python3 /tests/tcp-probe.py "$1" "$2"
}

expect_udp() {
    python3 /tests/udp-probe.py "$1" "$2" "$3"
}

expect_drop_tcp() {
    if python3 /tests/tcp-probe.py "$1" "$2"; then
        echo "unexpected TCP access to $1:$2" >&2
        exit 1
    fi
}

expect_drop_udp() {
    if python3 /tests/udp-probe.py "$1" "$2" "$3"; then
        echo "unexpected UDP access to $1:$2" >&2
        exit 1
    fi
}

expect_tcp 10.251.0.170 18080
expect_udp 10.251.0.170 18081 udp-ok
expect_tcp 10.252.0.127 18180
expect_udp 10.252.0.127 18181 udp-ok
expect_tcp 10.252.0.117 8118
expect_drop_tcp 10.252.0.117 9090
expect_drop_udp 10.252.0.117 8118 udp-ok
expect_drop_tcp 10.253.0.200 19090

# These flows terminate on the gateway and must not enter the FORWARD hook.
python3 /tests/port-open.py 10.250.0.10 22
expect_udp 10.250.0.10 51820 wg-listener
