#!/bin/sh
set -eu

return_network="$1"
gateway="$2"
shift 2
ip route replace "$return_network" via "$gateway"

for listener in "$@"; do
    protocol="${listener%%:*}"
    port="${listener#*:}"
    case "$protocol" in
        tcp) python3 /tests/tcp-echo.py "$port" >/tmp/tcp-"$port".log 2>&1 & ;;
        udp) python3 /tests/udp-echo.py "$port" udp-ok >/tmp/udp-"$port".log 2>&1 & ;;
        *) echo "unsupported listener: $listener" >&2; exit 1 ;;
    esac
done

touch /tmp/target-ready
exec sleep infinity
