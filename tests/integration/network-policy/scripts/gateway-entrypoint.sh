#!/bin/sh
set -eu

peer_interface="$(ip -o -4 addr show | awk '$4 == "10.250.0.10/24" { print $2; exit }')"
test -n "$peer_interface"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_close=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_udp_timeout=1 >/dev/null
sysctl -w net.netfilter.nf_conntrack_udp_timeout_stream=1 >/dev/null
ip link add wg0 type bridge
ip link set "$peer_interface" master wg0
ip addr del 10.250.0.10/24 dev "$peer_interface"
ip addr add 10.250.0.10/24 dev wg0
ip link set wg0 up
ip route replace 10.250.0.0/24 dev wg0 src 10.250.0.10

ssh-keygen -A >/dev/null 2>&1
/usr/sbin/sshd
python3 /tests/udp-echo.py 51820 wg-listener >/tmp/wg-listener.log 2>&1 &
python3 -m network_policy.denial_responder >/tmp/denial-responder.log 2>&1 &

nft -f - <<'NFT'
add table inet docker_sentinel
add chain inet docker_sentinel forward { type filter hook forward priority filter; policy accept; }
add rule inet docker_sentinel forward accept
NFT
nft -a list table inet docker_sentinel | sha256sum | awk '{ print $1 }' >/tmp/docker-sentinel.sha256

python3 /tests/apply-audit-config.py
python3 /tests/apply-initial-policy.py
WGD_AUDIT_DATABASE_PATH=/tmp/wgdashboard_audit.db \
python3 -m network_audit.collector \
    --config /tmp/audit-config.json \
    --spool /tmp/audit-spool.db \
    --health /tmp/audit-health.json \
    --sync-status /tmp/audit-sync-status.json \
    >/tmp/audit-collector.log 2>&1 &
collector_pid=$!

collector_ready=false
for _attempt in $(seq 1 30); do
    if ! kill -0 "$collector_pid" 2>/dev/null; then
        cat /tmp/audit-collector.log >&2
        exit 1
    fi
    if test -f /tmp/audit-health.json && \
        test "$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["status"])' /tmp/audit-health.json)" = healthy; then
        collector_ready=true
        break
    fi
    sleep 1
done
test "$collector_ready" = true
touch /tmp/gateway-ready
exec sleep infinity
