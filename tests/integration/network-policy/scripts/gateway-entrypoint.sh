#!/bin/sh
set -eu

peer_interface="$(ip -o -4 addr show | awk '$4 == "10.250.0.10/24" { print $2; exit }')"
test -n "$peer_interface"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
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

python3 /tests/apply-initial-policy.py
touch /tmp/gateway-ready
exec sleep infinity
