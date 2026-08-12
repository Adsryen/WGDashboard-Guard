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
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 2 http://10.251.0.170/)" = "target-http-ok"
expect_tcp 10.252.0.127 18180
expect_udp 10.252.0.127 18181 udp-ok
expect_tcp 10.252.0.117 8118
expect_drop_tcp 10.252.0.117 9090
expect_drop_udp 10.252.0.117 8118 udp-ok
expect_drop_tcp 10.253.0.200 19090

denied_html="$(curl --noproxy '*' --silent --show-error --max-time 2 --write-out '%{http_code}' http://10.253.0.200/)"
test "${denied_html%403}" != "$denied_html"
printf '%s' "$denied_html" | grep -q 'VPN access denied'
denied_json="$(curl --noproxy '*' --silent --show-error --max-time 2 --header 'Accept: application/json' --header 'Accept-Language: zh-CN' --write-out '%{http_code}' http://10.253.0.200/api/status)"
test "${denied_json%403}" != "$denied_json"
printf '%s' "$denied_json" | grep -q 'vpn_access_denied'
printf '%s' "$denied_json" | grep -q '当前 VPN 端点没有访问权限'

# These flows terminate on the gateway and must not enter the FORWARD hook.
python3 /tests/port-open.py 10.250.0.10 22
expect_udp 10.250.0.10 51820 wg-listener
