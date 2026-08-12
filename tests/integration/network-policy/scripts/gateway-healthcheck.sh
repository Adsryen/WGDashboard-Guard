#!/bin/sh
set -eu

test -f /tmp/gateway-ready
ip link show wg0 >/dev/null
nft list table inet wgd_network_policy >/dev/null
ss -ltn | grep -q ':22'
ss -lun | grep -q ':51820'
