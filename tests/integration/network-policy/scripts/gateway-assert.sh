#!/bin/sh
set -eu

test "$(nft -a list table inet docker_sentinel | sha256sum | awk '{ print $1 }')" = "$(cat /tmp/docker-sentinel.sha256)"
nft list table inet wgd_network_audit >/tmp/audit-owned-table.txt
grep -q 'wgd-audit-owner:v1' /tmp/audit-owned-table.txt
grep -q 'iifname "wg0" ip saddr 10.250.0.3 ct state new log prefix "wgd-audit:forward_observed" group 11500' /tmp/audit-owned-table.txt
! grep -q 'ip saddr 10.250.0.2 ct state new log prefix "wgd-audit:forward_observed" group 11500' /tmp/audit-owned-table.txt
nft list table inet wgd_network_policy >/tmp/owned-table.txt
grep -q 'wgd-policy:' /tmp/owned-table.txt
grep -q 'hook forward' /tmp/owned-table.txt
grep -q 'hook input' /tmp/owned-table.txt
grep -q 'hook prerouting' /tmp/owned-table.txt
grep -q 'redirect to :61573' /tmp/owned-table.txt
python3 /tests/failed-apply-test.py
test "$(nft -a list table inet docker_sentinel | sha256sum | awk '{ print $1 }')" = "$(cat /tmp/docker-sentinel.sha256)"
nft list table inet wgd_network_audit >/tmp/audit-owned-table-after-policy-failure.txt
cmp /tmp/audit-owned-table.txt /tmp/audit-owned-table-after-policy-failure.txt
python3 /tests/audit-assert.py
