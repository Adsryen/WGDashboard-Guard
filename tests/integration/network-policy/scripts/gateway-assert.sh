#!/bin/sh
set -eu

test "$(nft -a list table inet docker_sentinel | sha256sum | awk '{ print $1 }')" = "$(cat /tmp/docker-sentinel.sha256)"
nft list table inet wgd_network_policy >/tmp/owned-table.txt
grep -q 'wgd-policy:' /tmp/owned-table.txt
grep -q 'hook forward' /tmp/owned-table.txt
! grep -q 'hook input' /tmp/owned-table.txt
python3 /tests/failed-apply-test.py
test "$(nft -a list table inet docker_sentinel | sha256sum | awk '{ print $1 }')" = "$(cat /tmp/docker-sentinel.sha256)"
