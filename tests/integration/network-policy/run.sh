#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
compose="docker compose --project-name wgd-network-policy-it --file $script_dir/compose.yaml"

cleanup() {
    $compose down --volumes --remove-orphans
}
trap cleanup EXIT INT TERM

$compose up --build -d gateway target-a target-b target-c target-denied
$compose up -d managed-peer unmanaged-peer
$compose wait managed-peer unmanaged-peer
$compose exec -T gateway /tests/gateway-assert.sh
