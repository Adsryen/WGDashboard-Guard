#!/bin/sh
set -eu

if [ "$1" = "-f" ]; then
    cat >/dev/null
    echo "simulated nft load failure" >&2
    exit 1
fi

exec nft "$@"
