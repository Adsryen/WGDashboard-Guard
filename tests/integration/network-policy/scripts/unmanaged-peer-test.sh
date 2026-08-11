#!/bin/sh
set -eu

ip route replace 10.253.0.0/24 via 10.250.0.10
python3 /tests/tcp-probe.py 10.253.0.200 19090
