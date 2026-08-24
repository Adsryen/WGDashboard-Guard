#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${WGD_INSTALL_DIR:-/opt/WGDashboard}"
SERVICE_NAME="${WGD_SERVICE_NAME:-wg-dashboard}"

usage() {
    printf 'Usage: sudo %s [--install-dir PATH]\n' "$0"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --install-dir)
            [[ $# -ge 2 ]] || { printf 'Missing value for --install-dir\n' >&2; exit 2; }
            INSTALL_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ${EUID} -ne 0 ]]; then
    printf 'This installer must run as root.\n' >&2
    exit 1
fi

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
SOURCE_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)

[[ -f "${SOURCE_DIR}/src/requirements.txt" ]] || {
    printf 'Run this script from a WGDashboard source checkout.\n' >&2
    exit 1
}

if ! command -v apt-get >/dev/null 2>&1 || ! command -v systemctl >/dev/null 2>&1; then
    printf 'The native installer currently supports Debian and Ubuntu with systemd.\n' >&2
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git python3 python3-pip python3-venv sudo wireguard-tools

python_binary="${WGD_PYTHON_BIN:-}"
if [[ -z "${python_binary}" ]]; then
    for candidate in python3.14 python3.13 python3.12 python3; do
        if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -c 'import sys; raise SystemExit(sys.version_info < (3, 12))'; then
            python_binary=$(command -v "${candidate}")
            break
        fi
    done
fi

if [[ -z "${python_binary}" ]]; then
    printf 'Python 3.12 or newer is required. Set WGD_PYTHON_BIN to a compatible interpreter.\n' >&2
    exit 1
fi

install -d -m 755 "${INSTALL_DIR}"
tar \
    --exclude=.git \
    --exclude=src/venv \
    --exclude=src/db \
    --exclude=src/download \
    --exclude=src/backup \
    --exclude=src/log \
    --exclude=src/wg-dashboard.ini \
    --exclude=src/wg-dashboard-oidc-providers.json \
    --exclude=src/ssl \
    -C "${SOURCE_DIR}" -cf - . | tar -C "${INSTALL_DIR}" -xf -

install -d -m 755 \
    "${INSTALL_DIR}/src/db" \
    "${INSTALL_DIR}/src/download" \
    "${INSTALL_DIR}/src/backup" \
    "${INSTALL_DIR}/src/log" \
    /etc/wireguard

if [[ ! -x "${INSTALL_DIR}/src/venv/bin/python" ]]; then
    "${python_binary}" -m venv "${INSTALL_DIR}/src/venv"
fi

"${INSTALL_DIR}/src/venv/bin/python" -m pip install --upgrade pip
"${INSTALL_DIR}/src/venv/bin/python" -m pip install -r "${INSTALL_DIR}/src/requirements.txt"

chmod +x "${INSTALL_DIR}/src/wgd.sh"
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=WGDashboard
After=syslog.target network-online.target
Wants=network-online.target wg-quick.target
ConditionPathIsDirectory=/etc/wireguard

[Service]
Type=forking
PIDFile=${INSTALL_DIR}/src/gunicorn.pid
WorkingDirectory=${INSTALL_DIR}/src
ExecStart=${INSTALL_DIR}/src/wgd.sh start
ExecStop=${INSTALL_DIR}/src/wgd.sh stop
ExecReload=${INSTALL_DIR}/src/wgd.sh restart
TimeoutSec=120
PrivateTmp=yes
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}.service" >/dev/null
systemctl restart "${SERVICE_NAME}.service"

printf 'WGDashboard installed at %s\n' "${INSTALL_DIR}"
printf 'Service: %s.service\n' "${SERVICE_NAME}"
printf 'Check status: systemctl status %s.service\n' "${SERVICE_NAME}"
