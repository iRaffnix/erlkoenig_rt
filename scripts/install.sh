#!/bin/sh
# install.sh — Install/uninstall erlkoenig_rt.
#
# Installs:
#   /usr/lib/erlkoenig/erlkoenig_rt     Static runtime binary (~164 KB)
#   /usr/lib/systemd/system/            Template unit + target
#   /usr/lib/sysusers.d/                erlkoenig user/group
#   /usr/lib/tmpfiles.d/                Runtime directories
#   /etc/erlkoenig/rt.conf              Default config
#
# Usage:
#   sudo ./scripts/install.sh [--prefix /usr] [--uninstall]

set -eu

PREFIX="${PREFIX:-/usr}"
ACTION=install

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)   PREFIX="$2"; shift 2 ;;
        --uninstall) ACTION=uninstall; shift ;;
        --help)     echo "Usage: sudo $0 [--prefix DIR] [--uninstall]"; exit 0 ;;
        *)          echo "Unknown: $1"; exit 1 ;;
    esac
done

LIBDIR="$PREFIX/lib/erlkoenig"
SYSTEMD_UNIT_DIR="$PREFIX/lib/systemd/system"
SYSUSERS_DIR="$PREFIX/lib/sysusers.d"
TMPFILES_DIR="$PREFIX/lib/tmpfiles.d"
SRCDIR="$(cd "$(dirname "$0")/.." && pwd)"

[ "$(id -u)" = "0" ] || { echo "Error: must run as root"; exit 1; }

do_install() {
    echo "Installing erlkoenig_rt..."
    echo "  prefix: $PREFIX"

    # Binary
    install -d -m 0755 "$LIBDIR"
    if [ -f "$SRCDIR/build/erlkoenig_rt" ]; then
        install -m 0755 "$SRCDIR/build/erlkoenig_rt" "$LIBDIR/erlkoenig_rt"
        if command -v setcap >/dev/null 2>&1; then
            setcap 'cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override+ep' \
                "$LIBDIR/erlkoenig_rt" 2>/dev/null || true
        fi
        echo "  binary: $LIBDIR/erlkoenig_rt ($(du -h "$LIBDIR/erlkoenig_rt" | cut -f1))"
    else
        echo "  ERROR: build/erlkoenig_rt not found (run 'make' first)"
        exit 1
    fi

    # CLI tool
    if [ -f "$SRCDIR/build/ek_rtctl" ]; then
        install -m 0755 "$SRCDIR/build/ek_rtctl" "$LIBDIR/ek_rtctl"
        echo "  ctl:    $LIBDIR/ek_rtctl ($(du -h "$LIBDIR/ek_rtctl" | cut -f1))"
    fi

    # systemd
    install -d -m 0755 "$SYSTEMD_UNIT_DIR"
    install -m 0644 "$SRCDIR/dist/systemd/erlkoenig-rt@.service" "$SYSTEMD_UNIT_DIR/"
    install -m 0644 "$SRCDIR/dist/systemd/erlkoenig.target" "$SYSTEMD_UNIT_DIR/"
    echo "  units:  erlkoenig-rt@.service, erlkoenig.target"

    # sysusers.d
    install -d -m 0755 "$SYSUSERS_DIR"
    install -m 0644 "$SRCDIR/dist/systemd/erlkoenig.sysusers" "$SYSUSERS_DIR/erlkoenig.conf"
    if command -v systemd-sysusers >/dev/null 2>&1; then
        systemd-sysusers "$SYSUSERS_DIR/erlkoenig.conf" 2>/dev/null || true
    fi

    # tmpfiles.d
    install -d -m 0755 "$TMPFILES_DIR"
    install -m 0644 "$SRCDIR/dist/systemd/erlkoenig.tmpfiles" "$TMPFILES_DIR/erlkoenig.conf"
    if command -v systemd-tmpfiles >/dev/null 2>&1; then
        systemd-tmpfiles --create "$TMPFILES_DIR/erlkoenig.conf" 2>/dev/null || true
    fi

    # Config
    install -d -m 0755 /etc/erlkoenig
    if [ ! -f /etc/erlkoenig/rt.conf ]; then
        cat > /etc/erlkoenig/rt.conf << 'CONF'
# erlkoenig_rt configuration
ERLKOENIG_LOG=info
CONF
    fi

    # Reload
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable erlkoenig.target 2>/dev/null || true
    fi

    echo ""
    echo "Done. Usage:"
    echo "  systemctl start erlkoenig-rt@web-1"
    echo "  systemctl stop erlkoenig.target"
}

do_uninstall() {
    echo "Uninstalling erlkoenig_rt..."
    if command -v systemctl >/dev/null 2>&1; then
        systemctl stop 'erlkoenig-rt@*' 2>/dev/null || true
        systemctl disable erlkoenig.target 2>/dev/null || true
    fi
    rm -f "$SYSTEMD_UNIT_DIR/erlkoenig-rt@.service"
    rm -f "$SYSTEMD_UNIT_DIR/erlkoenig.target"
    rm -f "$SYSUSERS_DIR/erlkoenig.conf"
    rm -f "$TMPFILES_DIR/erlkoenig.conf"
    rm -rf "$LIBDIR"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    echo "Done. Config preserved at /etc/erlkoenig/"
}

case "$ACTION" in
    install)   do_install ;;
    uninstall) do_uninstall ;;
esac
