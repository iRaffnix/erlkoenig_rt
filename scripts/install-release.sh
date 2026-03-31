#!/bin/sh
# install-release.sh — Download and install erlkoenig_rt from GitHub Releases.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/iRaffnix/erlkoenig_rt/main/scripts/install-release.sh | sudo sh
#   curl -fsSL ... | sudo sh -s -- --version v0.1.0
#   curl -fsSL ... | sudo sh -s -- --prefix /opt/erlkoenig
#   curl -fsSL ... | sudo sh -s -- --uninstall
#
# What it does:
#   1. Detects latest release (or uses --version)
#   2. Downloads the tarball from GitHub Releases
#   3. Installs binaries, systemd units, sysusers, tmpfiles
#   4. Sets file capabilities (setcap)
#   5. Reloads systemd

set -eu

REPO="iRaffnix/erlkoenig_rt"
PREFIX="/usr"
VERSION=""
ACTION="install"
TMPDIR=""

usage() {
    cat <<EOF
Usage: sudo $0 [OPTIONS]

Options:
  --version VERSION   Install specific version (e.g. v0.1.0)
                      Default: latest release
  --prefix DIR        Install prefix (default: /usr)
  --uninstall         Remove installation
  --help              Show this help

Examples:
  # Install latest
  curl -fsSL https://raw.githubusercontent.com/$REPO/main/scripts/install-release.sh | sudo sh

  # Install specific version
  curl -fsSL ... | sudo sh -s -- --version v0.2.0

  # Install to /opt
  curl -fsSL ... | sudo sh -s -- --prefix /opt/erlkoenig
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version)   VERSION="$2"; shift 2 ;;
        --prefix)    PREFIX="$2"; shift 2 ;;
        --uninstall) ACTION="uninstall"; shift ;;
        --help)      usage ;;
        *)           echo "Unknown option: $1"; usage ;;
    esac
done

LIBDIR="$PREFIX/lib/erlkoenig"
SYSTEMD_UNIT_DIR="$PREFIX/lib/systemd/system"
SYSUSERS_DIR="$PREFIX/lib/sysusers.d"
TMPFILES_DIR="$PREFIX/lib/tmpfiles.d"

[ "$(id -u)" = "0" ] || { echo "Error: must run as root"; exit 1; }

cleanup() {
    [ -n "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
            | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/$REPO/releases/latest" \
            | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p'
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
}

download() {
    url="$1"
    dest="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$dest" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dest" "$url"
    fi
}

do_install() {
    # Resolve version
    if [ -z "$VERSION" ]; then
        echo "Detecting latest release..."
        VERSION=$(get_latest_version)
        if [ -z "$VERSION" ]; then
            echo "Error: could not detect latest release"
            echo "Try: $0 --version v0.1.0"
            exit 1
        fi
    fi

    echo "Installing erlkoenig_rt $VERSION"
    echo "  prefix: $PREFIX"

    # Download
    TMPDIR=$(mktemp -d)
    TARBALL="$TMPDIR/erlkoenig_rt.tar.gz"
    URL="https://github.com/$REPO/releases/download/$VERSION/erlkoenig_rt-${VERSION}-linux-amd64.tar.gz"

    echo "  downloading: $URL"
    download "$URL" "$TARBALL"

    # Extract
    tar xzf "$TARBALL" -C "$TMPDIR"

    # Install binaries
    install -d -m 0755 "$LIBDIR"

    install -m 0755 "$TMPDIR/erlkoenig_rt" "$LIBDIR/erlkoenig_rt"
    echo "  binary: $LIBDIR/erlkoenig_rt ($(du -h "$LIBDIR/erlkoenig_rt" | cut -f1))"

    install -m 0755 "$TMPDIR/ek_rtctl" "$LIBDIR/ek_rtctl"
    echo "  ctl:    $LIBDIR/ek_rtctl ($(du -h "$LIBDIR/ek_rtctl" | cut -f1))"

    if [ -f "$TMPDIR/gateway" ]; then
        install -m 0755 "$TMPDIR/gateway" "$LIBDIR/gateway"
        echo "  demo:   $LIBDIR/gateway ($(du -h "$LIBDIR/gateway" | cut -f1))"
    fi

    # Set capabilities
    if command -v setcap >/dev/null 2>&1; then
        setcap 'cap_sys_admin,cap_net_admin,cap_sys_chroot,cap_sys_ptrace,cap_setpcap,cap_setuid,cap_setgid,cap_dac_override+ep' \
            "$LIBDIR/erlkoenig_rt" 2>/dev/null || true
    fi

    # systemd units
    if [ -d "$TMPDIR/systemd" ]; then
        install -d -m 0755 "$SYSTEMD_UNIT_DIR"
        install -m 0644 "$TMPDIR/systemd/erlkoenig-rt@.service" "$SYSTEMD_UNIT_DIR/"
        install -m 0644 "$TMPDIR/systemd/erlkoenig.target" "$SYSTEMD_UNIT_DIR/"
        echo "  units:  erlkoenig-rt@.service, erlkoenig.target"

        # sysusers
        if [ -f "$TMPDIR/systemd/erlkoenig.sysusers" ]; then
            install -d -m 0755 "$SYSUSERS_DIR"
            install -m 0644 "$TMPDIR/systemd/erlkoenig.sysusers" "$SYSUSERS_DIR/erlkoenig.conf"
            if command -v systemd-sysusers >/dev/null 2>&1; then
                systemd-sysusers "$SYSUSERS_DIR/erlkoenig.conf" 2>/dev/null || true
            fi
        fi

        # tmpfiles
        if [ -f "$TMPDIR/systemd/erlkoenig.tmpfiles" ]; then
            install -d -m 0755 "$TMPFILES_DIR"
            install -m 0644 "$TMPDIR/systemd/erlkoenig.tmpfiles" "$TMPFILES_DIR/erlkoenig.conf"
            if command -v systemd-tmpfiles >/dev/null 2>&1; then
                systemd-tmpfiles --create "$TMPFILES_DIR/erlkoenig.conf" 2>/dev/null || true
            fi
        fi
    fi

    # Config
    install -d -m 0755 /etc/erlkoenig
    if [ ! -f /etc/erlkoenig/rt.conf ]; then
        cat > /etc/erlkoenig/rt.conf << 'CONF'
# erlkoenig_rt configuration
ERLKOENIG_LOG=info
CONF
    fi

    # Reload systemd
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
        systemctl enable erlkoenig.target 2>/dev/null || true
    fi

    # Version file
    echo "$VERSION" > "$LIBDIR/VERSION"

    echo ""
    echo "Done. erlkoenig_rt $VERSION installed."
    echo ""
    echo "Usage:"
    echo "  systemctl start erlkoenig-rt@web-1"
    echo "  ek_rtctl /run/erlkoenig/web-1.sock spawn --path /app --image app.erofs"
    echo "  ek_rtctl /run/erlkoenig/web-1.sock go"
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
