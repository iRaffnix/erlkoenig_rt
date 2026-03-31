# Installation

## Build requirements

- Linux (kernel >= 5.13)
- musl-gcc (`apt install musl-tools`)
- cmake >= 3.10
- mkfs.erofs (`apt install erofs-utils`) — for container images

## Build

```bash
make              # build/erlkoenig_rt (~164 KB static musl)
                  # build/ek_rtctl (~53 KB static musl)
```

Both binaries are statically linked with zero runtime dependencies.

## Install

```bash
sudo make install
# or: sudo ./scripts/install.sh --prefix /opt/erlkoenig
```

Installs:

| Path | Description |
|------|-------------|
| `/usr/lib/erlkoenig/erlkoenig_rt` | Runtime binary (164 KB) |
| `/usr/lib/erlkoenig/ek_rtctl` | CLI control tool (53 KB) |
| `/usr/lib/systemd/system/erlkoenig-rt@.service` | systemd template unit |
| `/usr/lib/systemd/system/erlkoenig.target` | Container target |
| `/usr/lib/sysusers.d/erlkoenig.conf` | User/group definitions |
| `/usr/lib/tmpfiles.d/erlkoenig.conf` | Runtime directories |

## Usage

```bash
# Start an instance
sudo systemctl start erlkoenig-rt@web-1

# Spawn and start a container
ek_rtctl /run/erlkoenig/web-1.sock spawn --path /app --image app.erofs
ek_rtctl /run/erlkoenig/web-1.sock go
ek_rtctl /run/erlkoenig/web-1.sock watch

# Stop all instances
sudo systemctl stop erlkoenig.target
```

## Uninstall

```bash
sudo ./scripts/install.sh --uninstall
```

## Network steering

For L4 DSR load balancing: [erlkoenig_ebpfd](https://github.com/iRaffnix/erlkoenig_ebpfd)
