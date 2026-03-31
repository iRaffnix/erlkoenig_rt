# Getting Started with erlkoenig_rt

This guide walks you through building, running, and understanding the
erlkoenig container runtime.

## Prerequisites

Linux with kernel 5.13+ (Landlock required). Tested on Ubuntu 24.04 (6.8).

```
# Required
musl-gcc          # static C compilation (apt install musl-tools)
cmake >= 3.10
mkfs.erofs        # EROFS image creation (apt install erofs-utils)

# Verify kernel features
cat /proc/filesystems | grep erofs       # EROFS support
cat /proc/filesystems | grep overlay     # OverlayFS support
ls /dev/loop-control                     # loop device support
```

## 1. Build

```bash
cd erlkoenig_rt
make
```

Produces:
- `build/erlkoenig_rt` — Container runtime (~164 KB, static musl)
- `build/ek_rtctl` — CLI control tool (~53 KB, static musl)
- `build/testbin/` — Test binaries for containers

All binaries are statically linked with zero external dependencies.

## 2. Your First Container

Build an EROFS image from a static binary:

```bash
# Create a minimal rootfs with one binary
mkdir -p /tmp/myapp-root
cp build/testbin/test-erlkoenig-hello_output /tmp/myapp-root/app
chmod 555 /tmp/myapp-root/app

# Build a compressed read-only EROFS image
mkfs.erofs -zlz4 /tmp/hello.erofs /tmp/myapp-root/
rm -rf /tmp/myapp-root
```

Start the runtime and spawn a container:

```bash
# Terminal 1: start runtime (one per container)
sudo build/erlkoenig_rt --socket /tmp/test.sock

# Terminal 2: interact via ek_rtctl
sudo build/ek_rtctl /tmp/test.sock spawn \
    --path /app --image /tmp/hello.erofs
sudo build/ek_rtctl /tmp/test.sock go
sudo build/ek_rtctl /tmp/test.sock watch
```

Expected output:
```
REPLY_CONTAINER_PID PID=12345 netns=/proc/12345/ns/net
REPLY_READY
REPLY_STDOUT: hello from erlkoenig container
REPLY_STDOUT: this is stdout line 2
REPLY_STDOUT: this is stdout line 3
REPLY_EXITED exit=0
```

## 3. Container Lifecycle

### 3.1 Spawn

Creates the container (namespaces, rootfs, cgroups) but does NOT start it:

```bash
ek_rtctl /tmp/test.sock spawn \
    --path /app \
    --image /tmp/app.erofs \
    --memory 256M \
    --pids 50 \
    --env MYVAR=hello \
    --arg --listen \
    --arg 0.0.0.0:8080
```

Reply: `REPLY_CONTAINER_PID PID=<pid> netns=<path>`

### 3.2 Network Setup (optional)

After spawn, before go — the control plane can configure container
networking via the `NET_SETUP` protocol command (0x15). The runtime
handles everything via netlink (no shell commands, no `ip`, no `nsenter`).

Note: `ek_rtctl` does not implement `net-setup` — this command is
used programmatically by the Erlang control plane or the FaaS gateway.

For the FaaS gateway (`demo/gateway.c`), veth creation + host-side
configuration + container-side setup is done via
`erlkoenig_netcfg_veth_create()` and `erlkoenig_netcfg_setup()` —
all pure netlink, zero fork/exec.

### 3.3 Start the binary

```bash
ek_rtctl /tmp/test.sock go
```

Reply: `REPLY_READY` — the container binary is now executing.

### 3.4 Watch (stream events)

```bash
ek_rtctl /tmp/test.sock watch
```

Streams stdout, stderr, and exit events until the container exits.

### 3.5 Status

```bash
ek_rtctl /tmp/test.sock status
```

Reply: `REPLY_STATUS state=<n> pid=<pid> uptime=<ms>ms`

### 3.6 Kill

```bash
ek_rtctl /tmp/test.sock kill        # SIGTERM
ek_rtctl /tmp/test.sock kill 9      # SIGKILL
```

## 4. Security Hardening

After `go`, the runtime applies three irreversible security layers:

1. **Capabilities**: only CAP_KILL retained
2. **Landlock**: all filesystem access denied (pre-opened FDs only)
3. **Seccomp**: 29 syscalls blocked

Container hardening:
- Securebits locked (NOROOT + NO_SETUID_FIXUP)
- io_uring blocked in all seccomp profiles
- close_range before execve (FD leak prevention)
- execveat(AT_EMPTY_PATH) for TOCTOU elimination
- Read-only EROFS rootfs + tmpfs /tmp overlay

## 5. Wire Protocol

Binary TLV over Unix socket. `{packet, 4}` framing.

Commands (Erlang/client → runtime):
| Tag | Name | Description |
|-----|------|-------------|
| 0x10 | SPAWN | Create container |
| 0x11 | GO | Start container binary |
| 0x12 | KILL | Send signal |
| 0x13 | CGROUP_SET | Update cgroup limits |
| 0x14 | QUERY_STATUS | Get state/pid/uptime |
| 0x15 | NET_SETUP | Configure container networking |
| 0x16 | WRITE_FILE | Write file into container rootfs |
| 0x17 | STDIN | Forward stdin data |
| 0x18 | RESIZE | Resize PTY window |
| 0x19 | DEVICE_FILTER | Set device access rules |
| 0x1A | METRICS_START | Start eBPF metrics collection |
| 0x1B | METRICS_STOP | Stop metrics collection |

Replies (runtime → client):
| Tag | Name | Description |
|-----|------|-------------|
| 0x01 | OK | Success |
| 0x02 | ERROR | Error with code + message |
| 0x03 | CONTAINER_PID | PID + netns path |
| 0x04 | READY | Container started |
| 0x05 | EXITED | Exit code + signal |
| 0x06 | STATUS | State + PID + uptime |
| 0x07 | STDOUT | Container stdout data |
| 0x08 | STDERR | Container stderr data |
| 0x09 | METRICS_EVENT | eBPF metrics event |

Source of truth: `include/erlkoenig_proto.h`

## 6. systemd Integration

```bash
# Install
sudo make install

# Start a container instance
sudo systemctl start erlkoenig-rt@web-1

# The socket is at /run/erlkoenig/web-1.sock
ek_rtctl /run/erlkoenig/web-1.sock status

# Stop all instances
sudo systemctl stop erlkoenig.target

# View logs
journalctl -u erlkoenig-rt@web-1
```

## 7. Benchmarks

```bash
sudo ./scripts/bench-startup.sh 20
```

Measures spawn, go+exit, and total lifecycle time across N iterations
with min/avg/p50/p99/max statistics.

## 8. Network Steering

For L4 DSR load balancing across containers, see
[erlkoenig_ebpfd](https://github.com/iRaffnix/erlkoenig_ebpfd).

## 9. Architecture

```
Erlang (erlkoenig_ct) ──► Unix Socket ──► erlkoenig_rt (C, 164 KB)
                                              │
                                              ├── clone(6 namespaces)
                                              ├── pivot_root + EROFS mount
                                              ├── seccomp + cap drop + Landlock
                                              └── execveat container binary
```

One erlkoenig_rt process per container. The Unix socket survives BEAM crashes.
