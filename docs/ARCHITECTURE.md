# Architecture & Integration Guide

This document describes how erlkoenig_rt works internally and how to
integrate it from any language. The wire protocol is the only public
interface — everything runs over a Unix socket with `{packet, 4}` framing.

## Overview

```
                     ┌─────────────────────────────────────────────┐
                     │              Control Plane                  │
                     │  (Erlang / Python / Go / shell / anything)  │
                     └────────────────┬────────────────────────────┘
                                      │ Unix Socket
                                      │ {packet, 4} + TLV
                     ┌────────────────▼────────────────────────────┐
                     │           erlkoenig_rt  (164 KB)            │
                     │                                             │
                     │  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
                     │  │ Proto   │  │ Namespace │  │ Security  │  │
                     │  │ Parser  │  │ + Rootfs  │  │ Hardening │  │
                     │  └────┬────┘  └────┬─────┘  └─────┬─────┘  │
                     │       │            │              │         │
                     │  ┌────▼────┐  ┌────▼─────┐  ┌────▼──────┐  │
                     │  │ Event   │  │ cgroup   │  │ Netlink   │  │
                     │  │ Loop    │  │ + BPF    │  │ Net Setup │  │
                     │  └─────────┘  └──────────┘  └───────────┘  │
                     └────────────────┬────────────────────────────┘
                                      │ clone(6 ns)
                     ┌────────────────▼────────────────────────────┐
                     │              Container                      │
                     │  EROFS (ro) + tmpfs overlay + pivot_root    │
                     │  seccomp + Landlock + cap drop              │
                     │  execveat AT_EMPTY_PATH → /app              │
                     └─────────────────────────────────────────────┘
```

One erlkoenig_rt process manages exactly one container. The control
plane starts N runtime processes for N containers.

## Two I/O Modes

**Port mode** (legacy): Erlang starts erlkoenig_rt as an Erlang port.
stdin = commands, stdout = replies. Connection loss terminates the runtime.

**Socket mode** (`--socket PATH`): The runtime creates a Unix domain
socket and accepts one connection. The protocol is identical. Connection
loss does NOT terminate the runtime — the container survives and the
runtime waits for reconnect. This enables BEAM crash recovery.

```bash
# Socket mode (recommended)
erlkoenig_rt --socket /run/erlkoenig/web-1.sock

# Port mode (Erlang)
open_port({spawn_executable, "/usr/lib/erlkoenig/erlkoenig_rt"},
          [{packet, 4}, binary, exit_status]).
```

## Wire Protocol

### Framing

Every message is prefixed with a 4-byte big-endian length:

```
┌──────────────┬─────────────────────┐
│ Length (4 BE) │ Payload (N bytes)   │
└──────────────┴─────────────────────┘
```

### Handshake

After connecting (socket mode), the client sends a 1-byte protocol
version in a frame. The server replies with its version in a frame.
Both must be `0x01`.

```
Client → Server:  [00 00 00 01] [01]
Server → Client:  [00 00 00 01] [01]
```

### Message Format

Commands and most replies use TLV encoding:

```
┌──────────┬─────────┬────────────────────┐
│ Tag (1B) │ Ver (1B)│ TLV Attributes...  │
└──────────┴─────────┴────────────────────┘
```

Streaming messages (STDOUT, STDERR, STDIN) use raw format:

```
┌──────────┬──────────────────┐
│ Tag (1B) │ Raw Data...      │
└──────────┴──────────────────┘
```

### TLV Attribute Encoding

Each attribute is:

```
┌────────────┬────────────┬───────────────┐
│ Type (2BE) │ Len (2BE)  │ Value (N B)   │
└────────────┴────────────┴───────────────┘
```

- Type bit 15 (`0x8000`) = critical. Unknown critical attributes
  cause the message to be rejected. Unknown non-critical attributes
  are silently skipped.
- Integer values are big-endian.

## Command Reference

Source of truth: `include/erlkoenig_proto.h`

### CMD_SPAWN (0x10)

Create a container. Must be in state IDLE.

**Attributes:**

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | PATH | bytes | yes | Absolute path to binary inside rootfs |
| 2 | UID | uint32 | yes | Container UID (default: 65534/nobody) |
| 3 | GID | uint32 | yes | Container GID (default: 65534/nobody) |
| 4 | CAPS | uint64 | no | Capability bitmask (bit N = CAP_N, default: 0 = drop all) |
| 5 | ARG | bytes | no | Argument (repeated, appended to argv) |
| 6 | FLAGS | uint32 | no | Spawn flags (bit 0 = PTY mode) |
| 7 | ENV | bytes | no | Environment "KEY\0VALUE" (repeated) |
| 8 | ROOTFS_MB | uint32 | no | tmpfs /tmp size in MB (default: 64) |
| 9 | SECCOMP | uint8 | no | Seccomp profile (0=none, 1=default, 2=strict, 3=network) |
| 10 | DNS_IP | uint32 | no | DNS server IP for /etc/resolv.conf (default: 10.0.0.1) |
| 11 | VOLUME | bytes | no | Host bind mount "src\0dst" + 4B opts (repeated, max 16) |
| 12 | MEMORY_MAX | uint64 | no | cgroup memory.max in bytes |
| 13 | PIDS_MAX | uint32 | no | cgroup pids.max |
| 14 | CPU_WEIGHT | uint32 | no | cgroup cpu.weight (1-10000) |
| 15 | IMAGE_PATH | bytes | no | EROFS image path (empty = tmpfs-only mode) |

**Reply:** REPLY_CONTAINER_PID (0x03)

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | PID | uint32 | Container PID in host namespace |
| 2 | NETNS_PATH | bytes | Path to network namespace (e.g. /proc/PID/ns/net) |

**State transition:** IDLE → CREATED

### CMD_GO (0x11)

Start the container binary. Must be in state CREATED.

No attributes.

Applies irreversible security hardening before execve:
1. Capability drop (container: all except caps_keep; runtime: CAP_KILL only)
2. Securebits lock (NOROOT + NO_SETUID_FIXUP)
3. Seccomp BPF filter
4. Landlock filesystem restriction (runtime: deny all FS access)

**Reply:** REPLY_OK (0x01)

After GO, the runtime sends REPLY_READY (0x04) when execve succeeds,
then streams REPLY_STDOUT/REPLY_STDERR as data arrives, and finally
sends REPLY_EXITED (0x05) when the container exits.

**State transition:** CREATED → RUNNING

### CMD_KILL (0x12)

Send a signal to the container process. Must be in state CREATED or RUNNING.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | SIGNAL | uint8 | yes | Signal number (1-64, e.g. 15=SIGTERM, 9=SIGKILL) |

**Reply:** REPLY_OK (0x01)

Uses pidfd_send_signal() to avoid PID reuse races (fallback: kill()).

### CMD_CGROUP_SET (0x13)

Update cgroup limits on a running container. Must be in state CREATED or RUNNING.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 12 | MEMORY_MAX | uint64 | no | New memory.max in bytes |
| 13 | PIDS_MAX | uint32 | no | New pids.max |
| 14 | CPU_WEIGHT | uint32 | no | New cpu.weight |

**Reply:** REPLY_OK (0x01)

### CMD_QUERY_STATUS (0x14)

Query the current state of the runtime.

No attributes.

**Reply:** REPLY_STATUS (0x06)

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | STATE | uint8 | 0=IDLE, 1=CREATED/RUNNING, 2=STOPPED |
| 2 | PID | uint32 | Container PID (0 if IDLE/STOPPED) |
| 3 | UPTIME_MS | uint64 | Milliseconds since GO (0 if not started) |

In socket mode: if the child exited while disconnected, the runtime
sends a REPLY_EXITED after REPLY_STATUS on the first QUERY_STATUS.

### CMD_NET_SETUP (0x15)

Configure container networking. Must be in state CREATED (after SPAWN, before GO).

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | IFNAME | bytes | yes | Interface name inside container (e.g. "eth0") |
| 2 | CONTAINER_IP | uint32 | yes | Container IP address (host byte order) |
| 3 | GATEWAY_IP | uint32 | yes | Gateway IP address (host byte order) |
| 4 | PREFIXLEN | uint8 | no | Subnet prefix length (default: 24) |

The runtime:
1. Creates a veth pair (host: `vek<PID>`, container: IFNAME)
2. Moves the container end into the container's network namespace
3. Configures IP address, brings up the interface, adds default route
4. All via raw netlink (no fork/exec, no `ip` command)

If XDP steering is active, automatically registers the route in
the BPF map for L4 DSR load balancing.

**Reply:** REPLY_OK (0x01)

### CMD_WRITE_FILE (0x16)

Write a file into the container rootfs. Must be in state CREATED.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | FILE_PATH | bytes | yes | Absolute path inside container |
| 2 | CONTENT | bytes | yes | File content |
| 3 | FILE_MODE | uint32 | no | File permissions (default: 0644) |

Writes via `/proc/<PID>/root/` (follows pivot_root). Creates parent
directories as needed. Path must be absolute, no `..` components.

**Reply:** REPLY_OK (0x01)

### CMD_STDIN (0x17)

Forward stdin data to the container. Must be in state RUNNING.

Raw format (no TLV): `<<0x17, Data/binary>>`

Writes to the container's stdin pipe or PTY master.

### CMD_RESIZE (0x18)

Resize the container's PTY window. Only valid in PTY mode.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | ROWS | uint16 | yes | Terminal rows |
| 2 | COLS | uint16 | yes | Terminal columns |

Uses `ioctl(pty_master, TIOCSWINSZ, ...)`.

**Reply:** REPLY_OK (0x01)

### CMD_DEVICE_FILTER (0x19)

Set device access rules via eBPF cgroup device filter. Must have a cgroup.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | CGROUP_PATH | bytes | yes | cgroup path |
| 2 | DEV_RULE | bytes | no | Device rule (repeated, struct ek_dev_rule) |

Device rule format (5 bytes): `<<Type:8, Major:16BE, Minor:16BE>>`
followed by access mask. Types: 1=block, 2=char. Access: 1=mknod, 2=read, 4=write.

Default allowlist: null, zero, full, random, urandom, tty, ptmx, pts/*.

**Reply:** REPLY_OK (0x01)

### CMD_METRICS_START (0x1A)

Start eBPF tracepoint metrics collection for the container.

| Type | Name | Format | Required | Description |
|------|------|--------|----------|-------------|
| 1 | CGROUP_PATH | bytes | yes | cgroup path to monitor |

Attaches BPF programs to sched:sched_process_fork, sched:sched_process_exec,
sched:sched_process_exit, and oom:mark_victim tracepoints. Events are
collected via a 256 KB ring buffer.

Note: Metrics are auto-started if cgroup limits are set during SPAWN.

**Reply:** REPLY_OK (0x01)

### CMD_METRICS_STOP (0x1B)

Stop eBPF metrics collection.

No attributes.

**Reply:** REPLY_OK (0x01)

## Reply Reference

### REPLY_OK (0x01)

Success. Optional data attribute.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | DATA | bytes | Optional response data |

### REPLY_ERROR (0x02)

Error with machine-readable code and human-readable message.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | CODE | int32 | Negative errno value (e.g. -22 = EINVAL) |
| 2 | MESSAGE | bytes | Error description |

### REPLY_CONTAINER_PID (0x03)

Returned after successful SPAWN.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | PID | uint32 | Container PID |
| 2 | NETNS_PATH | bytes | Network namespace path |

### REPLY_READY (0x04)

Sent after GO when execve succeeds. No attributes.

### REPLY_EXITED (0x05)

Container process has exited.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | EXIT_CODE | int32 | Exit code (-1 if killed by signal) |
| 2 | TERM_SIGNAL | uint8 | Signal number (0 if normal exit) |

### REPLY_STATUS (0x06)

Response to QUERY_STATUS.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | STATE | uint8 | 0=IDLE, 1=RUNNING, 2=STOPPED |
| 2 | PID | uint32 | Container PID |
| 3 | UPTIME_MS | uint64 | Milliseconds since GO |

### REPLY_STDOUT (0x07)

Container stdout data. Raw format: `<<0x07, Data/binary>>` (no TLV).

### REPLY_STDERR (0x08)

Container stderr data. Raw format: `<<0x08, Data/binary>>` (no TLV).

### REPLY_METRICS_EVENT (0x09)

eBPF metrics event from the ring buffer.

| Type | Name | Format | Description |
|------|------|--------|-------------|
| 1 | EVENT_DATA | bytes | struct ek_metrics_event (binary) |

Event types: FORK(1), EXEC(2), EXIT(3), OOM(5).

## Container Lifecycle & State Machine

```
                  CMD_SPAWN             CMD_GO              exit/signal
    ┌──────┐  ──────────────►  ┌─────────┐  ──────────►  ┌─────────┐
    │ IDLE │                   │ CREATED │               │ RUNNING │
    └──┬───┘  ◄──────────────  └─────────┘               └────┬────┘
       ▲      reset after exit       │                        │
       │                        allowed:                      │
       │                        - NET_SETUP                   │
       │                        - WRITE_FILE                  │
       │                        - KILL                        │
       │                                                      │
       │            ┌─────────┐                               │
       └────────────│ STOPPED │  ◄────────────────────────────┘
         auto reset └─────────┘    REPLY_EXITED sent
```

**IDLE** → No container. Only SPAWN accepted.

**CREATED** → Container cloned, rootfs mounted, cgroups set.
Binary NOT yet executing. Allowed: NET_SETUP, WRITE_FILE, KILL, GO.

**RUNNING** → Binary executing (post-execve). Allowed: KILL,
QUERY_STATUS, STDIN, RESIZE, CGROUP_SET, DEVICE_FILTER,
METRICS_START, METRICS_STOP.

**STOPPED** → Child exited. Automatically resets to IDLE for reuse.

## Integration from Erlang

```erlang
%% Socket mode (recommended)
{ok, Sock} = gen_tcp:connect({local, "/run/erlkoenig/web-1.sock"},
                             0, [binary, {packet, 4}, {active, false}]),

%% Handshake
ok = gen_tcp:send(Sock, <<1>>),
{ok, <<1>>} = gen_tcp:recv(Sock, 0, 5000),

%% Spawn
SpawnMsg = <<16#10, 1,                       % CMD_SPAWN, version 1
             0,1, 0,4, "/app",              % TLV: PATH = "/app"
             0,2, 0,4, 0,0,255,254,         % TLV: UID = 65534
             0,3, 0,4, 0,0,255,254,         % TLV: GID = 65534
             0,15, 0,16, "/tmp/app.erofs">>, % TLV: IMAGE_PATH
ok = gen_tcp:send(Sock, SpawnMsg),
{ok, <<16#03, _Ver, Rest/binary>>} = gen_tcp:recv(Sock, 0, 5000),
%% Parse TLV: PID + netns_path from Rest

%% Go
ok = gen_tcp:send(Sock, <<16#11, 1>>),
{ok, <<16#01, _/binary>>} = gen_tcp:recv(Sock, 0, 5000),

%% Watch (active mode for streaming)
inet:setopts(Sock, [{active, true}]),
receive
    {tcp, Sock, <<16#07, Data/binary>>} -> io:format("stdout: ~s~n", [Data]);
    {tcp, Sock, <<16#05, _V, Rest/binary>>} -> %% EXITED, parse exit code
end.
```

## Integration from Python

```python
import socket, struct

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect("/run/erlkoenig/web-1.sock")

def send_frame(data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_frame() -> bytes:
    hdr = sock.recv(4)
    length = struct.unpack(">I", hdr)[0]
    return sock.recv(length)

# Handshake
send_frame(b"\x01")
assert recv_frame() == b"\x01"

# Build SPAWN with TLV attributes
def tlv(type_: int, value: bytes) -> bytes:
    return struct.pack(">HH", type_, len(value)) + value

def tlv_u32(type_: int, val: int) -> bytes:
    return tlv(type_, struct.pack(">I", val))

spawn_attrs = (
    tlv(1, b"/app") +                      # PATH
    tlv_u32(2, 65534) +                     # UID
    tlv_u32(3, 65534) +                     # GID
    tlv(15, b"/tmp/app.erofs")              # IMAGE_PATH
)
send_frame(b"\x10\x01" + spawn_attrs)       # CMD_SPAWN + version
reply = recv_frame()                         # REPLY_CONTAINER_PID

# GO
send_frame(b"\x11\x01")
reply = recv_frame()                         # REPLY_OK

# Watch for output and exit
while True:
    frame = recv_frame()
    tag = frame[0]
    if tag == 0x07:                          # STDOUT
        print(frame[1:].decode(), end="")
    elif tag == 0x08:                        # STDERR
        print("ERR:", frame[1:].decode(), end="")
    elif tag == 0x05:                        # EXITED
        break
```

## Integration from C

See `demo/gateway.c` for a complete example (FaaS HTTP gateway).
See `src/ek_rtctl.c` for the CLI client implementation.

Key functions for building a client:

```c
#include "erlkoenig_buf.h"
#include "erlkoenig_tlv.h"
#include "erlkoenig_proto.h"

// Write a {packet,4} frame
erlkoenig_write_frame(fd, payload, len);

// Read a {packet,4} frame
erlkoenig_read_frame(fd, buf, bufsz, &out_len);

// Build TLV attributes
struct erlkoenig_buf b;
erlkoenig_buf_init(&b, buf, sizeof(buf));
buf_write_u8(&b, ERLKOENIG_TAG_CMD_SPAWN);
buf_write_u8(&b, ERLKOENIG_PROTOCOL_VERSION);
ek_tlv_put_str(&b, EK_ATTR_PATH, "/app");
ek_tlv_put_u32(&b, EK_ATTR_UID, 65534);
ek_tlv_put_u32(&b, EK_ATTR_GID, 65534);
ek_tlv_put_str(&b, EK_ATTR_IMAGE_PATH, "/tmp/app.erofs");
erlkoenig_write_frame(fd, buf, b.pos);

// Parse TLV reply
struct ek_tlv attr;
while (ek_tlv_next(&b, &attr) == 0) {
    switch (attr.type) {
    case EK_ATTR_PID:  pid = ek_tlv_u32(&attr); break;
    case EK_ATTR_NETNS_PATH: /* ... */ break;
    }
}
```

## Security Layers

### Container security (applied during GO)

| Order | Layer | Mechanism |
|-------|-------|-----------|
| 1 | Identity | setresgid/setresuid to container UID/GID |
| 2 | Securebits | NOROOT + NO_SETUID_FIXUP (locked) |
| 3 | Capabilities | Drop all except caps_keep bitmask |
| 4 | Seccomp | BPF filter (3 profiles: strict, network, default) |
| 5 | FD hygiene | close_range(3, MAX, 0) before execve |
| 6 | Exec | execveat(fd, "", AT_EMPTY_PATH) for TOCTOU prevention |

### Runtime self-hardening (applied after GO)

| Order | Layer | Mechanism |
|-------|-------|-----------|
| 1 | Capabilities | Reduced to CAP_KILL only |
| 2 | Landlock | All filesystem access denied (ABI v1-v3) |
| 3 | Seccomp | Denylist: mount, clone, execve, setuid, reboot, io_uring |

### Filesystem isolation

```
EROFS image (read-only, lz4 compressed)
    │
    ▼
loop device → EROFS mount (lower, ro)
    │
    ├── OverlayFS merge (lower=EROFS, upper=tmpfs)
    │       │
    │       ▼
    │   pivot_root into merged view
    │       │
    │       ├── /     → read-only (remounted after pivot)
    │       ├── /tmp  → writable tmpfs (configurable size)
    │       ├── /proc → hidepid=2
    │       └── /dev  → bind-mounted devices (null, zero, urandom, ...)
    │
    └── openat2(RESOLVE_IN_ROOT) for all file access
```

### Seccomp profiles

| ID | Name | Approach | Description |
|----|------|----------|-------------|
| 0 | NONE | - | No filter |
| 1 | DEFAULT | denylist | Block 29 dangerous syscalls, allow everything else |
| 2 | STRICT | allowlist | Allow only 26 syscalls (compute + I/O only) |
| 3 | NETWORK | allowlist | STRICT + socket/bind/listen/accept/connect/send/recv/poll/epoll |

### Namespaces

6 namespaces via clone():
- **PID** — Container is PID 1 (mini-init) + PID 2 (application)
- **MNT** — Isolated mount table (EROFS + overlay + pivot_root)
- **NET** — Own network stack, veth pair to host
- **UTS** — Own hostname
- **IPC** — Isolated System V IPC
- **CGROUP** — Own cgroup view

## Subsystem APIs (C library, not protocol)

These are internal C APIs used by the runtime and the gateway demo.
They are NOT part of the wire protocol.

### Network (erlkoenig_netcfg.h)

```c
// Create veth pair, move peer into container netns
int erlkoenig_netcfg_veth_create(pid_t pid, const char *host_ifname,
                                  const char *peer_ifname);

// Destroy veth pair
int erlkoenig_netcfg_veth_destroy(const char *host_ifname);

// Configure container-side interface (IP, prefix, gateway, up)
int erlkoenig_netcfg_setup(pid_t pid, const char *ifname,
                            uint32_t ip, uint8_t prefixlen, uint32_t gateway);
```

### cgroup v2 (erlkoenig_cg.h)

```c
// Auto-detect cgroup base path
int erlkoenig_cg_detect_base(char *base, size_t base_len);

// Create per-container cgroup with limits
int erlkoenig_cg_setup(pid_t pid, const char *name,
                        uint64_t mem_max, uint32_t pids_max,
                        uint32_t cpu_weight, char *path, size_t path_len);

// Kill all processes and remove cgroup
int erlkoenig_cg_teardown(const char *path);
```

### Container lifecycle (erlkoenig_ns.h)

```c
// Clone child into 6 namespaces, setup rootfs, wait for GO
int erlkoenig_spawn(const struct erlkoenig_spawn_opts *opts,
                     struct erlkoenig_container *ct);

// Signal child to proceed with execve
int erlkoenig_go(struct erlkoenig_container *ct);

// Close remaining FDs (does NOT kill child)
void erlkoenig_cleanup(struct erlkoenig_container *ct);
```

### eBPF metrics (erlkoenig_metrics.h)

```c
// Start tracepoint monitoring for a cgroup
int ek_metrics_start(const char *cgroup_path, struct ek_metrics_ctx *ctx);

// Stop monitoring and clean up
void ek_metrics_stop(struct ek_metrics_ctx *ctx);

// Process pending events via callback
int ek_metrics_consume(struct ek_metrics_ctx *ctx,
                        void (*cb)(const struct ek_metrics_event *, void *),
                        void *user);
```

### Device filter (erlkoenig_devfilter.h)

```c
// Load and attach cgroup device filter BPF program
int ek_devfilter_attach(const char *cgroup_path,
                         const struct ek_dev_rule *rules, int nrules);
```

## Ecosystem

```
┌──────────────────┐     ┌────────────────────┐     ┌──────────────────┐
│   erlkoenig      │     │  erlkoenig_rt      │     │  erlkoenig_ebpfd │
│   (Erlang)       │     │  (C runtime)       │     │  (BPF steering)  │
│                  │     │                    │     │                  │
│  Orchestrator,   │────►│  Container spawn,  │────►│  TC BPF L4 DSR,  │
│  supervision,    │sock │  namespaces,       │     │  XDP steering,   │
│  scheduling      │     │  security,         │     │  bpf_redirect    │
│                  │     │  I/O forwarding    │     │  _peer()         │
└──────────────────┘     └────────────────────┘     └──────────────────┘
```

- **erlkoenig** — Erlang/OTP application. Starts one erlkoenig_rt per container.
  Handles scheduling, health checks, rolling deploys. Not required for standalone use.
- **erlkoenig_rt** — This repo. The actual container runtime.
- **erlkoenig_ebpfd** — Optional. BPF-based packet steering for L4 DSR
  load balancing across containers. Registered automatically if active
  during NET_SETUP.
