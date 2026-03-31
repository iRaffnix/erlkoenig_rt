# erlkoenig_rt

Privileged container runtime for the [erlkoenig](https://github.com/iRaffnix/erlkoenig) ecosystem.
One process per container, ~164 KB static binary, zero runtime dependencies.

A control plane (Erlang, shell, or any language) talks to erlkoenig_rt over a Unix socket
using a binary TLV protocol. Each container gets 6 Linux namespaces, a read-only EROFS
rootfs with tmpfs overlay, seccomp, Landlock, capability drop, and cgroup v2 limits.

```
Control Plane --> Unix Socket --> erlkoenig_rt (static musl)
                                      |
                                      +-- clone(mount, pid, net, uts, ipc, cgroup)
                                      +-- EROFS mount + OverlayFS + pivot_root
                                      +-- seccomp + Landlock + cap drop
                                      +-- execveat container binary
```

## Build

Requires Linux >= 5.13, musl-gcc, cmake >= 3.10.

```bash
make                  # build/erlkoenig_rt, build/ek_rtctl, build/gateway
```

## Quick start

```bash
# Create a minimal EROFS container image
mkdir -p /tmp/rootfs && cp build/testbin/test-erlkoenig-hello_output /tmp/rootfs/app
chmod 555 /tmp/rootfs/app && mkfs.erofs -zlz4 /tmp/hello.erofs /tmp/rootfs/

# Start runtime + spawn container
sudo build/erlkoenig_rt --socket /tmp/test.sock &
build/ek_rtctl /tmp/test.sock spawn --path /app --image /tmp/hello.erofs
build/ek_rtctl /tmp/test.sock go
build/ek_rtctl /tmp/test.sock watch
```

## Container lifecycle

```
          spawn              go              exit/kill
IDLE ----------> CREATED ----------> RUNNING ----------> STOPPED
                    |
              net setup
              write files
```

- **spawn** -- clone into namespaces, mount rootfs, setup cgroups. Returns PID + netns path.
- **go** -- apply seccomp, Landlock, cap drop, then execveat.
- **watch** -- stream stdout/stderr/exit events over the socket.

## Wire protocol

Binary TLV over Unix socket with `{packet, 4}` framing (4-byte BE length prefix).

| Tag | Name | Direction |
|-----|------|-----------|
| `0x10` | SPAWN | client -> runtime |
| `0x11` | GO | client -> runtime |
| `0x12` | KILL | client -> runtime |
| `0x13` | CGROUP_SET | client -> runtime |
| `0x14` | QUERY_STATUS | client -> runtime |
| `0x15` | NET_SETUP | client -> runtime |
| `0x16` | WRITE_FILE | client -> runtime |
| `0x17` | STDIN | client -> runtime |
| `0x18` | RESIZE | client -> runtime |
| `0x19` | DEVICE_FILTER | client -> runtime |
| `0x1A` | METRICS_START | client -> runtime |
| `0x1B` | METRICS_STOP | client -> runtime |
| `0x01` | OK | runtime -> client |
| `0x02` | ERROR | runtime -> client |
| `0x03` | CONTAINER_PID | runtime -> client |
| `0x04` | READY | runtime -> client |
| `0x05` | EXITED | runtime -> client |
| `0x06` | STATUS | runtime -> client |
| `0x07` | STDOUT | runtime -> client |
| `0x08` | STDERR | runtime -> client |
| `0x09` | METRICS_EVENT | runtime -> client |

Source of truth: [include/erlkoenig_proto.h](include/erlkoenig_proto.h)

## Security

| Layer | Mechanism |
|-------|-----------|
| Filesystem | Read-only EROFS + tmpfs overlay, openat2(RESOLVE_IN_ROOT) |
| Namespaces | mount, pid, net, uts, ipc, cgroup |
| Syscalls | Seccomp BPF (29 syscalls blocked) |
| FS access | Landlock (all denied post-go, pre-opened FDs only) |
| Capabilities | Only CAP_KILL retained after go |
| FD hygiene | close_range before execveat |

## Install

```bash
sudo make install
# or: sudo ./scripts/install.sh --prefix /opt/erlkoenig
```

Installs runtime, CLI, systemd units, sysusers/tmpfiles config.

```bash
sudo systemctl start erlkoenig-rt@web-1
ek_rtctl /run/erlkoenig/web-1.sock spawn --path /app --image app.erofs
ek_rtctl /run/erlkoenig/web-1.sock go
```

## Testing

```bash
make test                         # Unit tests (requires root + libcheck)
sudo ./scripts/test-erofs.sh      # EROFS integration tests
sudo ./scripts/bench-startup.sh   # Startup benchmarks
```

## Related

- [erlkoenig](https://github.com/iRaffnix/erlkoenig) -- Erlang control plane
- [erlkoenig_ebpfd](https://github.com/iRaffnix/erlkoenig_ebpfd) -- BPF packet steering, L4 DSR

## Documentation

- [Architecture & Integration](docs/ARCHITECTURE.md) -- Wire protocol, API reference, integration examples
- [Getting Started](docs/GETTING_STARTED.md) -- Detailed walkthrough
- [Installation](INSTALL.md) -- Build, install, systemd setup

## License

Apache License 2.0. See [LICENSE](LICENSE).
