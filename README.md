# trace-graph-engine

A distributed systems analysis tool that builds causal mappings between
requests and trace logs to reconstruct execution paths and study scheduling,
latency, and system behavior.

## eBPF TCP Span Tracer

`tcp_tracer` is an eBPF-based application that attaches **kprobes** to the
Linux kernel functions `tcp_sendmsg` and `tcp_recvmsg` (and optionally a
**uprobe** to any user-space function) to trace TCP reads and writes at the
kernel level.

### How it works

1. **Inbound request detection** — a kprobe on `tcp_recvmsg` fires whenever a
   process reads data from a TCP socket.  A fresh `trace_id` is generated for
   the calling PID and stored in a BPF hash map (`pid_trace_map`).

2. **Outbound span propagation** — a kprobe on `tcp_sendmsg` fires whenever a
   process writes to a TCP socket.  The same `trace_id` that was assigned to
   this PID on the most recent inbound read is reused, so the downstream send
   can be causally linked to the request that triggered it.

3. **Uprobe (optional)** — a generic uprobe section can be attached at runtime
   to any user-space symbol (e.g. an HTTP client function inside `curl`) to
   emit a span that shares the current `trace_id`.

4. **Span logs** — every probe emits a JSON object to stdout:

   ```json
   {
     "trace_id": "0xabcdef1234567890",
     "span_id":  "0x1234567890abcdef",
     "operation": "tcp_send",
     "pid": 1234,
     "tid": 1234,
     "comm": "nginx",
     "src": "10.0.0.1:8080",
     "dst": "10.0.0.2:9090",
     "data_len": 1024,
     "timestamp_ns": 1706450812345678901
   }
   ```

### Repository layout

```
ebpf/
  tcp_tracer.bpf.c   — BPF kernel program (kprobes + uprobe)
  tcp_tracer.h       — Shared event structures (BPF ↔ userspace)
tcp_tracer.c         — Userspace loader and JSON span-log consumer
Makefile             — Build system
```

### Build prerequisites

```bash
sudo apt-get install -y clang llvm libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-generic        # provides bpftool
```

### Build

```bash
make
```

This will:
1. Generate `ebpf/vmlinux.h` from the running kernel's BTF information.
2. Compile `ebpf/tcp_tracer.bpf.c` to a BPF ELF object with clang.
3. Compile `tcp_tracer.c` to the `tcp_tracer` userspace binary with gcc.

### Run

```bash
# Trace all TCP sends and receives system-wide:
sudo ./tcp_tracer

# Additionally uprobe a specific user-space function:
sudo ./tcp_tracer \
    --uprobe-binary /usr/bin/curl \
    --uprobe-sym    Curl_senddata

# Uprobe by raw offset when the symbol is stripped:
sudo ./tcp_tracer \
    --uprobe-binary /usr/bin/curl \
    --uprobe-offset 0x12345

# Pipe span logs to a file:
sudo ./tcp_tracer > spans.jsonl
```

Press **Ctrl-C** to stop.

### Options

| Flag | Description |
|------|-------------|
| `--uprobe-binary <path>` | Path to ELF binary to uprobe (optional) |
| `--uprobe-sym <symbol>`  | Symbol name to uprobe (optional if `--uprobe-offset` is given) |
| `--uprobe-offset <hex>`  | Byte offset inside binary (optional if `--uprobe-sym` is given) |
| `-h`, `--help`           | Print usage and exit |

### Permissions

Loading BPF programs requires `CAP_BPF` (Linux ≥ 5.8) or root.  On older
kernels the `RLIMIT_MEMLOCK` limit must be raised; the loader does this
automatically.
