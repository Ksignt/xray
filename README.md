# xray

A distributed systems analysis tool that builds causal mappings between requests and trace logs to reconstruct execution paths and study scheduling, latency, and system behavior.

Run (local development)

Prerequisites:

- Go 1.22+

1. Copy the example config into a local `config.yaml` and edit the `target_binary` path:

```bash
cp config.template.yaml config.yaml
# edit config.yaml and set `target_binary` to the absolute path of the running binary
```

2. Compile and run `main.go` (note: the config reader expects `../config.yaml` relative to the process working directory).

Option A — quick run (recommended for development):

```bash
cd configReader
go run ../main.go
```

Option B — build a binary and run it with the working directory set to `configReader`:

```bash
# build from the repository root
go build -o trace-graph-engine main.go

# run the built binary from the configReader directory so the reader finds ../config.yaml
cd configReader
../trace-graph-engine
```

Why run from `configReader`? `configReader.GetConfig()` reads `../config.yaml` using a relative path, which is resolved from the process working directory. Running from `configReader` makes `../config.yaml` point to the repo root `config.yaml`.

If you want to run the binary from another working directory, update `configReader/reader.go` to accept an absolute path or a `--config` flag.

Developer tips:

- To update module dependencies:

```bash
cd /home/skres/trace-graph-engine
go mod tidy
```

- To build all packages:

```bash
go build ./...
```

See `config.template.yaml` for the configuration format.

Building and running (BPF + userspace)

When working with the eBPF + userspace components you must compile the userspace C helpers, build the eBPF object, then build the Go binary. Example commands (run from repository root):

1) Compile the userspace tracer helper into an object and archive it into a static library:

```bash
# compile the userspace helper (from repo root)
gcc -c tracer/tcp_to_pid_user.c -o tcp_to_pid_user.o
# create a static archive library
ar rcs libtcp_to_pid_user.a tcp_to_pid_user.o
```

2) Build the eBPF object for your target architecture. You must define the target architecture (for example `arm64`) when compiling the BPF program. Example for ARM64:

```bash
# compile the BPF program (set -D__TARGET_ARCH_<arch> as needed)
clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -c tracer/tcp_to_pid.bpf.c -o tracer/tcp_to_pid.bpf.o
```

Replace `arm64` above with your architecture where appropriate (for example `x86_64` might use `-D__TARGET_ARCH_x86`).

3) Build the Go binary (from repository root):

```bash
go build -o trace-graph-engine .
```

4) Run the binary (ensure you run with appropriate privileges if loading BPF programs is required):

```bash
sudo ./trace-graph-engine
```

Notes:
- The BPF object file `tracer/tcp_to_pid.bpf.o` must be accessible relative to the process working directory; the default paths the userspace loader tries include `tracer/tcp_to_pid.bpf.o` and `./tracer/tcp_to_pid.bpf.o`.
- If you change the working directory from the repo root, adjust paths or rebuild accordingly.
- Building and loading eBPF programs requires appropriate kernel headers and clang/llvm toolchain configured for BPF cross-compilation.
