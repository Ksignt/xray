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
