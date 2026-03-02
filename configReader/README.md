# configReader

Reads `config.yaml` from the project root and resolves the PID of the configured target binary using its full path.

## Prerequisites

- Go 1.22+
- The target binary specified in `config.yaml` must be running

## Configuration

Copy the template and edit it:

```bash
cp config.template.yaml ../config.yaml
```

Edit `../config.yaml`:

```yaml
target_binary: /absolute/path/to/your/binary
```

## Build

```bash
go build -o reader .
```

## Run

Must be run from the `configReader/` directory (the config path is relative to it):

```bash
./reader
```

### Example output

```
Target Binary: /home/skres/trace-graph-engine/mock/App
PID: 12345
```
