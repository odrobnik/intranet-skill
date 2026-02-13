# Setup

## Prerequisites

- Python 3 (no additional packages required — uses built-in `http.server`)

## Configuration

### Root Directory

The server serves files from a root directory, created automatically if it doesn't exist.

| Source | Value |
|---|---|
| Default | `{workspace}/intranet/` |
| Env var | `INTRANET_DIR` |
| CLI flag | `--dir <path>` |

### Server Settings

| Setting | Default | Flag |
|---|---|---|
| Host | `0.0.0.0` | `--host` |
| Port | `8080` | `--port` |

### State Files

- `~/.intranet.pid` — PID of running server
- `~/.intranet.conf` — Runtime config (host, port, directory)

Created automatically on start, cleaned up on stop.

## Plugin Integration

Symlink directories into the webroot to serve content from other skills:

```bash
ln -s /path/to/content {workspace}/intranet/my-plugin
```

The server follows symlinks and supports executable `.py` CGI scripts.
