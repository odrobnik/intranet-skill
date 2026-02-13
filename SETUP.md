# Setup

## Prerequisites

- Python 3 (no additional packages — uses built-in `http.server`)

## Configuration

### Root Directory

The server serves files from a configurable root directory, created automatically if it doesn't exist.

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

Symlink skill directories into the webroot:

```bash
ln -s {workspace}/deliveries {workspace}/intranet/deliveries
```

### Dynamic Pages

Make any `.py` file executable in the webroot and it runs as a CGI script:

```bash
chmod +x {workspace}/intranet/my-dashboard/index.py
```

## Remote Access

To expose the intranet outside your LAN, use [ngrok](https://ngrok.com):

```bash
ngrok http 8080
# or with a fixed domain:
ngrok http 8080 --url your-domain.ngrok-free.app
```
