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

To expose the intranet outside your LAN, use any HTTP tunnel or reverse proxy (e.g. Cloudflare Tunnel, Tailscale Funnel, or similar). When exposing to the internet, **always enable token authentication** (see below).

## Authentication

Enable bearer token authentication to restrict access:

```bash
# Via CLI flag
python3 scripts/intranet.py start --token MY_SECRET_TOKEN

# Via environment variable
INTRANET_TOKEN=MY_SECRET_TOKEN python3 scripts/intranet.py start
```

When a token is set, clients authenticate via:
- **Query param:** `?token=MY_SECRET_TOKEN` — sets a session cookie and redirects to strip the token from the URL. All subsequent requests use the cookie automatically. Ideal for browsers.
- **Header:** `Authorization: Bearer MY_SECRET_TOKEN` — for API/curl clients (no cookie needed).

The session cookie is `HttpOnly`, `SameSite=Strict`, valid for 30 days. The token never appears in URLs after the initial redirect.

Requests without a valid token or session cookie receive `401 Unauthorized`.

## Host Allowlist

Restrict which hostnames the server responds to via `allowed_hosts` in `config.json`:

```json
{
  "allowed_hosts": [
    "localhost",
    "my-machine.local",
    "my-tunnel.example.com"
  ]
}
```

Requests with a `Host` header not on the list receive `403 Forbidden` — before authentication is even checked. This prevents direct IP access and unknown hostname probing.

When `allowed_hosts` is omitted or empty, all hosts are accepted (suitable for LAN-only use).

## Persistent Config (`config.json`)

All settings can be stored in `{workspace}/intranet/config.json`:

```json
{
  "token": "MY_SECRET_TOKEN",
  "allowed_hosts": ["localhost", "my-machine.local"],
  "allowed_paths": ["~/extra/allowed/dir"],
  "env": {
    "MY_VAR": "value"
  }
}
```

| Key | Description |
|---|---|
| `token` | Bearer token (fallback if no `--token` flag or env var) |
| `allowed_hosts` | Hostnames the server responds to |
| `allowed_paths` | Extra directories allowed for symlink targets and CGI scripts (beyond workspace and `/tmp`) |
| `env` | Extra environment variables injected into CGI scripts |
