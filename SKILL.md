---
name: intranet
description: "Lightweight local HTTP file server with plugin support. Serves static files from a webroot, mounts plugin directories at URL prefixes via config, and runs index.py entry points as CGI. Symlinks skipped in directory listings."
summary: "Local HTTP file server with config-based plugins and CGI support."
version: 2.1.0
homepage: https://github.com/odrobnik/intranet-skill
metadata:
  openclaw:
    emoji: "🌐"
    requires:
      bins: ["python3"]
---

# Intranet

Lightweight local HTTP file server — no Apache/nginx needed, no root required. Serves static files, mounts plugin directories, and runs `index.py` entry points as CGI.

**Entry point:** `{baseDir}/scripts/intranet.py`

## Setup

See [SETUP.md](SETUP.md) for prerequisites and setup instructions.

## Commands

```bash
python3 {baseDir}/scripts/intranet.py start                          # Start on default port 8080
python3 {baseDir}/scripts/intranet.py start --port 9000              # Custom port
python3 {baseDir}/scripts/intranet.py start --host localhost          # Local-only (no LAN)
python3 {baseDir}/scripts/intranet.py start --token SECRET            # Enable bearer token auth
python3 {baseDir}/scripts/intranet.py status                         # Check if running
python3 {baseDir}/scripts/intranet.py stop                           # Stop server
```

## Plugins

Plugins mount external directories at URL prefixes. Configure in `config.json`:

```json
{
  "plugins": {
    "banker": "/path/to/banker",
    "deliveries": "/path/to/deliveries"
  }
}
```

- `/banker/*` → served from the banker directory
- If the plugin directory contains an `index.py`, it handles **all** sub-paths as CGI
- If no `index.py`, files are served statically (with `index.html` as default)

## CGI Execution

Only files named `index.py` can execute as CGI:

- **Webroot**: `index.py` in any subdirectory handles that directory's requests
- **Plugins**: `index.py` at the plugin root handles all plugin sub-paths
- **All other `.py` files** → 403 Forbidden (never served, never executed)
- Scripts must have the executable bit set (`chmod +x`)

## Security

- **Symlinks skipped** in directory listings; all resolved paths checked for strict containment within webroot/plugins
- **Plugin allowlist** — only directories explicitly registered in `config.json` are served; must be inside workspace
- **CGI restricted to `index.py`** — no arbitrary script execution
- **All `.py` files blocked** except `index.py` entry points (not served as text, not executed)
- **Host allowlist** — optional `allowed_hosts` restricts which `Host` headers are accepted
- **Token auth** — optional bearer token via `--token` flag, `INTRANET_TOKEN` env var, or `config.json`. Browser clients visit `?token=SECRET` once → session cookie set → all subsequent navigation works. API clients use `Authorization: Bearer <token>` header.
- **Path traversal protection** — all paths resolved and validated before serving
- **Default bind: `0.0.0.0`** (all interfaces). Use `--host localhost` for local-only access.

## Notes
- PID file: `~/.intranet.pid`
- Config file: `~/.intranet.conf`
- Root: always `{workspace}/intranet/` (auto-detected, not configurable)
- 30-second timeout on CGI execution
