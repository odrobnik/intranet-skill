# Intranet Skill

An [OpenClaw](https://openclaw.ai) skill providing a lightweight local HTTP file server — no Apache/nginx needed, no root required.

## Why?

Apache and nginx require sudo, complex configuration, and are overkill for serving workspace files on your LAN. This skill starts a Python HTTP server in one command, serving dashboards, JSON APIs, and web UIs for local automations.

## Features

- **Static file serving** from a configurable root directory
- **Dynamic Python pages** — executable `.py` files run as CGI scripts for dashboards, APIs, etc.
- **Plugin support** — other skills add content via symlinks into the webroot
- **Security** — path traversal protection, workspace-scoped CGI execution, executable permission required
- **Directory listing** with clean HTML interface
- **PID management** — start/stop/status with process tracking
- **ngrok compatible** — tunnel for remote access outside your LAN

## Requirements

- Python 3 (no external packages)

## Quick Start

```bash
# Start server (accessible on LAN)
python3 scripts/intranet.py start

# Local-only (not accessible from LAN)
python3 scripts/intranet.py start --host localhost

# Check status
python3 scripts/intranet.py status

# Stop server
python3 scripts/intranet.py stop
```

Default: `http://localhost:8080/`

## Plugin Example

```bash
# Serve another skill's web dashboard
ln -s ~/clawd/deliveries ~/clawd/intranet/deliveries
# → http://localhost:8080/deliveries/
```

## Security Model

- Symlinks in the webroot may point outside it, but only to targets within the workspace or `/tmp`
- `.py` files are only executed if they have the executable bit set AND resolve within the workspace
- The server binds to `0.0.0.0` by default (LAN accessible). Use `--host localhost` for local-only access
- All symlinked content and `.py` files in the webroot are treated as trusted
- 30-second timeout on CGI execution

## License

MIT
