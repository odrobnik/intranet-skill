# Intranet Skill

An [OpenClaw](https://openclaw.ai) skill providing a lightweight local HTTP file server — no Apache/nginx needed, no root required.

## Why?

Apache and nginx require sudo, complex configuration, and are overkill for serving workspace files on your LAN. This skill starts a Python HTTP server in one command, serving dashboards, JSON APIs, and web UIs for local automations.

## Features

- **Static file serving** from a webroot directory
- **Plugin support** — mount external directories at URL prefixes via `config.json`
- **CGI execution** — `index.py` entry points run as CGI (off by default, opt-in via config)
- **Directory listing** with clean HTML interface
- **PID management** — start/stop/status with process tracking
- **Bearer token auth** — optional authentication for remote/public access
- **Tunnel-friendly** — works behind any HTTP tunnel or reverse proxy

## Requirements

- Python 3 (no external packages)

## Quick Start

```bash
# Start server (localhost only by default)
python3 scripts/intranet.py start

# Check status
python3 scripts/intranet.py status

# Stop server
python3 scripts/intranet.py stop
```

Default: `http://localhost:8080/`

## Security Model

- **Path containment** — all resolved paths (including symlinks) must stay within their base directory
- **CGI off by default** — enable via `"cgi": true` in config.json
- **CGI restricted to `index.py`** — no arbitrary script execution
- **Plugin CGI requires hash verification** — SHA-256 of `index.py` must match config
- **Plugin directories must be inside workspace** — enforced at startup
- **LAN binding requires auth** — binding to `0.0.0.0` requires both token and `allowed_hosts`
- 30-second timeout on CGI execution

## Documentation

- [SKILL.md](SKILL.md) — agent-facing reference (commands, behavior, limitations)
- [SETUP.md](SETUP.md) — prerequisites, configuration, and setup instructions
- [ClawHub](https://www.clawhub.com/skills/intranet) — install via ClawHub registry

## License

MIT
