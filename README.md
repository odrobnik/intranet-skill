# Intranet Skill

An [OpenClaw](https://openclaw.ai) skill providing a lightweight local HTTP file server with plugin support.

## Features

- **Simple file serving** from a configurable root directory
- **Plugin support** — other skills add content via symlinks
- **CGI scripts** — executable `.py` files run as dynamic content
- **Directory listing** with clean HTML interface
- **PID management** — start/stop/status with process tracking
- **Path traversal protection** built in

## Requirements

- Python 3 (no external packages)

## Quick Start

```bash
# Start server
python3 scripts/intranet.py start

# Check status
python3 scripts/intranet.py status

# Stop server
python3 scripts/intranet.py stop
```

Default: `http://localhost:8080/`

## Plugin Example

```bash
# Serve another skill's web dashboard
ln -s ~/my-dashboard ~/clawd/intranet/dashboard
# → http://localhost:8080/dashboard/
```

## License

MIT
