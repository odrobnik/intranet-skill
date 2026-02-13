# Intranet Skill

An [OpenClaw](https://openclaw.ai) skill providing a lightweight local HTTP file server with dynamic Python pages and plugin support.

## Features

- **Static file serving** from a configurable root directory
- **Dynamic Python pages** — executable `.py` files run as CGI scripts for dashboards, APIs, etc.
- **Plugin support** — other skills add content via symlinks into the webroot
- **Path traversal protection** — requests are sandboxed to the root directory
- **Directory listing** with clean HTML interface
- **PID management** — start/stop/status with process tracking
- **ngrok compatible** — tunnel for remote access outside your LAN

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
ln -s ~/clawd/deliveries ~/clawd/intranet/deliveries
# → http://localhost:8080/deliveries/
```

## Remote Access

```bash
ngrok http 8080
```

## License

MIT
