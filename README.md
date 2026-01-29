# Intranet Skill

Lightweight local HTTP file server for `~/clawd/intranet` (or a custom root).

## Usage
```bash
# Start
python3 scripts/intranet.py start

# Status
python3 scripts/intranet.py status

# Stop
python3 scripts/intranet.py stop
```

## Options
- `--host <host>` (default: 0.0.0.0)
- `--port <port>` (default: 8080)
- `--dir <path>` (default: ~/clawd/intranet)

## Plugin support
Other skills can add content via symlinks:
```bash
ln -s ~/banker ~/clawd/intranet/banker
ln -s ~/my-docs ~/clawd/intranet/docs
```

Visit: `http://localhost:8080/`

## Notes
- PID stored at `~/.intranet.pid`
- Config stored at `~/.intranet.conf`
- See `SKILL.md` for agent usage guidance
