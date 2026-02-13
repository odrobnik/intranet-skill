#!/usr/bin/env python3
"""intranet_web.py

Simple web server for serving static files from a root directory.

Features:
- Serves files from a configurable root directory
- Follows symlinks (enabling plugin support for other skills)
- Directory listing with simple HTML interface
- Content type detection for common file types

Security note:
- View-only by intent
- Bound to local network by default (0.0.0.0)
- Path traversal protection included
"""

import hashlib
import hmac
import html
import http.cookies
import mimetypes
import os
import posixpath
import secrets
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional

# Session cookie name and max age (30 days)
_COOKIE_NAME = "intranet_session"
_COOKIE_MAX_AGE = 30 * 24 * 3600


def _find_workspace_root() -> Path:
    """Walk up from script location to find workspace root (parent of 'skills/')."""
    env = os.environ.get("INTRANET_WORKSPACE")
    if env:
        return Path(env)
    
    # Prefer CWD if it looks like a workspace (handles symlinks correctly)
    cwd = Path.cwd()
    if (cwd / "skills").is_dir():
        return cwd

    d = Path(__file__).resolve().parent
    for _ in range(6):
        if (d / "skills").is_dir() and d != d.parent:
            return d
        d = d.parent
    return Path.cwd()


# Initialize mimetypes
mimetypes.init()


def _read_ignore_list(path: Path) -> set[str]:
    """Read a simple ignore file (one token per line).

    - blank lines ignored
    - lines starting with # ignored
    - tokens matched case-insensitively
    """
    try:
        if not path.exists() or not path.is_file():
            return set()
        out: set[str] = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            s = (line or "").strip()
            if not s or s.startswith("#"):
                continue
            out.add(s.lower())
        return out
    except Exception:
        return set()


def _banker_ignore_tokens(root_dir: Path, dir_path: Path, url_path: str) -> set[str]:
    """Return ignore tokens for banker directory listings.

    Looks for `.bankerignore` files:
    - at the banker root (intranet/<banker symlink>/..)
    - in any parent directory between the current listing and banker root

    This allows both global ignores (~/banker/.bankerignore) and per-bank ignores
    (~/banker/banks/<bank>/.bankerignore).
    """
    if not (url_path or "").startswith("/banker/"):
        return set()

    try:
        banker_root = (root_dir / "banker").resolve()
        cur = dir_path.resolve()
    except Exception:
        return set()

    if not banker_root.exists() or not banker_root.is_dir():
        return set()

    tokens: set[str] = set()

    # Only walk parents if we're actually inside the banker tree.
    if cur == banker_root or banker_root in cur.parents:
        p = cur
        while True:
            tokens |= _read_ignore_list(p / ".bankerignore")
            if p == banker_root:
                break
            p = p.parent

    return tokens


def _h(s: any) -> str:
    """HTML escape helper."""
    return html.escape("" if s is None else str(s), quote=True)


def _bytes_format(n: int) -> str:
    """Format bytes as human-readable size."""
    for unit, div in (("B", 1), ("KB", 1024), ("MB", 1024**2), ("GB", 1024**3)):
        if n < 1024 or unit == "GB":
            if unit == "B":
                return f"{n} B"
            return f"{n/div:.2f} {unit}"
        n //= 1024
    return f"{n} B"


def _is_within_workspace(path: Path) -> bool:
    """Check if a resolved path is within the workspace or /tmp."""
    resolved = path.resolve()
    workspace = _find_workspace_root().resolve()
    allowed = [workspace, Path("/tmp").resolve()]
    return any(resolved == a or a in resolved.parents for a in allowed)


def _is_trusted_symlink(symlink_path: Path) -> bool:
    """Check if a symlink is trusted for serving.

    A symlink is trusted if:
    1. It lives within the workspace (owner placed it), AND
    2. Its immediate target (readlink, not fully resolved) points into
       the workspace or /tmp.

    This prevents arbitrary symlinks to sensitive files (e.g. /etc/passwd)
    while allowing workspace symlink chains (e.g. intranet/tasks →
    workspace/skills/foo/web where skills/foo is itself a symlink).
    """
    workspace = _find_workspace_root().resolve()
    allowed = [workspace, Path("/tmp").resolve()]

    # Check symlink location (parent must be in workspace)
    parent = symlink_path.parent.resolve()
    if not any(parent == a or a in parent.parents for a in allowed):
        return False

    # Check immediate target (one level of readlink, not full resolve)
    try:
        immediate = Path(os.readlink(symlink_path))
        if not immediate.is_absolute():
            immediate = (symlink_path.parent / immediate)
        # Normalize without resolving symlinks
        immediate = Path(os.path.normpath(str(immediate)))
        return any(immediate == a or a in immediate.parents for a in allowed)
    except OSError:
        return False


def _safe_resolve(base: Path, rel: str) -> Optional[Path]:
    """Safely resolve a relative path within base directory.

    Returns None if the path would escape the base directory.
    Symlinks that live within the workspace are trusted (the owner placed
    them intentionally), regardless of where they point.
    """
    rel = rel.lstrip("/")
    base_res = base.resolve()

    # Walk path components to find symlinks
    parts = Path(rel).parts if rel else ()
    current = base_res
    for i, part in enumerate(parts):
        next_path = current / part
        if next_path.is_symlink():
            # Trust symlinks within workspace that point to workspace paths
            if not _is_trusted_symlink(next_path):
                return None
            resolved = next_path.resolve()
            remaining = Path(*parts[i + 1:]) if i + 1 < len(parts) else Path()
            return resolved / remaining if remaining.parts else resolved
        current = next_path

    # No symlinks encountered — strict containment check
    candidate = (base / rel).resolve()
    if candidate == base_res or base_res in candidate.parents:
        return candidate
    return None


def _page(title: str, body_html: str) -> str:
    """Generate a simple HTML page."""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_h(title)}</title>
  <style>
    body {{
      font-family: -apple-system, system-ui, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      margin: 24px;
      max-width: 1200px;
    }}
    h1 {{ margin-bottom: 8px; }}
    .muted {{ color: #666; font-size: 14px; }}
    table {{
      border-collapse: collapse;
      width: 100%;
      margin-top: 16px;
    }}
    th, td {{
      border-bottom: 1px solid #eee;
      padding: 8px 12px;
      text-align: left;
    }}
    th {{
      background: #f8f8f8;
      font-weight: 600;
      position: sticky;
      top: 0;
    }}
    tr:hover td {{ background: #fafafa; }}
    a {{ color: #0066cc; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    .icon {{
      display: inline-block;
      width: 20px;
      text-align: center;
      margin-right: 8px;
    }}
    .right {{ text-align: right; }}
  </style>
</head>
<body>
  {body_html}
</body>
</html>"""


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP server."""
    daemon_threads = True


class IntranetHandler(BaseHTTPRequestHandler):
    """HTTP request handler for serving files."""

    server_version = "intranet-web/1.0"

    def _find_cgi_handler(self, url_path: str) -> Optional[Path]:
        """Find an index.py CGI handler for the given URL path.

        Walks up the path hierarchy looking for symlinked directories
        that contain an index.py, which should handle all sub-paths.
        """
        parts = url_path.strip("/").split("/") if url_path.strip("/") else []
        base = self.server.root_dir.resolve()

        # Check each prefix of the path
        for i in range(len(parts), 0, -1):
            prefix = "/".join(parts[:i])
            check_path = base / prefix

            # If this path component is a symlink, check for index.py
            if check_path.is_symlink() or (i == 1 and check_path.exists()):
                resolved = check_path.resolve() if check_path.exists() else None
                if resolved and resolved.is_dir():
                    index_py = resolved / "index.py"
                    if index_py.exists() and index_py.is_file():
                        return index_py

        return None

    def _check_host(self) -> bool:
        """Check if the request's Host header is in the allowed hosts list.

        Returns True if allowed, False if denied (response already sent).
        When no allowed_hosts are configured, all hosts are accepted.
        """
        allowed = getattr(self.server, "allowed_hosts", None)
        if not allowed:
            return True

        host = (self.headers.get("Host") or "").lower().split(":")[0]
        if host in allowed:
            return True

        self.send_response(HTTPStatus.FORBIDDEN)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        body = b"403 Forbidden\n"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _make_session_mac(self, token: str) -> str:
        """Create an HMAC session value from the token + server secret."""
        secret = getattr(self.server, "session_secret", b"")
        return hmac.new(secret, token.encode(), hashlib.sha256).hexdigest()

    def _get_cookie(self, name: str) -> str | None:
        """Extract a cookie value from the request."""
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        try:
            cookies = http.cookies.SimpleCookie(cookie_header)
            morsel = cookies.get(name)
            return morsel.value if morsel else None
        except Exception:
            return None

    def _set_session_cookie(self, mac: str) -> str:
        """Build a Set-Cookie header value."""
        c = http.cookies.SimpleCookie()
        c[_COOKIE_NAME] = mac
        c[_COOKIE_NAME]["httponly"] = True
        c[_COOKIE_NAME]["samesite"] = "Strict"
        c[_COOKIE_NAME]["max-age"] = str(_COOKIE_MAX_AGE)
        c[_COOKIE_NAME]["path"] = "/"
        # Extract just the header value (SimpleCookie outputs "Set-Cookie: name=val")
        return c[_COOKIE_NAME].OutputString()

    def _check_auth(self) -> bool:
        """Check authentication if a token is configured.

        Auth flow:
        1. No token configured → allow all (LAN use).
        2. Valid session cookie → allow.
        3. Valid Authorization: Bearer header → allow (API clients).
        4. Valid ?token= query param → set session cookie, redirect to
           strip the token from the URL (browser use).
        5. Otherwise → 401.

        Returns True if the request should proceed, False if a response
        was already sent (redirect or 401).
        """
        required_token = getattr(self.server, "auth_token", None)
        if not required_token:
            return True

        expected_mac = self._make_session_mac(required_token)

        # 1. Check session cookie
        cookie_val = self._get_cookie(_COOKIE_NAME)
        if cookie_val and hmac.compare_digest(cookie_val, expected_mac):
            return True

        # 2. Check Authorization header (for API / curl clients)
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer ") and hmac.compare_digest(auth_header[7:], required_token):
            return True

        # 3. Check ?token= query param → set cookie + redirect
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        token_values = params.get("token", [])
        if token_values and hmac.compare_digest(token_values[0], required_token):
            # Build redirect URL without the token param
            remaining = {k: v for k, v in params.items() if k != "token"}
            clean_query = urllib.parse.urlencode(remaining, doseq=True)
            clean_path = parsed.path
            if clean_query:
                clean_path += "?" + clean_query

            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", clean_path)
            self.send_header("Set-Cookie", self._set_session_cookie(expected_mac))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False

        # 4. Denied
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("WWW-Authenticate", "Bearer")
        body = b"401 Unauthorized\n"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def do_GET(self):
        """Handle GET requests."""
        if not self._check_host():
            return
        if not self._check_auth():
            return

        parsed = urllib.parse.urlparse(self.path)
        path_only = urllib.parse.unquote(parsed.path)

        # Resolve the file system path
        fs_path = _safe_resolve(self.server.root_dir, path_only)

        if fs_path is None:
            self._send_error(HTTPStatus.FORBIDDEN, "Forbidden")
            return

        # First priority: exact path exists
        if fs_path.exists():
            # Handle directories
            if fs_path.is_dir():
                # Redirect if path doesn't end with /
                if not path_only.endswith("/"):
                    self.send_response(HTTPStatus.MOVED_PERMANENTLY)
                    self.send_header("Location", path_only + "/")
                    self.end_headers()
                    return

                # Try to serve index.py (CGI) or index.html
                index_py = fs_path / "index.py"
                if index_py.exists() and index_py.is_file():
                    self._execute_python(index_py, path_only)
                    return

                index_html = fs_path / "index.html"
                if index_html.exists() and index_html.is_file():
                    self._serve_file(index_html)
                    return

                # Otherwise show directory listing
                self._serve_directory(fs_path, path_only)
                return

            # Handle .py files as CGI
            if fs_path.is_file() and fs_path.suffix == ".py":
                self._execute_python(fs_path, path_only)
                return

            # Handle other files
            if fs_path.is_file():
                self._serve_file(fs_path)
                return

        # Second priority: try adding .py extension
        if not path_only.endswith('.py'):
            py_path = _safe_resolve(self.server.root_dir, path_only + '.py')
            if py_path and py_path.exists() and py_path.is_file():
                self._execute_python(py_path, path_only)
                return

        # Third priority: check if any parent directory has an index.py that should handle this request
        # This allows CGI apps to handle all sub-paths (e.g., /banker/george/ -> banker's index.py)
        cgi_handler = self._find_cgi_handler(path_only)
        if cgi_handler:
            self._execute_python(cgi_handler, path_only)
            return

        self._send_error(HTTPStatus.NOT_FOUND, "Not Found")

    def _serve_directory(self, dir_path: Path, url_path: str):
        """Serve a directory listing."""
        try:
            entries = []

            # Add parent directory link if not at root
            if url_path != "/":
                parent_url = posixpath.dirname(url_path.rstrip("/")) + "/"
                entries.append({
                    "name": "..",
                    "url": parent_url,
                    "is_dir": True,
                    "is_symlink": False,
                    "size": "",
                    "icon": "📁",
                })

            ignore_tokens = _banker_ignore_tokens(self.server.root_dir, dir_path, url_path)

            # List directory contents
            for entry in sorted(dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                # Skip hidden files
                if entry.name.startswith("."):
                    continue

                # Banker-specific ignore support
                if ignore_tokens and entry.name.lower() in ignore_tokens:
                    continue

                is_dir = entry.is_dir()
                is_symlink = entry.is_symlink()

                # Get size for files
                size = ""
                if not is_dir:
                    try:
                        size = _bytes_format(entry.stat().st_size)
                    except OSError:
                        size = "?"

                # Build URL
                entry_url = posixpath.join(url_path, urllib.parse.quote(entry.name))
                if is_dir and not entry_url.endswith("/"):
                    entry_url += "/"

                # Choose icon
                if is_symlink:
                    icon = "🔗"
                elif is_dir:
                    icon = "📁"
                else:
                    # Icon based on file type
                    suffix = entry.suffix.lower()
                    if suffix in (".html", ".htm"):
                        icon = "🌐"
                    elif suffix in (".md", ".txt"):
                        icon = "📄"
                    elif suffix in (".json", ".xml", ".yaml", ".yml"):
                        icon = "📋"
                    elif suffix in (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp"):
                        icon = "🖼️"
                    elif suffix in (".pdf"):
                        icon = "📕"
                    elif suffix in (".zip", ".tar", ".gz", ".bz2"):
                        icon = "📦"
                    else:
                        icon = "📄"

                entries.append({
                    "name": entry.name,
                    "url": entry_url,
                    "is_dir": is_dir,
                    "is_symlink": is_symlink,
                    "size": size,
                    "icon": icon,
                })

            # Generate HTML
            rows = []
            for entry in entries:
                name_display = entry["name"]
                if entry["is_symlink"]:
                    name_display += " →"
                if entry["is_dir"] and entry["name"] != "..":
                    name_display += "/"

                rows.append(
                    f"<tr>"
                    f"<td><span class='icon'>{entry['icon']}</span>"
                    f"<a href='{_h(entry['url'])}'>{_h(name_display)}</a></td>"
                    f"<td class='right'>{_h(entry['size'])}</td>"
                    f"</tr>"
                )

            # Show setup guide if root directory is empty
            is_root = url_path == "/"
            is_empty = len([e for e in entries if e.get("name") != ".."]) == 0

            if is_root and is_empty:
                body = self._get_empty_root_guide(dir_path)
            else:
                body = f"""
                <h1>Index of {_h(url_path)}</h1>
                <p class="muted">{_h(str(dir_path))}</p>
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th class="right">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {''.join(rows) if rows else '<tr><td colspan="2" class="muted">(empty)</td></tr>'}
                  </tbody>
                </table>
                """

            self._send_html(HTTPStatus.OK, _page(f"Index of {url_path}", body))

        except OSError as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading directory: {e}")

    def _serve_file(self, file_path: Path):
        """Serve a file with appropriate content type."""
        try:
            # Guess content type
            content_type, _ = mimetypes.guess_type(str(file_path))
            if content_type is None:
                content_type = "application/octet-stream"

            # Read file
            data = file_path.read_bytes()

            # Send response
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        except OSError as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Error reading file: {e}")

    def _execute_python(self, script_path: Path, url_path: str):
        """Execute a Python script (CGI-style) and return its output.

        Security: only executes files that are (a) executable and (b) resolve
        to a path within the workspace or /tmp.
        """
        import subprocess
        import sys

        actual_script = script_path.resolve()

        # Must be executable
        if not os.access(actual_script, os.X_OK):
            self.send_error(HTTPStatus.FORBIDDEN, "Script is not executable")
            return

        # Path was already validated by _safe_resolve (symlinks must originate
        # within workspace). Double-check the resolved path is a file.
        if not actual_script.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Script not found")
            return

        parsed = urllib.parse.urlparse(self.path)

        # Build CGI environment (inherits process env)
        env = os.environ.copy()
        env.update({
            "REQUEST_METHOD": "GET",
            "SCRIPT_NAME": url_path,
            "PATH_INFO": url_path,
            "QUERY_STRING": parsed.query or "",
            "SERVER_NAME": self.server.server_address[0],
            "SERVER_PORT": str(self.server.server_address[1]),
            "SERVER_PROTOCOL": self.request_version,
            "HTTP_HOST": self.headers.get("Host", ""),
            "HTTP_ACCEPT": self.headers.get("Accept", ""),
            "HTTP_USER_AGENT": self.headers.get("User-Agent", ""),
            "DOCUMENT_ROOT": str(self.server.root_dir),
        })

        try:
            result = subprocess.run(
                [sys.executable, str(actual_script)],
                capture_output=True,
                timeout=30,
                env=env,
                cwd=str(script_path.parent.resolve()),
            )

            output = result.stdout

            # Parse CGI headers from output
            if b"\r\n\r\n" in output:
                header_data, body = output.split(b"\r\n\r\n", 1)
            elif b"\n\n" in output:
                header_data, body = output.split(b"\n\n", 1)
            else:
                # No headers, treat entire output as body
                header_data = b""
                body = output

            # Parse headers
            status_code = HTTPStatus.OK
            content_type = "text/html; charset=utf-8"
            extra_headers = []

            if header_data:
                for line in header_data.decode("utf-8", errors="replace").split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    if line.lower().startswith("status:"):
                        try:
                            status_code = int(line.split(":", 1)[1].strip().split()[0])
                        except (ValueError, IndexError):
                            pass
                    elif line.lower().startswith("content-type:"):
                        content_type = line.split(":", 1)[1].strip()
                    elif ":" in line:
                        key, val = line.split(":", 1)
                        extra_headers.append((key.strip(), val.strip()))

            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            for key, val in extra_headers:
                if key.lower() not in ("status", "content-type", "content-length"):
                    self.send_header(key, val)
            self.end_headers()
            self.wfile.write(body)

        except subprocess.TimeoutExpired:
            self._send_error(HTTPStatus.GATEWAY_TIMEOUT, "Script timed out")
        except Exception as e:
            self._send_error(HTTPStatus.INTERNAL_SERVER_ERROR, f"Script error: {e}")

    def _send_html(self, status: int, html_text: str):
        """Send an HTML response."""
        data = html_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_error(self, status: int, message: str):
        """Send an error page."""
        if status == HTTPStatus.NOT_FOUND:
            body = self._get_404_guide()
        else:
            body = f"<h1>{status} {message}</h1>"
        self._send_html(status, _page(f"{status} {message}", body))

    def _get_empty_root_guide(self, root_dir: Path) -> str:
        """Generate a welcome page when root directory is empty."""
        return f"""
        <h1>Welcome to Intranet</h1>
        <p class="muted">Your local file server is running, but there's no content yet.</p>

        <h2>Quick Start</h2>
        <p>Your root folder is: <code>{_h(str(root_dir))}</code></p>

        <h3>Option 1: Create a Homepage</h3>
        <p>Create <code>index.html</code> in your root folder:</p>
        <pre><code>&lt;!doctype html&gt;
&lt;html&gt;
&lt;head&gt;&lt;title&gt;My Intranet&lt;/title&gt;&lt;/head&gt;
&lt;body&gt;
  &lt;h1&gt;Welcome&lt;/h1&gt;
  &lt;ul&gt;
    &lt;li&gt;&lt;a href="/projects/"&gt;Projects&lt;/a&gt;&lt;/li&gt;
    &lt;li&gt;&lt;a href="/notes/"&gt;Notes&lt;/a&gt;&lt;/li&gt;
  &lt;/ul&gt;
&lt;/body&gt;
&lt;/html&gt;</code></pre>

        <h3>Option 2: Just Add Files</h3>
        <p>Drop any files into the root folder and they'll be listed here automatically:</p>
        <ul>
          <li>HTML pages, images, PDFs, text files</li>
          <li>JSON/CSV data files</li>
          <li>Any other static content</li>
        </ul>

        <h3>Option 3: Link Existing Folders</h3>
        <p>Use symlinks to serve content from elsewhere:</p>
        <pre><code>ln -s ~/Documents/myproject {_h(str(root_dir))}/myproject</code></pre>

        <h3>Dynamic Pages</h3>
        <p>Create HTML with JavaScript to build interactive dashboards, fetch APIs, or process local JSON files.</p>

        <p style="margin-top: 24px; padding: 12px; background: #f0f7ff; border-radius: 4px;">
          <strong>Tip:</strong> Refresh this page after adding content.
        </p>
        """

    def _get_404_guide(self) -> str:
        """Generate a helpful 404 page with setup instructions."""
        root_dir = self.server.root_dir
        return f"""
        <h1>404 — Not Found</h1>
        <p>The requested page doesn't exist yet.</p>

        <h2>Getting Started</h2>
        <p>Your intranet root folder is: <code>{_h(str(root_dir))}</code></p>

        <h3>Create a Homepage</h3>
        <p>Add an <code>index.html</code> file to your root folder:</p>
        <pre><code>{_h(str(root_dir))}/index.html</code></pre>

        <h3>Add Subfolders</h3>
        <p>Create folders for different sections, each with its own <code>index.html</code>:</p>
        <pre><code>{_h(str(root_dir))}/projects/index.html
{_h(str(root_dir))}/notes/index.html
{_h(str(root_dir))}/docs/index.html</code></pre>

        <h3>Static Files</h3>
        <p>Any file placed in the root folder is served directly:</p>
        <ul>
          <li>HTML files (<code>.html</code>)</li>
          <li>Images (<code>.jpg</code>, <code>.png</code>, <code>.svg</code>, etc.)</li>
          <li>Documents (<code>.pdf</code>, <code>.txt</code>, <code>.md</code>)</li>
          <li>Data files (<code>.json</code>, <code>.csv</code>, <code>.xml</code>)</li>
        </ul>

        <h3>Dynamic Content</h3>
        <p>For dynamic pages, create HTML files with embedded JavaScript that fetches data from APIs or local JSON files.</p>

        <h3>Symlinks</h3>
        <p>Link content from other locations using symlinks:</p>
        <pre><code>ln -s /path/to/existing/folder {_h(str(root_dir))}/linked-folder</code></pre>

        <p style="margin-top: 24px;"><a href="/">← Back to root</a></p>
        """

    def log_message(self, fmt: str, *args):
        """Suppress logging in daemon mode."""
        pass


def run_server(host: str = "0.0.0.0", port: int = 8080, root_dir: Path = None, token: str = None):
    """Start the intranet web server."""
    if root_dir is None:
        root_dir = _find_workspace_root() / "intranet"

    root_dir = Path(root_dir).expanduser().resolve()

    if not root_dir.exists():
        root_dir.mkdir(parents=True, exist_ok=True)

    httpd = ThreadingHTTPServer((host, port), IntranetHandler)
    httpd.root_dir = root_dir
    httpd.auth_token = token
    httpd.session_secret = secrets.token_bytes(32)

    # Load settings from config.json
    import json as _json
    config_file = root_dir / "config.json"
    allowed_hosts = None
    if config_file.exists():
        try:
            cfg = _json.loads(config_file.read_text())
            hosts_list = cfg.get("allowed_hosts", [])
            if hosts_list:
                allowed_hosts = {h.lower() for h in hosts_list}
        except Exception:
            pass
    httpd.allowed_hosts = allowed_hosts

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main() -> int:
    """Main entry point for standalone execution."""
    import argparse

    ap = argparse.ArgumentParser(description="Serve local files over HTTP")
    ap.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    ap.add_argument("--port", type=int, default=8080, help="Port to bind to")
    ap.add_argument("--dir", default=None, help="Root directory to serve")
    ap.add_argument("--token", default=None, help="Bearer token for authentication")
    args = ap.parse_args()

    root_dir = Path(args.dir) if args.dir else (_find_workspace_root() / "intranet")
    token = args.token or os.environ.get("INTRANET_TOKEN")

    print(f"[intranet-web] Serving {root_dir} on http://{args.host}:{args.port}/")
    if token:
        print("[intranet-web] Token authentication enabled")
    run_server(args.host, args.port, root_dir, token=token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
