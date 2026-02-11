import http.server
import socketserver
import json
import subprocess
import time
import threading
import sys
import os
from pathlib import Path


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


# Configuration
PORT = 8081
WORKSPACE_ROOT = str(_find_workspace_root())
BANKER_SCRIPT = os.path.join(WORKSPACE_ROOT, "skills/banker/scripts/banker.py")
QUOTES_SCRIPT = os.path.join(WORKSPACE_ROOT, "skills/market-quotes/scripts/quotes.py")

ACCOUNTS = [
    {"bank": "oliver@revolut", "account": "revolut_gia", "owner": "Oliver"},
    {"bank": "sylvia@revolut", "account": "sylvia@revolut:invest", "owner": "Sylvia"},
]

CACHE = {
    "data": [],
    "last_update": 0,
    "status": "initializing"
}

def run_cmd(cmd_list):
    try:
        # Run with cwd at workspace root
        res = subprocess.run(cmd_list, capture_output=True, text=True, cwd=WORKSPACE_ROOT)
        if res.returncode != 0:
            print(f"Error running {' '.join(cmd_list)}: {res.stderr}")
            return None
        return json.loads(res.stdout)
    except Exception as e:
        print(f"Exception running {' '.join(cmd_list)}: {e}")
        return None

def fetch_data():
    while True:
        try:
            print("Fetching portfolio data...")
            holdings = []
            symbols_to_quote = set()

            for acc in ACCOUNTS:
                # banker portfolio-latest --bank X --account Y
                data = run_cmd(["python3", BANKER_SCRIPT, "portfolio-latest", "--bank", acc["bank"], "--account", acc["account"]])
                
                if not data:
                    continue

                for pos in data.get("positions", []):
                    # Revolut specific: isin field contains symbol or ISIN.
                    # Heuristic: if len < 9, it's a symbol. Else it's an ISIN.
                    raw_id = pos.get("isin", "")
                    symbol = raw_id
                    
                    # Store for quote fetching
                    if symbol:
                        symbols_to_quote.add(symbol)
                    
                    item = {
                        "owner": acc["owner"],
                        "name": pos.get("name"),
                        "symbol": symbol,
                        "qty": float(pos.get("quantity", 0)),
                        "cost_basis": float(pos.get("averagePrice", {}).get("amount", 0) or 0),
                        "currency": pos.get("price", {}).get("currency", "USD"), # Default to USD for Revolut
                    }
                    holdings.append(item)

            print(f"Fetching quotes for: {symbols_to_quote}")
            
            # Fetch quotes in batch
            if symbols_to_quote:
                # quotes.py price SYM1 SYM2 ... --json
                cmd = ["python3", QUOTES_SCRIPT, "price"] + list(symbols_to_quote) + ["--json"]
                quotes_res = run_cmd(cmd)
                
                if quotes_res and "results" in quotes_res:
                    # Map symbol -> quote data
                    quote_map = {}
                    for r in quotes_res["results"]:
                        if r.get("ok"):
                            # Handle both input match and symbol match
                            quote_map[r.get("symbol")] = r
                            quote_map[r.get("input")] = r 
                    
                    # Enrich holdings
                    for h in holdings:
                        sym = h["symbol"]
                        q = quote_map.get(sym)
                        if q:
                            h["price"] = q.get("price")
                            h["change_pct"] = q.get("changePercent")
                            # Recalculate market value based on live price
                            h["market_value"] = h["price"] * h["qty"]
                            if h["cost_basis"] > 0:
                                h["gain_loss"] = h["market_value"] - (h["cost_basis"] * h["qty"])
                                h["gain_loss_pct"] = (h["gain_loss"] / (h["cost_basis"] * h["qty"])) * 100
                            else:
                                h["gain_loss"] = 0
                                h["gain_loss_pct"] = 0

            CACHE["data"] = holdings
            CACHE["last_update"] = time.time()
            CACHE["status"] = "ok"
            print("Data update complete.")
            
        except Exception as e:
            print(f"Global fetch error: {e}")
            CACHE["status"] = f"error: {e}"
        
        time.sleep(10)

class APIHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/investments':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*') 
            self.end_headers()
            self.wfile.write(json.dumps(CACHE).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        return # Silence logs

def run_server():
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), APIHandler) as httpd:
        print(f"Investment Backend serving at port {PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    t = threading.Thread(target=fetch_data, daemon=True)
    t.start()
    run_server()
