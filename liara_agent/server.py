"""وب‌سرور محلی (stdlib). فقط 127.0.0.1؛ توکن نشست، بررسی Host/Origin، CSP، محدودیت اندازه و نرخ."""
import base64, hmac, json, os, secrets, threading, time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from . import audit, brain, insights
from .client import make_client
from .tools import build_tools, execute

WEB = Path(__file__).parent / "web"
SESSION = secrets.token_urlsafe(24)
MAX_BODY, LOCK = 65536, threading.RLock()
S = {"tools": None, "st": brain.new_state(), "port": 8080, "chat_times": deque()}


def status(name, url=""):
    t = S["tools"]
    a = execute(t, "app_status", {"name": name})
    if a["status"] != "ok":
        return {"error": brain._err(a)}
    m = execute(t, "get_metrics", {"name": name})
    metrics = m["result"] if m["status"] == "ok" else {"cpu": None, "memory": None, "disk": None}
    out = {**a["result"], "metrics": metrics, "metrics_available": m["status"] == "ok",
           "metrics_note": "" if m["status"] == "ok" else brain._err(m)[:160],
           "simulated": os.getenv("LIARA_MOCK") == "1", "ts": time.strftime("%H:%M:%S")}
    if url:
        h = execute(t, "health_check", {"url": url})
        out["health"] = h["result"] if h["status"] == "ok" else {"ok": False, "error": h.get("message", "")}
    out["score"], out["score_reasons"] = insights.health_score(out, metrics, out.get("health"))
    out["alerts"] = insights.alerts(out, metrics, out.get("health"))
    out["history"] = insights.record(name, metrics)
    return out


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _hdrs(self, ctype, nonce=""):
        csp = ("default-src 'none'; connect-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; "
               f"script-src 'nonce-{nonce}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def _send(self, obj, code=200, ctype="application/json", nonce=""):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self._hdrs(ctype, nonce)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def _guard(self, api, post):
        """اعتبارسنجی درخواست؛ حالت عمومی فقط با احراز هویت فعال می‌شود."""
        public = os.getenv("LIARA_PUBLIC", "").lower() in ("1", "true", "yes") or bool(os.getenv("PORT"))
        host = self.headers.get("Host", "")
        if not host or any(ch in host for ch in "\r\n /\\"):
            self._send({"error": "invalid host"}, 400); return False
        if not public:
            p = S["port"]
            if host not in (f"127.0.0.1:{p}", f"localhost:{p}"):
                self._send({"error": "host not allowed"}, 403); return False
        else:
            username, password = os.getenv("LIARA_WEB_USERNAME", ""), os.getenv("LIARA_WEB_PASSWORD", "")
            if not username or not password:
                self._send({"error": "public mode requires LIARA_WEB_USERNAME and LIARA_WEB_PASSWORD"}, 503); return False
            auth = self.headers.get("Authorization", "")
            valid = False
            if auth.startswith("Basic "):
                try:
                    raw = base64.b64decode(auth[6:], validate=True).decode("utf-8")
                    supplied_user, supplied_password = raw.split(":", 1)
                    valid = hmac.compare_digest(supplied_user, username) and hmac.compare_digest(supplied_password, password)
                except (ValueError, UnicodeDecodeError):
                    valid = False
            if not valid:
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="Liara SRE Agent", charset="UTF-8"')
                self._hdrs("application/json")
                body = b'{"error":"authentication required"}'
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                return False
        if api:
            if not hmac.compare_digest(self.headers.get("X-Session", ""), SESSION):
                self._send({"error": "invalid session"}, 403); return False
            origin = self.headers.get("Origin")
            if origin:
                parsed = urlparse(origin)
                if public:
                    if parsed.scheme not in ("http", "https") or parsed.netloc != host:
                        self._send({"error": "origin not allowed"}, 403); return False
                elif origin not in (f"http://127.0.0.1:{S['port']}", f"http://localhost:{S['port']}"):
                    self._send({"error": "origin not allowed"}, 403); return False
        if post and not self.headers.get("Content-Type", "").startswith("application/json"):
            self._send({"error": "content-type must be application/json"}, 415); return False
        return True

    def do_GET(self):
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        if not self._guard(u.path.startswith("/api/"), False):
            return
        if u.path == "/":
            nonce = secrets.token_urlsafe(16)
            html = (WEB / "index.html").read_text(encoding="utf-8").replace("__NONCE__", nonce).replace("__SESSION__", SESSION)
            return self._send(html.encode(), ctype="text/html", nonce=nonce)
        with LOCK:
            if u.path == "/api/apps":
                r = execute(S["tools"], "list_apps", {})
                if r["status"] != "ok":
                    return self._send({"error": brain._err(r)})
                return self._send({"mock": os.getenv("LIARA_MOCK") == "1", "llm": bool(os.getenv("ANTHROPIC_API_KEY")),
                                   "apps": [{"name": p.get("project_id"), "status": p.get("status")} for p in r["result"]]})
            if u.path == "/api/audit":
                return self._send({"entries": audit.entries()})
            if u.path == "/api/status":
                return self._send(status(q.get("name", ""), q.get("url", "")))
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        if not self._guard(True, True):
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self._send({"error": "bad length"}, 400)
        if n > MAX_BODY:
            return self._send({"error": "payload too large"}, 413)
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
            assert isinstance(d, dict)
        except (ValueError, AssertionError):
            return self._send({"error": "invalid json"}, 400)
        t, st = S["tools"], S["st"]
        try:
            with LOCK:
                if self.path == "/api/chat":
                    now, q = time.time(), S["chat_times"]
                    while q and q[0] < now - 60:
                        q.popleft()
                    if len(q) >= 30:
                        return self._send({"error": "rate limited"}, 429)
                    q.append(now)
                    return self._send({"events": brain.handle(str(d.get("message", "")), str(d.get("app", "")), t, st, str(d.get("url", "")))})
                if self.path == "/api/confirm":
                    return self._send({"events": brain.apply_confirmed(t, st, d.get("id"), d.get("approve"))})
        except Exception:
            return self._send({"events": [{"type": "error", "text": "خطای داخلی سرور (جزئیات در لاگ سرور)"}]}, 500)
        self._send({"error": "not found"}, 404)


def run(port=None):
    public = os.getenv("LIARA_PUBLIC", "").lower() in ("1", "true", "yes") or bool(os.getenv("PORT"))
    port = int(os.getenv("PORT") or os.getenv("LIARA_PORT") or port or 8080)
    host = "0.0.0.0" if public else "127.0.0.1"
    if public and (not os.getenv("LIARA_WEB_USERNAME") or not os.getenv("LIARA_WEB_PASSWORD")):
        raise RuntimeError("برای اجرای عمومی، متغیرهای LIARA_WEB_USERNAME و LIARA_WEB_PASSWORD را در تنظیمات محیطی لیارا تنظیم کنید.")
    S["tools"], S["port"] = build_tools(make_client()), port
    audit.load()
    print(f"🚀 Liara SRE Agent listening on {host}:{port}")
    ThreadingHTTPServer((host, port), H).serve_forever()
