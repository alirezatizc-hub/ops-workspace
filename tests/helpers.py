import http.client, json, os, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ["LIARA_AUDIT_FILE"] = "/tmp/liara_test_audit.jsonl"
os.environ["LIARA_NO_LLM"] = "1"
os.environ.pop("LIARA_ALLOW_UNVERIFIED", None)


def mock_env(on=True):
    if on:
        os.environ["LIARA_MOCK"] = "1"
    else:
        os.environ.pop("LIARA_MOCK", None)


def fresh_mock():
    from liara_agent import brain, insights
    from liara_agent.client import make_client
    from liara_agent.tools import build_tools
    mock_env(True); insights.HIST.clear()
    return build_tools(make_client()), brain.new_state()


def start_web():
    from liara_agent import brain, insights, server
    from liara_agent.client import make_client
    from liara_agent.tools import build_tools
    mock_env(True); insights.HIST.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), server.H)
    server.S.update(tools=build_tools(make_client()), st=brain.new_state(), port=srv.server_address[1])
    server.S["chat_times"].clear()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def req(srv, method, path, body=None, headers=None, session=True, raw_body=None):
    c = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    from liara_agent import server
    h = {"Content-Type": "application/json"}
    if session:
        h["X-Session"] = server.SESSION
    h.update(headers or {})
    data = raw_body if raw_body is not None else (json.dumps(body).encode() if body is not None else None)
    c.request(method, path, body=data, headers=h)
    r = c.getresponse(); b = r.read()
    try:
        j = json.loads(b)
    except ValueError:
        j = None
    return r.status, dict(r.getheaders()), j, b


class FakeLiara:
    """سرور جعلی که فقط قرارداد «مستندات رسمی» را شبیه‌سازی می‌کند (نه رفتار واقعی لیارا)."""
    def __init__(self, leak_token_in_401=False):
        self.calls, self.leak = [], leak_token_in_401
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _do(self):
                n = int(self.headers.get("Content-Length", 0) or 0)
                body = json.loads(self.rfile.read(n)) if n else None
                outer.calls.append({"m": self.command, "path": self.path, "auth": self.headers.get("Authorization"), "body": body})
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    return self._j(401, {"message": "Missing authentication"})
                if auth == "Bearer BADTOKEN12345":
                    return self._j(401, {"message": "bad " + auth if outer.leak else "bad"})
                p = self.path.split("?")[0]
                if self.command == "GET" and p == "/v1/projects":
                    return self._j(200, {"projects": [{"project_id": "my-shop", "status": "RUNNING"}]})
                if self.command == "GET" and p == "/v1/projects/my-shop":
                    return self._j(200, {"project": {"project_id": "my-shop", "status": "RUNNING", "planID": "p1", "scale": 1, "isDeployed": True, "envs": []}})
                if self.command == "GET" and p == "/v1/projects/my-shop/logs":
                    if "since=" not in self.path:
                        return self._j(400, {"message": "since required"})
                    return self._j(200, {"logs": [{"message": "hello"}]})
                if self.command == "GET" and p == "/v1/projects/my-shop/metrics/summary":
                    return self._j(200, {"cpuUsage": [{"applet": "a", "value": [1700000000, "0.2"]}],
                                         "memoryUsage": [{"applet": "a", "value": [1700000000, "1000"]}],
                                         "disksUsage": [{"name": "d", "size": "100", "usage": "50", "reportedAt": "x"}]})
                if self.command == "POST" and p in ("/v1/projects/my-shop/actions/restart", "/v1/projects/my-shop/resize"):
                    return self._j(200, {})
                self._j(404, {"message": "not found"})

            do_GET = do_POST = _do

            def _j(self, code, obj):
                b = json.dumps(obj).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def stop(self): self.srv.shutdown()
