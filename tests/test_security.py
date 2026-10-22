import json, os, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import helpers
from helpers import fresh_mock, mock_env, req, start_web
from liara_agent import security as sec
from liara_agent import tools as T
from liara_agent.client import LiaraAPIError
from liara_agent.security import ConfirmStore, ValidationError
from liara_agent.tools import build_tools, execute, two_step


def _raises(fn, exc=ValidationError):
    try:
        fn()
    except exc:
        return True
    return False


# ---------- SSRF ----------
def test_ssrf_blocked_urls():
    for u in ["http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data", "http://[::1]/",
              "http://10.0.0.1/", "http://192.168.1.1/", "http://0.0.0.0/", "http://[::ffff:127.0.0.1]/", "http://2130706433/",
              "file:///etc/passwd", "ftp://example.com/", "http://user:pw@example.com/", "https://example.com:8080/", "gopher://x"]:
        assert _raises(lambda: sec.safe_http_check(u)), u


def test_is_public_ip():
    for ip in ("127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.0.5", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "::ffff:10.0.0.1", "224.0.0.1"):
        assert not sec.is_public_ip(ip), ip
    for ip in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        assert sec.is_public_ip(ip), ip


def test_safe_check_works_when_private_explicitly_allowed():
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            self.send_response(302); self.send_header("Location", "http://169.254.169.254/"); self.send_header("Content-Length", "0"); self.end_headers()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = sec.safe_http_check(f"http://127.0.0.1:{srv.server_address[1]}/", allow_private=True)
    assert r["status_code"] == 302 and r["ok"]       # ریدایرکت دنبال نمی‌شود
    srv.shutdown()


def test_health_tool_rejects_internal_target():
    tools, _ = fresh_mock()
    r = execute(tools, "health_check", {"url": "http://169.254.169.254/"})
    assert r["status"] == "invalid_input"


# ---------- اعتبارسنجی ورودی ----------
def test_input_validators():
    assert _raises(lambda: sec.validate_app_name("../x")) and _raises(lambda: sec.validate_plan("a b"))
    assert _raises(lambda: sec.validate_env("1BAD", "v")) and _raises(lambda: sec.validate_env("OK", "x" * 5000))
    assert _raises(lambda: sec.validate_port(0)) and _raises(lambda: sec.validate_port(True)) and _raises(lambda: sec.validate_port("80"))
    assert _raises(lambda: sec.validate_platform("node; rm -rf /"))
    for u in ("http://github.com/a/b", "https://evil.com/a/b", "https://github.com/a/b;rm -rf", "https://github.com/../b", "https://github.com/a", "https://github.com.evil.com/a/b"):
        assert _raises(lambda: sec.validate_github_url(u)), u
    assert sec.validate_github_url("https://github.com/acme/shop.git")
    assert _raises(lambda: sec.validate_domain("a b.ir")) and sec.validate_domain("My-Shop.ir") == "my-shop.ir"


def test_tools_reject_bad_input_without_calling_api():
    tools, _ = fresh_mock()
    assert execute(tools, "resize_app", {"name": "my-shop", "plan": "a b"}, confirmed=True)["status"] == "invalid_input"
    assert execute(tools, "set_env_var", {"name": "my-shop", "key": "9X", "value": "v"}, confirmed=True)["status"] == "invalid_input"
    assert execute(tools, "app_status", {"name": "../x"})["status"] == "invalid_input"
    assert execute(tools, "analyze_repo", {"repo_url": "https://evil.com/a/b"})["status"] == "invalid_input"
    assert execute(tools, "domain_guide", {"domain": "x y"})["status"] == "invalid_input"
    assert execute(tools, "app_status", {"name": "my-shop", "extra": 1})["status"] == "invalid_input"
    assert execute(tools, "nope", {})["status"] == "error"


def test_detect_project_path_traversal_blocked():
    tools, _ = fresh_mock()
    for p in ("/etc", "../..", "/", "../../etc"):
        assert execute(tools, "detect_project", {"path": p})["status"] == "invalid_input", p
    assert execute(tools, "detect_project", {"path": "."})["status"] in ("ok", "error")
    assert execute(tools, "deploy_app", {"name": "my-shop", "platform": "node", "path": "/etc"}, confirmed=True)["status"] == "invalid_input"


# ---------- تأیید عملیات حساس ----------
def test_high_risk_never_runs_without_confirmation():
    class C:
        token = "t"; calls = []
        def restart(self, n): self.calls.append("restart")
        def resize(self, n, p): self.calls.append("resize")
        def set_envs(self, n, e): self.calls.append("env")
    c = C(); tools = build_tools(c)
    for name, args in [("restart_app", {"name": "a"}), ("resize_app", {"name": "a", "plan": "p"}), ("set_env_var", {"name": "a", "key": "K", "value": "v"}),
                       ("deploy_app", {"name": "a", "platform": "node"}), ("deploy_repo", {"name": "a", "repo_url": "https://github.com/a/b", "platform": "node"})]:
        assert execute(tools, name, args)["status"] == "needs_confirmation", name
    assert c.calls == []


def test_confirm_store_single_use_and_expiry():
    s = ConfirmStore(ttl=300); i = s.create("restart_app", {"name": "a"})
    assert s.consume(i) == ("restart_app", {"name": "a"}) and s.consume(i) is None
    assert ConfirmStore(ttl=-1).consume(ConfirmStore(ttl=-1).create("x", {})) is None
    s2 = ConfirmStore(ttl=-1); assert s2.consume(s2.create("x", {})) is None
    assert s.consume("guess") is None


def test_mcp_two_step_binds_token_to_params():
    tools, _ = fresh_mock(); store = ConfirmStore()
    r = two_step(tools, store, "resize_app", {"name": "my-shop", "plan": "medium"})
    tok = r["confirmation_token"]
    assert r["status"] == "needs_confirmation"
    assert two_step(tools, store, "resize_app", {"name": "my-shop", "plan": "large"}, tok)["status"] == "error"   # پارامتر تغییر کرده
    assert two_step(tools, store, "resize_app", {"name": "my-shop", "plan": "medium"}, tok)["status"] == "error"  # توکن قبلاً مصرف شد
    tok2 = two_step(tools, store, "resize_app", {"name": "my-shop", "plan": "medium"})["confirmation_token"]
    assert two_step(tools, store, "resize_app", {"name": "my-shop", "plan": "medium"}, tok2)["status"] == "ok"
    assert two_step(tools, store, "restart_app", {"name": "my-shop"}, tok2)["status"] == "error"


# ---------- وب‌سرور ----------
def test_web_guards():
    srv = start_web()
    from liara_agent import server
    assert req(srv, "GET", "/api/apps", session=False)[0] == 403
    assert req(srv, "GET", "/api/apps", headers={"X-Session": "wrong"}, session=False)[0] == 403
    assert req(srv, "GET", "/api/apps", headers={"Host": "evil.com"})[0] == 403
    assert req(srv, "GET", "/", headers={"Host": "evil.com"}, session=False)[0] == 403
    assert req(srv, "POST", "/api/chat", {"message": "x"}, headers={"Origin": "http://evil.com"})[0] == 403
    assert req(srv, "POST", "/api/chat", {"message": "x"}, headers={"Content-Type": "text/plain"})[0] == 415
    assert req(srv, "POST", "/api/chat", raw_body=b"{not json")[0] == 400
    assert req(srv, "POST", "/api/chat", raw_body=b"[1,2]")[0] == 400
    assert req(srv, "POST", "/api/chat", {"message": "x"}, headers={"Content-Length": "999999"}, raw_body=b"")[0] == 413
    assert req(srv, "GET", "/api/apps")[0] == 200
    s, h, _, body = req(srv, "GET", "/", session=False)
    assert s == 200 and "frame-ancestors 'none'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "DENY"
    assert server.SESSION.encode() in body and b"__NONCE__" not in body and b"__SESSION__" not in body
    nonce = h["Content-Security-Policy"].split("nonce-")[1].split("'")[0]
    assert f'nonce="{nonce}"'.encode() in body
    srv.shutdown()


def test_web_confirmation_flow_is_enforced_server_side():
    srv = start_web()
    _, _, j, _ = req(srv, "POST", "/api/chat", {"message": "سایتم ارور ۵۰۰ میده", "app": "my-shop"})
    card = next(e for e in j["events"] if e["type"] == "confirm")
    assert req(srv, "GET", "/api/status?name=my-shop")[2]["planID"] == "small"          # قبل از تأیید تغییری نیست
    # approve غیر از true دقیق = رد؛ و توکن مصرف می‌شود
    _, _, j2, _ = req(srv, "POST", "/api/confirm", {"id": card["id"], "approve": "true"})
    assert "لغو" in json.dumps(j2, ensure_ascii=False)
    assert req(srv, "GET", "/api/status?name=my-shop")[2]["planID"] == "small"
    assert req(srv, "POST", "/api/confirm", {"id": card["id"], "approve": True})[2]["events"][0]["type"] == "error"   # استفاده‌ی دوباره
    assert req(srv, "POST", "/api/confirm", {"id": "guessed-id", "approve": True})[2]["events"][0]["type"] == "error"
    assert req(srv, "POST", "/api/confirm", {"id": ["x"], "approve": True})[2]["events"][0]["type"] == "error"
    # تأیید صریح
    _, _, j, _ = req(srv, "POST", "/api/chat", {"message": "ارور ۵۰۰", "app": "my-shop"})
    card = next(e for e in j["events"] if e["type"] == "confirm")
    req(srv, "POST", "/api/confirm", {"id": card["id"], "approve": True})
    assert req(srv, "GET", "/api/status?name=my-shop")[2]["planID"] == "medium"
    srv.shutdown()


def test_web_chat_rate_limit():
    srv = start_web()
    from liara_agent import server
    codes = [req(srv, "POST", "/api/chat", {"message": "سلام", "app": "my-shop"})[0] for _ in range(32)]
    assert codes.count(200) == 30 and codes[-1] == 429
    server.S["chat_times"].clear(); srv.shutdown()


def test_ui_has_no_unsafe_dom_sinks():
    html = open(os.path.join(os.path.dirname(__file__), "..", "liara_agent", "web", "index.html"), encoding="utf-8").read()
    assert html.count("innerHTML") == 1 and "eval(" not in html and "document.write" not in html and "http://" not in html.replace("http://127", "")


# ---------- توکن ----------
def test_token_never_in_argv_and_redacted():
    T.POLL_INTERVAL = 0
    class C:
        token = "SECRET-TOKEN-123456"
        def get_project(self, n): return {"status": "RUNNING", "isDeployed": True, "defaultSubdomain": False}
    seen = {}
    class R: returncode = 1; stdout = ""; stderr = "auth failed for SECRET-TOKEN-123456 and Bearer abcdefghijk"
    def fake_run(cmd, **kw): seen["cmd"], seen["env"] = cmd, kw.get("env"); return R()
    mock_env(False)
    old_run, old_which = T.subprocess.run, T.shutil.which
    T.subprocess.run, T.shutil.which = fake_run, lambda x: "/usr/bin/liara"
    try:
        tools = build_tools(C())
        r = execute(tools, "deploy_app", {"name": "my-shop", "platform": "node", "port": 3000}, confirmed=True)
    finally:
        T.subprocess.run, T.shutil.which = old_run, old_which; mock_env(True)
    assert "SECRET-TOKEN-123456" not in " ".join(seen["cmd"]) and "--api-token" not in seen["cmd"]
    assert seen["env"]["LIARA_API_TOKEN"] == "SECRET-TOKEN-123456"
    blob = json.dumps(r, ensure_ascii=False)
    assert "SECRET-TOKEN-123456" not in blob and "abcdefghijk" not in blob


def test_env_var_values_are_never_returned():
    tools, _ = fresh_mock()
    execute(tools, "set_env_var", {"name": "my-shop", "key": "PLAIN_NAME", "value": "visible?"}, confirmed=True)
    r = execute(tools, "get_env_vars", {"name": "my-shop"})["result"]
    assert set(r.values()) == {"***"} and "PLAIN_NAME" in r


def test_audit_masks_secret_values():
    from liara_agent import audit, brain
    tools, st = fresh_mock()
    cid = st["confirm"].create("set_env_var", {"name": "my-shop", "key": "K", "value": "TOPSECRET"})
    brain.apply_confirmed(tools, st, cid, True)
    assert "TOPSECRET" not in json.dumps(audit.entries(), ensure_ascii=False)
