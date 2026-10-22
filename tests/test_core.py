"""تست‌های منطق با MockClient (شبیه‌سازی؛ این‌ها هیچ ارتباطی با لیارای واقعی را ثابت نمی‌کنند)."""
import json
import helpers
from helpers import fresh_mock, mock_env, req, start_web
from liara_agent import brain, insights, tools as T
from liara_agent.client import LiaraAPIError
from liara_agent.tools import build_tools, execute


def test_diagnose_finds_oom_and_proposes_resize():
    tools, _ = fresh_mock()
    rep = execute(tools, "diagnose_app", {"name": "my-shop"})["result"]
    top = rep["findings"][0]
    assert "حافظه" in top["cause"] and top["confidence"] >= 0.9
    assert top["fix_tool"] == "resize_app" and top["fix_args"]["plan"] == "medium"
    assert rep["sources"] == {"status": "ok", "metrics": "ok", "logs": "ok"}


def test_fix_requires_confirmation_then_verifies():
    tools, _ = fresh_mock()
    assert execute(tools, "resize_app", {"name": "my-shop", "plan": "medium"})["status"] == "needs_confirmation"
    assert execute(tools, "app_status", {"name": "my-shop"})["result"]["planID"] == "small"
    assert execute(tools, "resize_app", {"name": "my-shop", "plan": "medium"}, confirmed=True)["status"] == "ok"
    assert execute(tools, "diagnose_app", {"name": "my-shop"})["result"]["findings"] == []


def test_api_errors_are_reported_not_raised():
    tools, _ = fresh_mock()
    assert execute(tools, "app_status", {"name": "nope"})["status"] == "unsupported"


def test_diagnose_with_unavailable_metrics_does_not_fabricate():
    """اگر متریک در دسترس نباشد: هیچ عدد ساختگی، منبع «unavailable»، و پیشنهاد ثابتِ resize حذف می‌شود."""
    class C:
        token = "t"
        def get_project(self, n): return {"project_id": n, "status": "RUNNING", "planID": "p1", "scale": 1, "isDeployed": True}
        def metrics(self, n, p="1h"): raise LiaraAPIError(501, "مسیر «metrics» تأیید نشده")
        def logs(self, n, since=None): return {"logs": [{"message": "FATAL ERROR: JavaScript heap out of memory"}]}
        def plans(self): raise LiaraAPIError(501, "plans تأیید نشده")
    mock_env(False)
    try:
        rep = execute(build_tools(C()), "diagnose_app", {"name": "my-shop"})["result"]
    finally:
        mock_env(True)
    assert rep["metrics"] == {"cpu": None, "memory": None, "disk": None}
    assert rep["sources"]["metrics"].startswith("unavailable") and rep["sources"]["logs"] == "ok"
    f = rep["findings"][0]
    assert "حافظه" in f["cause"] and f["fix_tool"] == "" and "پنل لیارا" in f["suggestion"]
    assert f["confidence"] < 0.9            # اطمینان بالا فقط وقتی لاگ + متریک هر دو تأیید کنند


def test_no_metric_samples_recorded_when_unavailable():
    insights.HIST.clear(); mock_env(False)
    try:
        assert insights.record("x", {"cpu": None, "memory": None, "disk": None}) == []
    finally:
        mock_env(True)


def test_health_score_uses_only_real_fields():
    s, why = insights.health_score({"status": "RUNNING", "scale": 1, "isDeployed": True}, {"cpu": None, "memory": None, "disk": None}, None)
    assert s == 100 and why == []
    s, why = insights.health_score({"status": "STOPPED", "scale": 0}, {}, {"ok": False})
    assert s <= 0 + 0 or s < 20


def test_deploy_real_stage_results():
    T.POLL_INTERVAL, T.POLL_TRIES = 0, 2
    state = {"proj": {"status": "RUNNING", "isDeployed": True, "defaultSubdomain": True}, "calls": 0}
    class C:
        token = "tok"
        def get_project(self, n): state["calls"] += 1; return state["proj"]
    class R:
        def __init__(self, rc): self.returncode, self.stdout, self.stderr = rc, "", "Cannot find module 'express'" if rc else ""
    rc = {"v": 0}
    old = (T.subprocess.run, T.shutil.which, T.sec.safe_http_check)
    T.subprocess.run = lambda cmd, **kw: R(rc["v"]); T.shutil.which = lambda x: "/bin/liara"
    T.sec.safe_http_check = lambda url, **kw: {"ok": True, "status_code": 200, "latency_ms": 12}
    mock_env(False)
    try:
        tools = build_tools(C())
        a = {"name": "my-shop", "platform": "node"}
        r = execute(tools, "deploy_app", a, True)["result"]                       # موفق
        assert r["ok"] and [s["state"] for s in r["stages"]] == ["ok", "ok", "ok"] and not r.get("simulated")
        state["proj"] = {"status": "STOPPED", "isDeployed": False, "defaultSubdomain": False}   # اپ بالا نیامد
        r = execute(tools, "deploy_app", a, True)["result"]
        assert not r["ok"] and r["stages"][1]["state"] == "warn" and r["stages"][2]["state"] == "skipped"
        state["calls"] = 0; rc["v"] = 1                                           # بیلد ناموفق
        r = execute(tools, "deploy_app", a, True)["result"]
        assert not r["ok"] and len(r["stages"]) == 1 and r["stages"][0]["state"] == "fail" and state["calls"] == 0
        T.sec.safe_http_check = lambda url, **kw: {"ok": False, "status_code": 502, "latency_ms": 5}    # health ناموفق
        rc["v"] = 0; state["proj"] = {"status": "RUNNING", "isDeployed": True, "defaultSubdomain": True}
        r = execute(tools, "deploy_app", a, True)["result"]
        assert not r["ok"] and r["stages"][2]["state"] == "fail"
        T.shutil.which = lambda x: None                                           # CLI نصب نیست
        assert execute(tools, "deploy_app", a, True)["status"] == "unsupported"
    finally:
        T.subprocess.run, T.shutil.which, T.sec.safe_http_check = old; mock_env(True)


def test_mock_deploy_is_labelled_simulated():
    tools, _ = fresh_mock()
    r = execute(tools, "deploy_repo", {"name": "my-shop", "repo_url": "https://github.com/acme/shop", "platform": "node"}, True)["result"]
    assert r["simulated"] and all("شبیه‌سازی" in s["detail"] for s in r["stages"])


def test_web_end_to_end_mock():
    srv = start_web()
    assert req(srv, "GET", "/api/apps")[2]["apps"][0]["name"] == "my-shop"
    st = req(srv, "GET", "/api/status?name=my-shop")[2]
    assert st["metrics"]["memory"] == 97 and st["score"] == 75 and {a["key"] for a in st["alerts"]} == {"mem"} and st["simulated"]
    ev = req(srv, "POST", "/api/chat", {"message": "سایتم ارور ۵۰۰ میده", "app": "my-shop"})[2]["events"]
    card = next(e for e in ev if e["type"] == "confirm")
    after = req(srv, "POST", "/api/confirm", {"id": card["id"], "approve": True})[2]["events"]
    assert any(e.get("celebrate") for e in after)
    st = req(srv, "GET", "/api/status?name=my-shop")[2]
    assert st["metrics"]["memory"] == 54 and st["score"] == 100 and st["alerts"] == []
    g = req(srv, "POST", "/api/chat", {"message": "https://github.com/acme/shop را دیپلوی کن", "app": "my-shop"})[2]["events"]
    c2 = next(e for e in g if e["type"] == "confirm")
    ev2 = req(srv, "POST", "/api/confirm", {"id": c2["id"], "approve": True})[2]["events"]
    prog = next(e for e in ev2 if e["type"] == "progress")
    assert prog["simulated"] and prog["stages"][0]["state"] == "ok"
    bad = req(srv, "POST", "/api/chat", {"message": "https://evil.com/x/y.git را دیپلوی کن", "app": "my-shop"})[2]["events"]
    assert not any(e["type"] == "confirm" for e in bad)
    d = req(srv, "POST", "/api/chat", {"message": "دامنه shop.ir را وصل کن", "app": "my-shop"})[2]["events"]
    assert any(e["type"] == "guide" and "ایرنیک" in " ".join(e["items"]) for e in d)
    au = req(srv, "GET", "/api/audit")[2]["entries"]
    assert au[0]["tool"] == "deploy_repo" and any(a["tool"] == "resize_app" for a in au)
    # URL داخلی در پنل پایش: خطا نه درخواست
    hs = req(srv, "GET", "/api/status?name=my-shop&url=http://169.254.169.254/")[2]
    assert hs["health"]["ok"] is False
    srv.shutdown()
