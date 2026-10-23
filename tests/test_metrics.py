"""تست‌های normalize_metrics با قالب رسمی GET /v1/projects/{name}/metrics/summary (داده‌ی نمونه‌ی ساختگی تست، نه پاسخ واقعی لیارا)."""
import helpers  # noqa: F401
from liara_agent.client import LiaraAPIError
from liara_agent.diagnose import analyze, normalize_metrics, parse_metrics_summary
from liara_agent.tools import build_tools, execute

NONE3 = {"cpu": None, "memory": None, "disk": None}
OFFICIAL = {
    "cpuUsage": [{"applet": "app", "value": [1700000000, "0.25"]}],
    "memoryUsage": [{"applet": "app", "value": [[1700000000, "100"], [1700000060, "300"]]}],
    "disksUsage": [{"name": "data", "size": "100", "usage": "40", "reportedAt": "2026-01-01"}],
}


def test_official_format_parsed_without_inventing_units():
    p = parse_metrics_summary(OFFICIAL)
    assert p["format"] == "official" and p["usable"] and p["issues"] == []
    assert p["cpu"][0]["value"] == 0.25 and p["memory"][0]["value"] == 300 and p["memory"][0]["timestamp"] == 1700000060  # جدیدترین
    assert normalize_metrics(OFFICIAL) == {"cpu": None, "memory": None, "disk": 40.0}   # CPU/RAM بدون واحد مستند ← درصد ساخته نمی‌شود


def test_empty_and_malformed_inputs_are_safe():
    for raw in (None, {}, [], "x", 5, [1, 2], {"metrics": "bad"}, {"unknown": 1}):
        p = parse_metrics_summary(raw)
        assert not p["usable"] and p["issues"], raw
        assert normalize_metrics(raw) == NONE3, raw
    p = parse_metrics_summary({"cpuUsage": [], "memoryUsage": [], "disksUsage": []})
    assert p["format"] == "official" and not p["usable"] and any("برنگشت" in i for i in p["issues"])


def test_invalid_values_are_ignored_not_fabricated():
    raw = {"cpuUsage": [{"applet": "a", "value": ["t", "x"]}, {"value": [1, "NaN"]}, {"value": [1, "inf"]}, {"value": [1, -3]},
                        {"value": [True, 1]}, "junk", {"value": "oops"}, {"value": [1, 2, 3]}],
           "memoryUsage": {"not": "list"},
           "disksUsage": [{"size": "0", "usage": "1"}, {"size": "abc", "usage": "1"}, {"size": "10"}, None]}
    p = parse_metrics_summary(raw)
    assert not p["usable"] and p["cpu"] == [] and p["disks"] == []
    assert normalize_metrics(raw) == NONE3
    assert any("memoryUsage" in i for i in p["issues"]) and any("disksUsage" in i for i in p["issues"])


def test_partial_data_keeps_only_valid_points():
    raw = {"cpuUsage": [{"applet": "a", "value": [[1, "0.1"], [2, "bad"], [3, "0.3"]]}],
           "disksUsage": [{"name": "a", "size": "100", "usage": "95"}, {"name": "b", "size": "x", "usage": "1"}]}
    p = parse_metrics_summary(raw)
    assert p["usable"] and p["cpu"][0]["value"] == 0.3 and len(p["disks"]) == 1
    assert any("نامعتبر" in i for i in p["issues"]) and any("memoryUsage" in i for i in p["issues"])   # کلید غایب گزارش می‌شود
    assert normalize_metrics(raw)["disk"] == 95.0


def test_legacy_percent_format_still_works_and_rejects_bad_values():
    assert normalize_metrics({"metrics": {"cpu": 38, "memory": 97, "disk": 31}}) == {"cpu": 38.0, "memory": 97.0, "disk": 31.0}
    assert normalize_metrics({"cpu_percent": "12.5", "ram": 50}) == {"cpu": 12.5, "memory": 50.0, "disk": None}
    assert normalize_metrics({"cpu": True, "memory": float("nan"), "disk": -1}) == NONE3


def test_high_disk_usage_from_official_format_is_analyzed():
    raw = {"cpuUsage": [], "memoryUsage": [], "disksUsage": [{"name": "d", "size": "100", "usage": "95"}]}
    fs = analyze({"project_id": "x"}, raw, {"logs": []})
    assert fs and "دیسک" in fs[0].cause and "disk = 95" in fs[0].evidence[0]
    assert analyze({"project_id": "x"}, OFFICIAL, {"logs": []}) == []                # مصرف عادی ← یافته‌ی ساختگی نیست


def test_high_memory_in_legacy_percent_is_analyzed_but_official_raw_is_not_guessed():
    fs = analyze({"project_id": "x"}, {"metrics": {"memory": 97}}, {"logs": []})
    assert fs and "حافظه" in fs[0].cause
    huge = {"memoryUsage": [{"value": [1, "99999999999"]}], "cpuUsage": [{"value": [1, "99999"]}]}
    assert analyze({"project_id": "x"}, huge, {"logs": []}) == []                    # واحد نامشخص ← هشدار «مصرف بالا» نمی‌دهد


class _C:
    token = "t"
    def __init__(self, raw): self.raw = raw
    def get_project(self, n): return {"project_id": n, "status": "RUNNING", "planID": "p1", "scale": 1, "isDeployed": True}
    def metrics(self, n, p=None): return self.raw
    def logs(self, n, since=None): return {"logs": []}
    def plans(self): raise LiaraAPIError(501, "plans تأیید نشده")


def _run(raw, tool):
    helpers.mock_env(False)
    try:
        return execute(build_tools(_C(raw)), tool, {"name": "my-shop"})
    finally:
        helpers.mock_env(True)


def test_get_metrics_tool_official_empty_and_invalid():
    r = _run(OFFICIAL, "get_metrics")
    assert r["status"] == "ok" and r["result"]["disk"] == 40.0 and r["result"]["latest"]["cpu"][0]["value"] == 0.25
    # این کلاینت تستی کاتالوگ پلن ندارد ← درصد ساخته نمی‌شود، ولی مقدار خام (بایت/هسته) داده می‌شود
    assert r["result"]["cpu"] is None and r["result"]["memory"] is None
    assert r["result"]["cpu_cores"] == 0.25 and r["result"]["memory_bytes"] == 300
    assert "درصد ساخته نشد" in r["result"]["note"]
    for bad in ({}, None, {"cpuUsage": [{"value": [1, "NaN"]}]}):
        r = _run(bad, "get_metrics")
        assert r["status"] != "ok"                                                   # خطای قابل‌فهم، نه عدد ساختگی


def test_official_metrics_become_percent_with_plan_limits():
    """واحد قالب رسمی (مشاهده‌ی رفتاری API): RAM=بایت، CPU=هسته؛ درصد نسبت به سقف پلن /v1/me."""
    from liara_agent.diagnose import metrics_detail, parse_series
    raw = {"cpuUsage": [{"applet": "a", "value": [1, "0.25"]}, {"applet": "b", "value": [1, "0.25"]}],
           "memoryUsage": [{"applet": "a", "value": [1, str(256 * 1024 * 1024)]}],
           "disksUsage": [{"name": "d", "size": "100", "usage": "40"}]}
    d = metrics_detail(raw, {"ram_mb": 512, "cpu": 1})
    assert d["cpu_cores"] == 0.5 and d["cpu"] == 50.0                 # مجموع اپلت‌ها: ۰٫۵ از ۱ هسته
    assert d["memory_bytes"] == 256 * 1024 * 1024 and d["memory"] == 50.0
    assert d["disk"] == 40.0
    assert analyze({"project_id": "x", "status": "ACTIVE", "scale": 1}, raw, {"logs": []}, "", {"ram_mb": 512, "cpu": 1}) == []
    hot = {"memoryUsage": [{"value": [1, str(int(0.97 * 512 * 1024 * 1024))]}], "cpuUsage": [{"value": [1, "0.1"]}]}
    fs = analyze({"project_id": "x", "status": "ACTIVE", "scale": 1}, hot, {"logs": []}, "", {"ram_mb": 512, "cpu": 1})
    assert fs and "حافظه" in fs[0].cause                              # حالا با پلن، مصرف بالای RAM دیده می‌شود
    assert parse_series({"result": [{"applet": "a", "values": [[1, "2"], [2, "3"]]},
                                    {"applet": "b", "values": [[1, "1"], [2, "bad"]]}]}) == [(1.0, 3.0), (2.0, 3.0)]


def test_app_state_recognizes_real_liara_statuses():
    """رفع باگ اسکرین‌شات کاربر: لیارا برای اپ سالم ACTIVE برمی‌گرداند و قبلاً «در حال اجرا نیست» می‌زدیم."""
    from liara_agent import insights
    from liara_agent.diagnose import app_state
    assert app_state({"status": "ACTIVE", "scale": 1}) == "running"
    assert app_state({"status": "RUNNING", "scale": 1}) == "running"
    assert app_state({"status": "ACTIVE", "scale": 0}) == "off"
    assert app_state({"status": "STOPPED", "scale": 1}) == "off"
    assert app_state({"status": "CRASHED", "scale": 1}) == "error"
    assert app_state({"status": "BUILDING", "scale": 1}) == "busy"
    assert app_state({"status": "SOME-NEW-STATE", "scale": 1, "isDeployed": True}) == "running"   # ناشناخته ← خاموش فرض نشود
    s, why = insights.health_score({"status": "ACTIVE", "scale": 1, "isDeployed": True},
                                   {"cpu": None, "memory": None, "disk": None}, None)
    assert s == 100 and why == []
    assert all(a["key"] != "down" for a in insights.alerts({"status": "ACTIVE", "scale": 1}, {}, None))


def test_diagnose_reports_metrics_source_honestly():
    rep = _run(OFFICIAL, "diagnose_app")["result"]
    assert rep["sources"]["metrics"] == "ok" and rep["metrics"]["disk"] == 40.0
    rep = _run({"cpuUsage": [], "memoryUsage": [], "disksUsage": []}, "diagnose_app")["result"]
    assert rep["sources"]["metrics"].startswith("unavailable") and rep["metrics"] == NONE3
