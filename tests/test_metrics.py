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
    assert "فرض تأییدنشده" in r["result"]["note"] and "استفاده نمی‌شود" in r["result"]["note"]
    for bad in ({}, None, {"cpuUsage": [{"value": [1, "NaN"]}]}):
        r = _run(bad, "get_metrics")
        assert r["status"] != "ok"                                                   # خطای قابل‌فهم، نه عدد ساختگی


def test_diagnose_reports_metrics_source_honestly():
    rep = _run(OFFICIAL, "diagnose_app")["result"]
    assert rep["sources"]["metrics"] == "ok" and rep["metrics"]["disk"] == 40.0
    rep = _run({"cpuUsage": [], "memoryUsage": [], "disksUsage": []}, "diagnose_app")["result"]
    assert rep["sources"]["metrics"].startswith("unavailable") and rep["metrics"] == NONE3
