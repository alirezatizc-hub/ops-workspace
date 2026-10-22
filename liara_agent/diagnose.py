"""موتور عیب‌یابی قاعده‌محور (بدون وابستگی). شواهد -> علت‌های رتبه‌بندی‌شده."""
import math, re
from dataclasses import dataclass, field


@dataclass
class Finding:
    cause: str
    confidence: float
    evidence: list = field(default_factory=list)
    suggestion: str = ""
    fix_tool: str = ""          # نام ابزار اصلاحی (در صورت وجود)
    fix_args: dict = field(default_factory=dict)


OFFICIAL_METRIC_KEYS = ("cpuUsage", "memoryUsage", "disksUsage")


def _num(x):
    """عدد متناهی و نامنفی یا None (bool، NaN، inf، رشته‌ی غیرعددی و مقدار منفی نامعتبرند)."""
    if isinstance(x, bool):
        return None
    if isinstance(x, str):
        if "_" in x:
            return None
        try:
            x = float(x.strip())
        except ValueError:
            return None
    if not isinstance(x, (int, float)):
        return None
    v = float(x)
    return v if math.isfinite(v) and v >= 0 else None


def _points(value):
    """«value» رسمی: یک جفت [timestamp, value] یا فهرستی از جفت‌ها. -> (نمونه‌های معتبر، تعداد نامعتبر)"""
    if not isinstance(value, list):
        return [], 1
    scalar = lambda v: not isinstance(v, (list, tuple, dict))
    cands = [value] if len(value) == 2 and scalar(value[0]) and scalar(value[1]) else value
    pts, bad = [], 0
    for c in cands:
        if isinstance(c, (list, tuple)) and len(c) == 2 and _num(c[0]) is not None and _num(c[1]) is not None:
            pts.append((_num(c[0]), _num(c[1])))
        else:
            bad += 1
    return pts, bad


def _series(items, key, issues):
    if items is None:
        return []
    if not isinstance(items, list):
        issues.append(f"{key}: قالب آرایه نیست")
        return []
    if not items:
        issues.append(f"{key}: داده‌ای برنگشت")
    out = []
    for it in items:
        pts, bad = _points(it.get("value")) if isinstance(it, dict) else ([], 1)
        if bad:
            issues.append(f"{key}: {bad} نمونه‌ی نامعتبر نادیده گرفته شد")
        if pts:
            t, v = max(pts)                                    # جدیدترین نمونه
            out.append({"applet": str(it.get("applet", "")), "timestamp": t, "value": v})
    return out


def _disks(items, issues):
    if items is None:
        return []
    if not isinstance(items, list):
        issues.append("disksUsage: قالب آرایه نیست")
        return []
    if not items:
        issues.append("disksUsage: داده‌ای برنگشت")
    out = []
    for it in items:
        size, usage = (_num(it.get("size")), _num(it.get("usage"))) if isinstance(it, dict) else (None, None)
        if size is None or usage is None or size == 0:
            issues.append("disksUsage: یک دیسک با size/usage نامعتبر نادیده گرفته شد")
            continue
        out.append({"name": str(it.get("name", "")), "size": size, "usage": usage,
                    "percent": usage / size * 100, "reportedAt": it.get("reportedAt")})
    return out


def parse_metrics_summary(raw) -> dict:
    """قالب رسمی GET /v1/projects/{name}/metrics/summary (+ قالب قدیمی cpu/memory/disk درصدی).
    فرض تأییدنشده: معنای «value» (جفت [timestamp, value]) در مستندات رسمی مثال/توضیح ندارد.
    هیچ مقداری ساخته یا حدس زده نمی‌شود؛ ناقص/نامعتبر در issues گزارش می‌شود."""
    r = {"format": "unknown", "usable": False, "cpu": [], "memory": [], "disks": [], "legacy": {}, "issues": []}
    if raw is None or raw == {} or raw == []:
        r["format"] = "empty"; r["issues"].append("پاسخ متریک خالی بود")
        return r
    if not isinstance(raw, dict):
        r["issues"].append("قالب پاسخ متریک شیء JSON نبود")
        return r
    if any(k in raw for k in OFFICIAL_METRIC_KEYS):
        r["format"] = "official"
        r["cpu"] = _series(raw.get("cpuUsage"), "cpuUsage", r["issues"])
        r["memory"] = _series(raw.get("memoryUsage"), "memoryUsage", r["issues"])
        r["disks"] = _disks(raw.get("disksUsage"), r["issues"])
        for k in OFFICIAL_METRIC_KEYS:
            if k not in raw:
                r["issues"].append(f"{k}: در پاسخ نبود")
    else:
        m = raw.get("metrics", raw)
        m = m if isinstance(m, dict) else {}
        pick = lambda *ks: next((_num(m[k]) for k in ks if _num(m.get(k)) is not None), None)
        r["legacy"] = {"cpu": pick("cpu", "cpu_percent"), "memory": pick("memory", "memory_percent", "ram"),
                       "disk": pick("disk", "disk_percent")}
        if any(v is not None for v in r["legacy"].values()):
            r["format"] = "legacy"
        else:
            r["issues"].append("قالب پاسخ متریک ناشناخته یا مقادیر نامعتبر بود")
    r["usable"] = bool(r["cpu"] or r["memory"] or r["disks"] or any(v is not None for v in r["legacy"].values()))
    return r


def normalize_metrics(raw) -> dict:
    """خروجی ثابت {cpu, memory, disk} بر حسب درصد یا None.
    در قالب رسمی فقط دیسک درصد می‌شود (usage/size)؛ واحد CPU/RAM در spec مشخص نیست و تبدیل نمی‌شود."""
    p = parse_metrics_summary(raw)
    if p["format"] == "official":
        return {"cpu": None, "memory": None, "disk": max((d["percent"] for d in p["disks"]), default=None)}
    return {"cpu": p["legacy"].get("cpu"), "memory": p["legacy"].get("memory"), "disk": p["legacy"].get("disk")}


def logs_to_lines(raw) -> list:
    items = raw.get("logs", raw.get("text", raw)) if isinstance(raw, dict) else raw
    if isinstance(items, str):
        return items.splitlines()
    out = []
    for i in items or []:
        out.append(i.get("message", str(i)) if isinstance(i, dict) else str(i))
    return out


RULES = [
    ("کمبود حافظه (RAM / OOM)", r"out of memory|OOMKilled|heap limit|MemoryError|Killed process",
     "memory", 85, "پلن را یک پله بالا ببرید یا نشت حافظه را بررسی کنید."),
    ("ماژول/وابستگی نصب‌نشده", r"Cannot find module|ModuleNotFoundError|No module named",
     None, 0, "وابستگی‌ها را در package.json/requirements.txt اضافه و دوباره دیپلوی کنید."),
    ("اتصال به دیتابیس/سرویس بیرونی ناموفق", r"ECONNREFUSED|ETIMEDOUT|could not connect|Access denied for user|ConnectionError",
     None, 0, "آدرس/رمز دیتابیس و متغیرهای محیطی را بررسی کنید."),
    ("متغیر محیطی ناموجود", r"is not defined|Missing required|KeyError: ['\"][A-Z_]+|env.*(undefined|missing)",
     None, 0, "متغیرهای محیطی لازم را تنظیم کنید."),
    ("تداخل/اشتباه پورت", r"EADDRINUSE|no open port|port.*(not|wrong)",
     None, 0, "برنامه باید روی پورت تعریف‌شده در لیارا گوش دهد (متغیر PORT)."),
    ("پر شدن دیسک", r"ENOSPC|No space left", "disk", 90, "فایل‌های اضافه را پاک کنید یا دیسک را افزایش دهید."),
]


def next_plan_from_catalog(catalog, current):
    """پلن بعدی را فقط از کاتالوگ واقعی (دارای id و ram_mb) پیدا می‌کند؛ در غیر این صورت ''."""
    items = catalog.get("plans", catalog) if isinstance(catalog, dict) else catalog
    plans = sorted((p for p in items or [] if isinstance(p, dict) and p.get("id") and isinstance(p.get("ram_mb"), (int, float))),
                   key=lambda p: p["ram_mb"])
    ids = [p["id"] for p in plans]
    return ids[ids.index(current) + 1] if current in ids[:-1] else ""


NO_PLAN_HINT = " (شناسه‌ی پلن‌ها از API تأییدشده در دسترس نیست؛ پلن را از پنل لیارا انتخاب کنید.)"


def analyze(project: dict, metrics_raw, logs_raw, next_plan="") -> list:
    met, lines = normalize_metrics(metrics_raw), logs_to_lines(logs_raw)
    text, findings = "\n".join(lines), []
    for cause, pat, metric, thr, sug in RULES:
        hits = [l for l in lines if re.search(pat, l, re.I)]
        high = metric and met.get(metric) is not None and met[metric] >= thr
        if not hits and not high:
            continue
        conf = 0.15 + (0.55 if hits else 0) + (0.3 if high else 0)
        ev = hits[:3] + ([f"{metric} = {met[metric]:.0f}٪"] if high else [])
        f = Finding(cause, round(min(conf, 0.98), 2), ev, sug)
        if metric == "memory":
            nxt = next_plan() if callable(next_plan) else next_plan
            if nxt:
                f.fix_tool, f.fix_args = "resize_app", {"name": project.get("project_id", ""), "plan": nxt}
            else:
                f.suggestion += NO_PLAN_HINT
        findings.append(f)
    n5xx = sum(1 for l in lines if re.search(r"\b5\d\d\b", l))
    if n5xx and not findings:
        findings.append(Finding("خطای برنامه (۵xx) با علت نامشخص", 0.4,
                                [f"{n5xx} خط خطای ۵xx در لاگ"], "لاگ کامل برنامه را بررسی کنید؛ آخرین دیپلوی را مرور کنید."))
    if met.get("cpu") and met["cpu"] >= 90 and not any("CPU" in f.cause for f in findings):
        findings.append(Finding("فشار CPU", 0.6, [f"cpu = {met['cpu']:.0f}٪"], "پلن را ارتقا دهید یا کدهای سنگین را بهینه کنید."))
    return sorted(findings, key=lambda f: -f.confidence)
