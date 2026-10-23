"""امتیاز سلامت، هشدارهای فعال و تاریخچه‌ی نمونه‌های مصرف."""
import math, os, time
from .diagnose import app_state

HIST = {}


def health_score(p, m, h):
    s, why = 100, []
    def pen(n, t):
        nonlocal s; s -= n; why.append(t)
    # تشخیص وضعیت از روی status/scale واقعی لیارا (مثلاً ACTIVE یعنی در حال اجرا)؛
    # وضعیت «نامشخص» امتیاز کم نمی‌کند تا هشدار کاذب ندهیم.
    st = app_state(p)
    if st in ("off", "error"):
        pen(60, "اپ در حال اجرا نیست" if st == "off" else "اپ در وضعیت خطاست")
    elif st == "busy":
        pen(10, "اپ در حال دیپلوی/راه‌اندازی است")
    mem, cpu, disk = m.get("memory"), m.get("cpu"), m.get("disk")
    if mem is not None:
        if mem >= 85: pen(25, f"RAM بحرانی ({mem:.0f}٪)")
        elif mem >= 70: pen(10, f"RAM بالا ({mem:.0f}٪)")
    if cpu is not None:
        if cpu >= 85: pen(15, f"CPU بحرانی ({cpu:.0f}٪)")
        elif cpu >= 70: pen(7, f"CPU بالا ({cpu:.0f}٪)")
    if disk is not None and disk >= 90: pen(15, f"دیسک رو به پر شدن ({disk:.0f}٪)")
    if h:
        if not h.get("ok"): pen(30, "سایت از بیرون پاسخ سالم نمی‌دهد")
        elif h.get("latency_ms", 0) > 2000: pen(15, f"سایت کند است ({h['latency_ms']}ms)")
    if p.get("scale") == 0: pen(20, "اپ خاموش است (scale=0)")
    if p.get("isDeployed") is False: pen(20, "اپ هنوز دیپلوی نشده")
    return max(s, 0), why


def alerts(p, m, h):
    out = []
    st = app_state(p)
    if p.get("scale") == 0:
        out.append({"key": "off", "level": "warn", "text": "اپ خاموش است", "ask": "اپ را روشن کن"})
    elif st in ("off", "error"):
        out.append({"key": "down", "level": "bad",
                    "text": "اپ در وضعیت خطاست" if st == "error" else "اپ در حال اجرا نیست",
                    "ask": "چرا اپ بالا نیست؟ بررسی کن"})
    if (m.get("memory") or 0) >= 85:
        out.append({"key": "mem", "level": "bad", "text": f"مصرف RAM بحرانی است ({m['memory']:.0f}٪)", "ask": "چرا مصرف RAM بالاست؟ بررسی کن"})
    if (m.get("cpu") or 0) >= 85:
        out.append({"key": "cpu", "level": "warn", "text": f"فشار روی CPU زیاد است ({m['cpu']:.0f}٪)", "ask": "چرا CPU بالاست؟ بررسی کن"})
    if (m.get("disk") or 0) >= 90:
        out.append({"key": "disk", "level": "warn", "text": f"دیسک نزدیک پر شدن است ({m['disk']:.0f}٪)", "ask": "دیسک‌ها را بررسی کن"})
    if h and not h.get("ok"):
        out.append({"key": "site", "level": "bad", "text": "سایت از بیرون در دسترس نیست یا خطا می‌دهد", "ask": "سایتم ارور می‌دهد، بررسی کن"})
    elif h and h.get("latency_ms", 0) > 2000:
        out.append({"key": "slow", "level": "warn", "text": f"سایت کند شده ({h['latency_ms']}ms)", "ask": "سایتم کند شده، بررسی کن"})
    return out


def record(name, m):
    h = HIST.setdefault(name, [])
    if not h and os.getenv("LIARA_MOCK") == "1":      # فقط در دمو: روند نمونه
        n, mem, cpu = 24, m.get("memory") or 50, m.get("cpu") or 30
        for i in range(n):
            f = i / (n - 1)
            h.append({"t": "", "memory": 45 + (mem - 45) * f ** 2 if mem >= 85 else mem + 2 * math.sin(i),
                      "cpu": cpu + 6 * math.sin(i / 2), "demo": True})
    if m.get("memory") is None and m.get("cpu") is None:
        return h                                   # هرگز نمونه‌ی خالی/ساختگی ثبت نمی‌شود
    now = time.strftime("%H:%M:%S")
    if h and h[-1].get("t") == now:                # همان ثانیه دوباره ثبت نکن (رفرش‌های پشت سر هم)
        return h
    h.append({"t": now, "memory": m.get("memory"), "cpu": m.get("cpu")})
    del h[:-60]
    return h


def seed(name, points):
    """پر کردن نمودار با تاریخچه‌ی واقعی API (فقط وقتی نمونه‌ی زنده‌ای هنوز نداریم)."""
    h = HIST.setdefault(name, [])
    real = [x for x in h if not x.get("demo") and x.get("t")]
    if len(real) >= 3 or not points:
        return h
    HIST[name] = (points[-60:] + real)[-60:]
    return HIST[name]
