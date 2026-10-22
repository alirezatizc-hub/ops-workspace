"""مغز گفتگو: پیام کاربر ← رویدادها برای UI. با LLM (اگر کلید باشد) یا قواعد داخلی."""
import json, os, re, time
from . import audit
from .diagnose import analyze
from .security import ConfirmStore
from .tools import execute

LABELS = {"diagnose_app": "بررسی وضعیت و لاگ‌ها", "get_logs": "خواندن لاگ‌ها", "get_metrics": "بررسی مصرف منابع",
          "app_status": "بررسی وضعیت اپ", "health_check": "تست دسترسی سایت", "detect_project": "تحلیل پوشه‌ی پروژه",
          "recommend_plan": "تخمین منابع", "domain_guide": "آماده‌سازی راهنمای دامنه", "deploy_guide": "آماده‌سازی راهنمای دیپلوی",
          "get_env_vars": "خواندن نام متغیرهای محیطی", "list_apps": "دریافت فهرست اپ‌ها", "analyze_repo": "تحلیل مخزن"}
DEPLOYS = ("deploy_app", "deploy_repo")
ev = lambda t, **k: {"type": t, **k}


def new_state():
    return {"confirm": ConfirmStore(), "msgs": [], "last": None, "url": ""}


def _err(r):
    return r.get("message", "خطای ناشناخته") + (f" ({str(r['detail'])[:120]})" if r.get("detail") else "")


def _confirm(tools, st, tool, args, title):
    if tool in DEPLOYS and st.get("url"):
        args = {**args, "health_url": st["url"]}
    return ev("confirm", id=st["confirm"].create(tool, args), title=title, preview=tools[tool].preview(args))


def diagnose_events(tools, st, app, url=""):
    out = [ev("step", text="در حال بررسی وضعیت و لاگ‌ها…")]
    r = execute(tools, "diagnose_app", {"name": app})
    if r["status"] != "ok":
        return out + [ev("error", text=_err(r))]
    rep = r["result"]; st["last"] = rep
    out.append(ev("report", data=rep))
    gaps = [f"{k}: {v[12:]}" for k, v in rep["sources"].items() if v.startswith("unavailable")]
    if gaps:
        out.append(ev("text", text="ℹ️ بخشی از داده‌ها در دسترس نبود و در تحلیل لحاظ نشد — " + " | ".join(gaps)))
    if url:
        h = execute(tools, "health_check", {"url": url})
        out.append(ev("step", text="تست دسترسی سایت از بیرون"))
        if h["status"] == "ok":
            hr = h["result"]
            out.append(ev("text", text=f"سایت {'پاسخ می‌دهد' if hr.get('ok') else 'مشکل دارد'}: " + (f"کد {hr['status_code']}، {hr['latency_ms']}ms" if "status_code" in hr else hr.get("error", ""))))
        else:
            out.append(ev("text", text="تست سایت انجام نشد: " + _err(h)))
    fs = rep["findings"]
    fix = next((f for f in fs if f["fix_tool"]), None)
    if fix:
        out.append(ev("text", text=f"محتمل‌ترین علت: «{fix['cause']}». پیشنهاد:"))
        out.append(_confirm(tools, st, fix["fix_tool"], fix["fix_args"], "اقدام پیشنهادی"))
    elif fs:
        out.append(ev("text", text="علت‌های محتمل بالا را ببینید (اقدام خودکار امن پیدا نشد). آخرین لاگ‌ها:"))
        lg = execute(tools, "get_logs", {"name": app, "lines": 12})
        if lg["status"] == "ok":
            out.append(ev("logs", lines=lg["result"]))
    elif gaps:
        out.append(ev("text", text="با داده‌های موجود مشکلی دیده نشد، ولی چون بخشی از داده در دسترس نبود نمی‌توانم سلامت کامل را تضمین کنم."))
    else:
        out.append(ev("text", text="با داده‌های موجود مشکلی پیدا نکردم."))
    return out


def apply_confirmed(tools, st, pid, approve):
    item = st["confirm"].consume(pid if isinstance(pid, str) else "")
    if not item:
        return [ev("error", text="این درخواست نامعتبر یا منقضی شده است.")]
    tool, args = item
    info = dict(tool=tool, summary=tools[tool].preview(args), args={k: ("***" if k == "value" else v) for k, v in args.items()})
    if approve is not True:
        audit.record(**info, decision="رد شد", outcome="—")
        return [ev("text", text="لغو شد. هیچ تغییری اعمال نشد.")]
    out = [ev("step", text="در حال اجرا…")]
    r = execute(tools, tool, args, confirmed=True)
    if r["status"] != "ok":
        audit.record(**info, decision="تأیید شد", outcome="خطا", detail=_err(r)[:200])
        return out + [ev("error", text="اجرا ناموفق بود: " + _err(r))]
    res = r["result"]
    if tool in DEPLOYS:
        audit.record(**info, decision="تأیید شد", outcome="موفق" if res.get("ok") else "ناموفق",
                     detail="; ".join(f"{s['name']}={s['state']}" for s in res["stages"]))
        out.append(ev("progress", stages=res["stages"], simulated=bool(res.get("simulated"))))
        if res.get("ok"):
            out.append(ev("text", text="✅ دیپلوی انجام شد و بررسی‌های بالا نتیجه‌ی واقعی هر مرحله است." + ((" آدرس: " + res["url"]) if res.get("url") else "")))
        else:
            out.append(ev("text", text="⚠️ دیپلوی کامل تأیید نشد؛ مراحل ناموفق/هشداردار را ببینید."))
            fs = analyze({}, {}, res.get("output", ""))
            if fs:
                out.append(ev("report", data={"metrics": {}, "plan": "-", "sources": {}, "findings": [f.__dict__ for f in fs]}))
        return out
    audit.record(**info, decision="تأیید شد", outcome="موفق")
    out.append(ev("text", text="✅ درخواست به API ارسال و پذیرفته شد."))
    app = args.get("name", "")
    before = (st.get("last") or {}).get("metrics", {})
    if os.getenv("LIARA_MOCK") != "1":
        time.sleep(8)
    out.append(ev("step", text="بررسی مجدد پس از اقدام…"))
    rr = execute(tools, "diagnose_app", {"name": app})
    if rr["status"] == "ok":
        rep = rr["result"]; st["last"] = rep
        out.append(ev("report", data=rep))
        bm, am = before.get("memory"), rep["metrics"].get("memory")
        cmp = f" مصرف RAM: {bm:.0f}٪ ← {am:.0f}٪." if bm is not None and am is not None else ""
        out.append(ev("text", text=("مشکل برطرف شد 🎉" if not rep["findings"] else "هنوز مورد باقی‌مانده هست.") + cmp, celebrate=not rep["findings"]))
    return out


def _rules(msg, app, tools, st, url):
    m = msg.lower()
    has = lambda *w: any(x in m for x in w)
    gh = re.search(r"https://github\.com/[\w.-]+/[\w.-]+", msg)
    if gh:
        a = execute(tools, "analyze_repo", {"repo_url": gh.group(0)})
        out = [ev("step", text="دریافت مخزن گیت‌هاب"), ev("step", text="تحلیل نوع پروژه")]
        if a["status"] != "ok":
            return out + [ev("error", text=_err(a))]
        d = a["result"]
        out.append(ev("guide", title=f"پروژه {d['platform']} شناسایی شد" + (" (شبیه‌سازی دمو)" if d.get("simulated") else ""),
                      items=[f"پورت پیشنهادی: {d['suggested_port']}", f"دیتابیس: {'دارد' if d['has_db'] else 'تشخیص داده نشد'}", d["recommendation"]["note"]]))
        out.append(ev("text", text=f"روی اپ موجود «{app}» دیپلوی کنم؟"))
        return out + [_confirm(tools, st, "deploy_repo", {"name": app, "repo_url": d["repo"], "platform": d["platform"], "port": d["suggested_port"]}, "دیپلوی از گیت‌هاب")]
    if re.search(r"https?://\S+", msg) and has("دیپلوی", "deploy", "انتشار") and not has("سایت", "لاگ"):
        return [ev("text", text="فعلاً فقط مخزن‌های عمومی گیت‌هاب را می‌توانم دیپلوی کنم؛ آدرس باید مثل https://github.com/user/repo باشد.")]
    dom = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", m)
    if has("دامنه", "ایرنیک", "irnic", "dns") or (dom and has("وصل", "تنظیم")):
        g = execute(tools, "domain_guide", {"domain": dom.group(1) if dom else "example.ir"})
        if g["status"] != "ok":
            return [ev("error", text=_err(g))]
        return [ev("step", text="آماده‌سازی راهنمای دامنه"), ev("guide", title="اتصال دامنه (راهنمای ثابت)", items=g["result"]["steps"], note=g["result"]["limitation"])]
    if has("دیپلوی", "انتشار", "راه‌اندازی", "راه اندازی", "بالا بیار", "deploy"):
        d = execute(tools, "detect_project", {"path": "."})
        out = [ev("step", text="تحلیل پوشه‌ی پروژه")]
        if d["status"] != "ok":
            g = execute(tools, "deploy_guide", {"kind": "node"})["result"]
            return out + [ev("text", text="پروژه را در پوشه‌ی فعلی پیدا نکردم (" + _err(d) + "). مراحل دستی:"),
                          ev("guide", title="دیپلوی با CLI", items=g["steps"], code=["liara login", "liara deploy"], note=g["limitation"])]
        d = d["result"]
        out.append(ev("guide", title=f"پروژه {d['platform']} شناسایی شد", items=[f"پورت پیشنهادی: {d['suggested_port']}", f"دیتابیس: {'دارد' if d['has_db'] else 'تشخیص داده نشد'}", d["recommendation"]["note"]]))
        return out + [_confirm(tools, st, "deploy_app", {"name": app, "platform": d["platform"], "port": d["suggested_port"]}, "دیپلوی روی لیارا")]
    if has("ری‌استارت", "ریستارت", "restart", "راه‌اندازی مجدد"):
        return [_confirm(tools, st, "restart_app", {"name": app}, "ری‌استارت اپ")]
    if has("لاگ", "log"):
        r = execute(tools, "get_logs", {"name": app, "lines": 25})
        return [ev("step", text="خواندن لاگ‌ها"), ev("logs", lines=r["result"]) if r["status"] == "ok" else ev("error", text=_err(r))]
    if has("وضعیت", "مصرف", "رم", "cpu", "سلامت", "چطور", "چرا اپ", "اپ بالا نیست", "بالا نیست", "بالا نمیاد", "بالا نمی‌آید", "اجرا نیست", "اجرا نمی‌شود", "اجرا نمیشه", "کار نمی‌کند", "کار نمیکنه", "راه نمی‌افتد", "راه نمیفته", "۵۰۰", "500", "ارور", "خطا", "کند", "کندی", "نمیاد", "باز نمی", "قطع", "مشکل", "down"):
        return diagnose_events(tools, st, app, url)
    return [ev("text", text="می‌توانم کمک کنم: «سایتم ارور ۵۰۰ می‌دهد»، «وضعیت سایت»، «لاگ‌ها»، «می‌خواهم دیپلوی کنم» یا «وصل کردن دامنه my.ir».")]


def _llm(msg, app, tools, st, url):
    from openai import OpenAI
    from .agent import SYSTEM
    ai = OpenAI(
        api_key=os.environ["BOXAPI_API_KEY"],
        base_url=os.getenv("BOXAPI_BASE_URL", "https://ai.boxapi.ir/ai/v1").rstrip("/"),
        timeout=45.0,
        max_retries=1,
    )
    model = os.getenv("LIARA_AGENT_MODEL", "gpt-5.4-mini")
    spec = [{"type": "function", "function": {
        "name": t.name, "description": t.description, "parameters": t.schema
    }} for t in tools.values()]
    st["msgs"].append({"role": "user", "content": f"[اپ فعلی: {app}] {msg}"})
    out = []
    for _ in range(6):
        r = ai.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": SYSTEM}, *st["msgs"]],
            tools=spec,
            max_completion_tokens=1200,
        )
        m = r.choices[0].message
        assistant_msg = m.model_dump(exclude_none=True)
        st["msgs"].append(assistant_msg)
        if m.content and m.content.strip():
            out.append(ev("text", text=m.content))
        calls = m.tool_calls or []
        if not calls:
            break
        results = []
        for call in calls:
            try:
                args = json.loads(call.function.arguments or "{}")
            except (TypeError, json.JSONDecodeError):
                args = {}
                x = {"status": "error", "message": "مدل آرگومان ابزار نامعتبر فرستاد."}
            else:
                x = execute(tools, call.function.name, args)
            if x["status"] == "needs_confirmation":
                out.append(_confirm(tools, st, call.function.name, args, "نیاز به تأیید شما"))
                x = {"status": "waiting", "message": "منتظر تأیید کاربر در UI."}
                results.append({"role": "tool", "tool_call_id": call.id,
                                "content": json.dumps(x, ensure_ascii=False)})
                st["msgs"].extend(results)
                return out
            out.append(ev("step", text=LABELS.get(call.function.name, call.function.name)))
            if call.function.name == "diagnose_app" and x["status"] == "ok":
                st["last"] = x["result"]
                out.append(ev("report", data=x["result"]))
            results.append({"role": "tool", "tool_call_id": call.id,
                            "content": json.dumps(x, ensure_ascii=False)})
        st["msgs"].extend(results)
    return out

def handle(msg, app, tools, st, url=""):
    msg = (msg or "")[:2000]
    st["url"] = url if isinstance(url, str) else ""
    if os.getenv("BOXAPI_API_KEY") and os.getenv("LIARA_NO_LLM") != "1":
        try:
            return _llm(msg, app, tools, st, url)
        except Exception as e:
            # جزئیات خطای API برای عیب‌یابی؛ کلیدها و توکن‌ها هرگز به UI فرستاده نمی‌شوند.
            detail = str(getattr(e, "message", "") or e)
            key = os.getenv("BOXAPI_API_KEY", "")
            if key:
                detail = detail.replace(key, "[REDACTED]")
            detail = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\\1[REDACTED]", detail)
            detail = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "[REDACTED]", detail)
            detail = re.sub(r"\s+", " ", detail).strip()[:260]
            status = getattr(e, "status_code", None)
            tag = f"HTTP {status}: " if status else ""
            return [ev("step", text=f"خطای BoxAPI ({type(e).__name__}) — {tag}{detail or 'جزئیات خطا موجود نیست'}؛ استفاده از حالت ساده")] + _rules(msg, app, tools, st, url)
    return _rules(msg, app, tools, st, url)
