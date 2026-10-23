"""مغز گفتگو: پیام کاربر ← رویدادها برای UI. با LLM (اگر کلید باشد) یا قواعد داخلی."""
import json, os, re, time
from . import audit
from .diagnose import analyze
from .security import ConfirmStore
from .tools import execute

LABELS = {"diagnose_app": "بررسی وضعیت و لاگ‌ها", "get_logs": "خواندن لاگ‌ها", "get_metrics": "بررسی مصرف منابع",
          "app_status": "بررسی وضعیت اپ", "health_check": "تست دسترسی سایت", "detect_project": "تحلیل پوشه‌ی پروژه",
          "recommend_plan": "تخمین منابع", "domain_guide": "آماده‌سازی راهنمای دامنه", "deploy_guide": "آماده‌سازی راهنمای دیپلوی",
          "get_env_vars": "خواندن نام متغیرهای محیطی", "list_apps": "دریافت فهرست اپ‌ها", "analyze_repo": "تحلیل مخزن",
          "get_plans": "دریافت پلن‌ها", "get_metric_history": "دریافت روند مصرف", "app_events": "خواندن رویدادهای اپ",
          "app_releases": "دریافت ریلیزها", "list_disks": "دریافت دیسک‌ها", "list_disk_backups": "فهرست بکاپ‌های دیسک",
          "account_info": "بررسی حساب", "list_databases": "دریافت فهرست دیتابیس‌ها", "database_status": "بررسی دیتابیس",
          "database_metrics": "مصرف منابع دیتابیس", "database_events": "رویدادهای دیتابیس",
          "list_database_backups": "فهرست بکاپ‌های دیتابیس", "list_domains": "دریافت دامنه‌ها", "check_domain": "بررسی دامنه"}
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


def _seen(tool, summary, outcome="موفق"):
    """اقدامات مشاهده‌ای (عیب‌یابی، لاگ، فهرست‌ها) هم در تاریخچه ثبت می‌شوند تا پنل تاریخچه خالی نماند."""
    audit.record(tool=tool, summary=summary, decision="مشاهده", outcome=outcome, args={})


def _rows(items, title_key, *sub_keys, badge_key=""):
    rows = []
    for it in items or []:
        if not isinstance(it, dict):
            rows.append({"t": str(it)[:120], "s": "", "b": ""}); continue
        sub = " · ".join(str(it[k]) for k in sub_keys if it.get(k) not in (None, ""))
        rows.append({"t": str(it.get(title_key, "—")), "s": sub, "b": str(it.get(badge_key, "")) if badge_key else ""})
    return rows


LIST_CARDS = {
    "list_databases": lambda r: ("🗄️ دیتابیس‌های شما", _rows(r.get("databases"), "hostname", "type", "version", "planID", badge_key="state_fa")),
    "list_domains": lambda r: ("🌐 دامنه‌های شما", _rows(r.get("domains"), "name", "project", badge_key="ssl")),
    "list_disks": lambda r: ("💾 دیسک‌های اپ", _rows(r.get("disks"), "name", "size", "usage")),
    "list_database_backups": lambda r: (f"🧰 بکاپ‌های «{r.get('database', '')}»", _rows(r.get("backups"), "name", "lastModified", "size")),
    "list_disk_backups": lambda r: ("🧰 بکاپ‌های دیسک", _rows(r.get("backups"), "name", "size")),
    "app_events": lambda r: ("📌 رویدادهای اپ", _rows(r.get("events"), "message", "created_at", badge_key="type")),
    "database_events": lambda r: (f"📌 رویدادهای «{r.get('database', '')}»", _rows(r.get("events"), "message", "created_at", badge_key="type")),
    "app_releases": lambda r: ("🚀 ریلیزهای اپ", _rows(r.get("releases"), "tag", "createdAt", badge_key="state")),
    "list_apps": lambda r: ("📦 اپ‌های شما", _rows(r, "project_id", "type", "planID", badge_key="state_fa")),
}


def list_event(tool, result):
    fn = LIST_CARDS.get(tool)
    if not fn:
        return None
    try:
        title, rows = fn(result)
    except Exception:
        return None
    return ev("list", title=title, rows=rows)


def diagnose_events(tools, st, app, url=""):
    out = [ev("step", text="در حال بررسی وضعیت و لاگ‌ها…")]
    r = execute(tools, "diagnose_app", {"name": app})
    if r["status"] != "ok":
        _seen("diagnose_app", f"عیب‌یابی اپ «{app}»", "خطا")
        return out + [ev("error", text=_err(r))]
    rep = r["result"]; st["last"] = rep
    _seen("diagnose_app", f"عیب‌یابی اپ «{app}» — {len(rep.get('findings', []))} یافته")
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
    # لینک دانلود بکاپ
    if isinstance(res, dict) and res.get("link"):
        return out + [ev("text", text=f"⬇️ لینک دانلود آماده است (موقت):\n{res['link']}")]
    # راستی‌آزمایی مخصوص دیتابیس
    if isinstance(res, dict) and res.get("database"):
        vr = execute(tools, "database_status", {"ref": res["database"]})
        if vr["status"] == "ok":
            d = vr["result"]
            out.append(ev("text", text=f"وضعیت فعلی دیتابیس «{d.get('hostname')}»: {d.get('state_fa', '')} · پلن {d.get('planID', '–')}"))
        return out
    if tool.startswith("create_database") or tool.startswith("download_") or tool in (
            "add_domain", "attach_domain", "enable_ssl", "disable_ssl", "set_domain_redirect", "delete_domain",
            "create_app", "delete_app", "create_disk", "create_disk_backup", "create_database_backup"):
        if isinstance(res, dict) and res.get("note"):
            out.append(ev("text", text="ℹ️ " + res["note"]))
        return out
    app = args.get("name", "")
    if not app:
        return out
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


def _db_ref(msg, tools):
    """نام دیتابیس را از متن پیدا می‌کند؛ اگر نبود و فقط یک دیتابیس هست همان، وگرنه None."""
    r = execute(tools, "list_databases", {})
    dbs = r["result"]["databases"] if r["status"] == "ok" else []
    low = msg.lower()
    for d in dbs:
        h = str(d.get("hostname") or "").lower()
        if h and h in low:
            return d.get("hostname"), dbs
    if len(dbs) == 1:
        return dbs[0].get("hostname"), dbs
    return None, dbs


def _db_need_ref(msg, tools):
    ref, dbs = _db_ref(msg, tools)
    if ref:
        return ref, None
    names = "، ".join(f"«{d.get('hostname')}»" for d in dbs) or "—"
    return None, [ev("text", text=f"کدام دیتابیس؟ نامش را بگو. دیتابیس‌های شما: {names}")]


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
    # ---------- دیتابیس‌ها ----------
    if has("دیتابیس", "پایگاه داده", "database", "mysql", "پستگرس", "postgres", "مانگو", "mongo", "ردیس", "redis"):
        if has("بساز", "ایجاد", "جدید", "ساخت"):
            host = re.search(r"[a-z][a-z0-9-]{2,40}", m.replace("mysql", " ").replace("postgres", " ").replace("mongodb", " ").replace("redis", " ").replace("mariadb", " "))
            dbt = next((t for t, w in (("mysql", ("mysql", "مای‌اس‌کیو‌ال")), ("postgres", ("postgres", "پستگرس")),
                                       ("mongodb", ("mongo", "مانگو")), ("redis", ("redis", "ردیس")),
                                       ("mariadb", ("mariadb", "ماریا"))) if any(x in m for x in w)), "")
            if not (host and dbt):
                return [ev("text", text="برای ساخت دیتابیس اینطوری بگو: «یک دیتابیس mysql به نام shop-db بساز» (نوع: mysql/postgres/mongodb/redis).")]
            return [_confirm(tools, st, "create_database", {"hostname": host.group(0), "db_type": dbt}, "ساخت دیتابیس جدید")]
        if has("حذف", "پاک"):
            ref, ask = _db_need_ref(msg, tools)
            return ask or [_confirm(tools, st, "delete_database", {"ref": ref}, "⚠️ حذف دیتابیس")]
        if has("خاموش", "توقف", "ببند"):
            ref, ask = _db_need_ref(msg, tools)
            return ask or [_confirm(tools, st, "turn_database_off", {"ref": ref}, "خاموش کردن دیتابیس")]
        if has("روشن", "اجرا کن", "استارت"):
            ref, ask = _db_need_ref(msg, tools)
            return ask or [_confirm(tools, st, "turn_database_on", {"ref": ref}, "روشن کردن دیتابیس")]
        if has("دانلود") and has("بکاپ", "پشتیبان"):
            ref, ask = _db_need_ref(msg, tools)
            return ask or [_confirm(tools, st, "download_database_backup", {"ref": ref}, "دانلود آخرین بکاپ دیتابیس")]
        if has("بکاپ", "پشتیبان"):
            ref, ask = _db_need_ref(msg, tools)
            if ask:
                return ask
            if has("لیست", "فهرست", "ها", "نشون", "نشان", "ببین"):
                r = execute(tools, "list_database_backups", {"ref": ref})
                _seen("list_database_backups", f"فهرست بکاپ‌های «{ref}»")
                return [ev("step", text="دریافت بکاپ‌ها"), list_event("list_database_backups", r["result"])] if r["status"] == "ok" else [ev("error", text=_err(r))]
            return [_confirm(tools, st, "create_database_backup", {"ref": ref}, "بکاپ از دیتابیس")]
        if has("شبکه عمومی", "دسترسی عمومی", "اینترنت"):
            ref, ask = _db_need_ref(msg, tools)
            on = not has("ببند", "قطع", "غیرفعال", "خاموش")
            return ask or [_confirm(tools, st, "set_database_public_network", {"ref": ref, "on": on}, "شبکه‌ی عمومی دیتابیس")]
        if has("مصرف", "منابع", "رم", "cpu"):
            ref, ask = _db_need_ref(msg, tools)
            if ask:
                return ask
            r = execute(tools, "database_metrics", {"ref": ref})
            if r["status"] != "ok":
                return [ev("error", text=_err(r))]
            d = r["result"]
            pct = lambda v: "نامشخص" if v is None else f"{v:.0f}٪"
            return [ev("text", text=f"مصرف دیتابیس «{ref}»: CPU {pct(d.get('cpu'))} · RAM {pct(d.get('memory'))} ({d.get('memory_human', '')}) · دیسک {pct(d.get('disk'))}")]
        # پیش‌فرض: فهرست دیتابیس‌ها + جزئیات اگر یکی مشخص بود
        ref, dbs = _db_ref(msg, tools)
        out = [ev("step", text="دریافت دیتابیس‌ها")]
        r = execute(tools, "list_databases", {})
        if r["status"] != "ok":
            return out + [ev("error", text=_err(r))]
        _seen("list_databases", "فهرست دیتابیس‌ها")
        out.append(list_event("list_databases", r["result"]))
        if ref:
            dr = execute(tools, "database_status", {"ref": ref})
            if dr["status"] == "ok":
                d, cn = dr["result"], dr["result"].get("connection", {})
                out.append(ev("text", text=f"«{d.get('hostname')}» ({d.get('type')} {d.get('version') or ''}): {d.get('state_fa', '')} · پلن {d.get('planID', '–')} · "
                                           f"هاست {cn.get('host', '–')}:{cn.get('port', '–')} · کاربر {cn.get('username', '–')} · رمز در پنل لیارا است و نمایشش نمی‌دهم."))
        else:
            out.append(ev("text", text="می‌توانم دیتابیس را خاموش/روشن کنم، بکاپ بگیرم یا دانلود کنم، پلنش را عوض کنم یا یکی جدید بسازم؛ مثلاً: «دیتابیس shop-db را خاموش کن»."))
        return out
    # ---------- روشن/خاموش و حذف اپ ----------
    if has("خاموش") and not has("دیتابیس"):
        return [_confirm(tools, st, "turn_app_off", {"name": app}, "خاموش کردن اپ")]
    if (has("روشن") or has("استارت")) and not has("دیتابیس", "دیپلوی"):
        return [_confirm(tools, st, "turn_app_on", {"name": app}, "روشن کردن اپ")]
    if has("حذف اپ", "اپ را حذف", "اپ رو حذف", "delete app"):
        return [_confirm(tools, st, "delete_app", {"name": app}, "⚠️ حذف کامل اپ")]
    if has("رویداد", "event"):
        src, tool = (("app_events", {"name": app}), "app_events")
        r = execute(tools, tool, src[1])
        _seen(tool, f"رویدادهای اپ «{app}»")
        return [list_event(tool, r["result"])] if r["status"] == "ok" else [ev("error", text=_err(r))]
    if has("ریلیز", "نسخه‌های دیپلوی", "release"):
        r = execute(tools, "app_releases", {"name": app})
        _seen("app_releases", f"ریلیزهای اپ «{app}»")
        return [list_event("app_releases", r["result"])] if r["status"] == "ok" else [ev("error", text=_err(r))]
    if has("دیسک"):
        r = execute(tools, "list_disks", {"name": app})
        _seen("list_disks", f"دیسک‌های اپ «{app}»")
        return [list_event("list_disks", r["result"])] if r["status"] == "ok" else [ev("error", text=_err(r))]
    if has("موجودی", "اعتبار حساب", "حساب من", "شارژ"):
        r = execute(tools, "account_info", {})
        if r["status"] != "ok":
            return [ev("error", text=_err(r))]
        d = r["result"]
        bal = f" · موجودی: {d['balance']:,}" if isinstance(d.get("balance"), (int, float)) else ""
        return [ev("text", text=f"حساب {d.get('fullname') or ''} ({d.get('email') or ''}){bal}\nاپ: {d.get('apps')} · دیتابیس: {d.get('databases')} · دامنه: {d.get('domains')}")]
    # ---------- دامنه‌ها ----------
    dom_all = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", m)
    if has("دامنه‌ها", "دامنه ها", "فهرست دامنه", "لیست دامنه"):
        r = execute(tools, "list_domains", {})
        _seen("list_domains", "فهرست دامنه‌ها")
        return [list_event("list_domains", r["result"])] if r["status"] == "ok" else [ev("error", text=_err(r))]
    if has("ssl", "گواهی", "https فعال", "اس‌اس‌ال") and dom_all:
        if has("غیرفعال", "خاموش", "حذف"):
            return [_confirm(tools, st, "disable_ssl", {"domain": dom_all.group(1)}, "غیرفعال کردن SSL")]
        return [_confirm(tools, st, "enable_ssl", {"domain": dom_all.group(1)}, "فعال‌سازی SSL")]
    if has("دامنه", "وصل کن", "اضافه کن") and dom_all and has("وصل", "اضافه", "ثبت", "جدید") and not has("راهنما", "چطور", "چگونه"):
        return [ev("text", text=f"دامنه‌ی «{dom_all.group(1)}» را به اپ «{app}» وصل می‌کنم؛ بعدش باید رکوردهای DNS را در پنل ثبت‌کننده‌ی دامنه وارد کنی."),
                _confirm(tools, st, "add_domain", {"domain": dom_all.group(1), "name": app}, "افزودن دامنه")]
    dom = re.search(r"((?:[a-z0-9-]+\.)+[a-z]{2,})", m)
    if has("دامنه", "ایرنیک", "irnic", "dns") or (dom and has("وصل", "تنظیم")):
        g = execute(tools, "domain_guide", {"domain": dom.group(1) if dom else "example.ir"})
        if g["status"] != "ok":
            return [ev("error", text=_err(g))]
        return [ev("step", text="آماده‌سازی راهنمای دامنه"), ev("guide", title="اتصال دامنه (راهنمای ثابت)", items=g["result"]["steps"], note=g["result"]["limitation"])]
    if has("ری‌استارت", "ریستارت", "restart", "راه‌اندازی مجدد", "راه اندازی مجدد"):
        return [_confirm(tools, st, "restart_app", {"name": app}, "ری‌استارت اپ")]
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
    if has("لاگ", "log"):
        r = execute(tools, "get_logs", {"name": app, "lines": 25})
        _seen("get_logs", f"مشاهده‌ی لاگ‌های «{app}»", "موفق" if r["status"] == "ok" else "خطا")
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
                _seen("diagnose_app", f"عیب‌یابی اپ «{args.get('name', app)}»")
            elif x["status"] == "ok":
                le = list_event(call.function.name, x.get("result"))
                if le:
                    out.append(le)
                    _seen(call.function.name, LABELS.get(call.function.name, call.function.name))
            results.append({"role": "tool", "tool_call_id": call.id,
                            "content": json.dumps(x, ensure_ascii=False)})
        st["msgs"].extend(results)
    return out

def handle(msg, app, tools, st, url=""):
    msg = (msg or "")[:2000]
    st["url"] = url if isinstance(url, str) else ""
    if len(st.get("msgs", [])) > 40:      # تاریخچه‌ی LLM بی‌نهایت رشد نکند (حافظه/هزینه)
        st["msgs"] = st["msgs"][-24:]
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
