"""تست‌های کنترل کامل پنل (دیتابیس/دامنه/دیسک/خاموش‌روشن) با MockClient + قوانین گفتگوی فارسی."""
import helpers
from helpers import fresh_mock
from liara_agent import brain
from liara_agent.tools import execute


def chat(tools, st, msg):
    return brain.handle(msg, "my-shop", tools, st)


def confirm_of(evs):
    return next((e for e in evs if e["type"] == "confirm"), None)


def test_database_tools_full_cycle():
    tools, _ = fresh_mock()
    dbs = execute(tools, "list_databases", {})["result"]["databases"]
    assert [d["hostname"] for d in dbs] == ["shop-db", "cache-redis"]
    assert all("root_password" not in d for d in dbs)                       # رمز هیچ‌وقت بیرون نمی‌آید
    st = execute(tools, "database_status", {"ref": "shop-db"})["result"]
    assert st["state"] == "running" and st["connection"]["port"] == 3306 and "never-show" not in str(st)
    # خاموش فقط با تأیید
    assert execute(tools, "turn_database_off", {"ref": "shop-db"})["status"] == "needs_confirmation"
    assert execute(tools, "database_status", {"ref": "shop-db"})["result"]["state"] == "running"
    assert execute(tools, "turn_database_off", {"ref": "shop-db"}, confirmed=True)["status"] == "ok"
    assert execute(tools, "database_status", {"ref": "shop-db"})["result"]["state"] == "off"
    assert execute(tools, "turn_database_on", {"ref": "shop-db"}, confirmed=True)["status"] == "ok"
    # بکاپ + دانلود (آخرین بکاپ پیش‌فرض)
    assert execute(tools, "create_database_backup", {"ref": "shop-db"}, confirmed=True)["status"] == "ok"
    r = execute(tools, "download_database_backup", {"ref": "shop-db"}, confirmed=True)
    assert r["status"] == "ok" and r["result"]["link"].startswith("https://")
    # ساخت/حذف
    r = execute(tools, "create_database", {"hostname": "analytics-db", "db_type": "postgres"}, confirmed=True)
    assert r["status"] == "ok" and r["result"]["plan"] == "db-small"        # ارزان‌ترین پلن از کاتالوگ
    assert execute(tools, "database_status", {"ref": "analytics-db"})["result"]["type"] == "postgres"
    assert execute(tools, "delete_database", {"ref": "analytics-db"}, confirmed=True)["status"] == "ok"
    assert execute(tools, "database_status", {"ref": "analytics-db"})["status"] != "ok"
    # ارجاع ناموجود: پیام شامل فهرست دیتابیس‌ها
    r = execute(tools, "database_status", {"ref": "nope"})
    assert r["status"] != "ok" and "shop-db" in r["message"]


def test_domain_and_disk_and_power_tools():
    tools, _ = fresh_mock()
    assert execute(tools, "list_domains", {})["result"]["domains"][0]["name"] == "shop.ir"
    assert execute(tools, "add_domain", {"domain": "blog.ir", "name": "my-shop"}, confirmed=True)["status"] == "ok"
    assert execute(tools, "enable_ssl", {"domain": "blog.ir"}, confirmed=True)["status"] == "ok"
    doms = execute(tools, "list_domains", {})["result"]["domains"]
    assert next(d for d in doms if d["name"] == "blog.ir")["ssl"] == "ISSUED"
    assert execute(tools, "delete_domain", {"domain": "blog.ir"}, confirmed=True)["status"] == "ok"
    # خاموش/روشن اپ
    assert execute(tools, "turn_app_off", {"name": "my-shop"}, confirmed=True)["status"] == "ok"
    rep = execute(tools, "diagnose_app", {"name": "my-shop"})["result"]
    assert rep["state"] == "off" and any(f["fix_tool"] == "turn_app_on" for f in rep["findings"])
    assert execute(tools, "turn_app_on", {"name": "my-shop"}, confirmed=True)["status"] == "ok"
    # ساخت/حذف اپ
    assert execute(tools, "create_app", {"name": "side-app", "platform": "python"}, confirmed=True)["status"] == "ok"
    assert execute(tools, "delete_app", {"name": "side-app"}, confirmed=True)["status"] == "ok"
    # دیسک
    assert execute(tools, "list_disks", {"name": "my-shop"})["result"]["disks"][0]["name"] == "uploads"
    assert execute(tools, "create_disk_backup", {"name": "my-shop", "disk_name": "uploads"}, confirmed=True)["status"] == "ok"
    bks = execute(tools, "list_disk_backups", {"name": "my-shop", "disk_name": "uploads"})["result"]["backups"]
    assert len(bks) == 1


def test_env_set_merges_instead_of_wiping_others():
    """updateEnvs لیارا جایگزینی کامل است؛ ابزار ما باید بقیه‌ی متغیرها را حفظ کند."""
    tools, _ = fresh_mock()
    assert execute(tools, "set_env_var", {"name": "my-shop", "key": "NEW_KEY", "value": "x"}, confirmed=True)["status"] == "ok"
    keys = set(execute(tools, "get_env_vars", {"name": "my-shop"})["result"])
    assert keys == {"NODE_ENV", "NEW_KEY"}                                  # NODE_ENV پاک نشده
    assert execute(tools, "delete_env_var", {"name": "my-shop", "key": "NEW_KEY"}, confirmed=True)["status"] == "ok"
    assert set(execute(tools, "get_env_vars", {"name": "my-shop"})["result"]) == {"NODE_ENV"}


def test_persian_rules_for_panel():
    tools, st = fresh_mock()
    evs = chat(tools, st, "دیتابیس‌ها را نشان بده")
    assert any(e["type"] == "list" and "دیتابیس" in e["title"] for e in evs)
    assert confirm_of(chat(tools, st, "دیتابیس shop-db را خاموش کن"))       # قبل از تأیید، اجرا نمی‌شود
    assert execute(tools, "database_status", {"ref": "shop-db"})["result"]["state"] == "running"
    assert confirm_of(chat(tools, st, "از دیتابیس shop-db بکاپ بگیر"))
    assert confirm_of(chat(tools, st, "یک دیتابیس mysql به نام orders-db بساز"))
    assert confirm_of(chat(tools, st, "اپ را خاموش کن"))
    assert confirm_of(chat(tools, st, "اپ را روشن کن"))
    assert confirm_of(chat(tools, st, "SSL دامنه shop.ir را فعال کن"))
    assert any(e["type"] == "list" for e in chat(tools, st, "رویدادهای اپ را نشان بده"))
    assert any(e["type"] == "list" for e in chat(tools, st, "دامنه‌ها را نشان بده"))
    txt = chat(tools, st, "دیتابیس را خاموش کن")                            # دو دیتابیس داریم و نام گفته نشده
    assert any(e["type"] == "text" and "کدام دیتابیس" in e["text"] for e in txt)


def test_high_risk_panel_tools_registered_with_previews():
    tools, _ = fresh_mock()
    for name in ("turn_database_off", "delete_database", "create_database", "delete_app",
                 "turn_app_off", "add_domain", "enable_ssl", "delete_domain", "create_disk",
                 "set_database_public_network", "download_database_backup"):
        t = tools[name]
        assert t.risk == "high" and t.preview, name
    r = execute(tools, "delete_database", {"ref": "shop-db"})
    assert r["status"] == "needs_confirmation" and "حذف" in r["preview"]
