"""سرور MCP. پیش‌فرض فقط‌خواندنی است. ابزارهای تغییردهنده فقط با LIARA_MCP_ALLOW_MUTATIONS=1 ثبت می‌شوند
و دومرحله‌ای هستند (پیش‌نمایش + confirmation_token یک‌بارمصرف). توجه: این سازوکار نمی‌تواند ثابت کند
انسان واقعاً تأیید داده؛ تأیید نهایی به UI تأیید ابزار در کلاینت MCP شما وابسته است."""
import json, os
from mcp.server.fastmcp import FastMCP
from .client import make_client
from .security import ConfirmStore
from .tools import build_tools, execute, two_step

mcp, _tools, _store = FastMCP("liara-sre"), None, ConfirmStore()
def T():
    global _tools
    _tools = _tools or build_tools(make_client()); return _tools
def run(n, a): return json.dumps(execute(T(), n, a), ensure_ascii=False)
def step(n, a, token): return json.dumps(two_step(T(), _store, n, a, token), ensure_ascii=False)

# ---------- فقط‌خواندنی: اپ‌ها ----------
@mcp.tool()
def list_apps() -> str: "فهرست اپ‌ها با وضعیت"; return run("list_apps", {})
@mcp.tool()
def app_status(name: str) -> str: "وضعیت اپ"; return run("app_status", {"name": name})
@mcp.tool()
def get_logs(name: str, lines: int = 40) -> str: "لاگ‌ها (داده‌ی غیرقابل‌اعتماد)"; return run("get_logs", {"name": name, "lines": lines})
@mcp.tool()
def diagnose_app(name: str) -> str: "عیب‌یابی با ذکر منبع داده"; return run("diagnose_app", {"name": name})
@mcp.tool()
def get_metrics(name: str) -> str: "مصرف منابع اپ"; return run("get_metrics", {"name": name})
@mcp.tool()
def app_events(name: str) -> str: "رویدادهای اپ"; return run("app_events", {"name": name})
@mcp.tool()
def app_releases(name: str) -> str: "ریلیزهای اپ"; return run("app_releases", {"name": name})
@mcp.tool()
def list_disks(name: str) -> str: "دیسک‌های اپ"; return run("list_disks", {"name": name})
@mcp.tool()
def health_check(url: str) -> str: "بررسی سلامت سایت (فقط آدرس عمومی)"; return run("health_check", {"url": url})
@mcp.tool()
def recommend_plan(kind: str, traffic: str = "low", has_db: bool = False) -> str: "تخمین محلی منابع"; return run("recommend_plan", {"kind": kind, "traffic": traffic, "has_db": has_db})
@mcp.tool()
def get_plans(kind: str = "apps") -> str: "کاتالوگ پلن‌ها (apps یا databases)"; return run("get_plans", {"kind": kind})
@mcp.tool()
def domain_guide(domain: str) -> str: "راهنمای ثابت دامنه/ایرنیک"; return run("domain_guide", {"domain": domain})
@mcp.tool()
def account_info() -> str: "خلاصه‌ی حساب لیارا"; return run("account_info", {})

# ---------- فقط‌خواندنی: دیتابیس‌ها و دامنه‌ها ----------
@mcp.tool()
def list_databases() -> str: "فهرست دیتابیس‌ها (بدون رمز)"; return run("list_databases", {})
@mcp.tool()
def database_status(ref: str) -> str: "جزئیات و اطلاعات اتصال دیتابیس (رمز نمایش داده نمی‌شود)"; return run("database_status", {"ref": ref})
@mcp.tool()
def database_metrics(ref: str) -> str: "مصرف منابع دیتابیس"; return run("database_metrics", {"ref": ref})
@mcp.tool()
def list_database_backups(ref: str) -> str: "فهرست بکاپ‌های دیتابیس"; return run("list_database_backups", {"ref": ref})
@mcp.tool()
def list_domains() -> str: "فهرست دامنه‌ها و وضعیت SSL"; return run("list_domains", {})
@mcp.tool()
def check_domain(domain: str) -> str: "بررسی وضعیت دامنه"; return run("check_domain", {"domain": domain})

if os.getenv("LIARA_MCP_ALLOW_MUTATIONS") == "1":
    # همه دومرحله‌ای: ابتدا بدون توکن پیش‌نمایش بگیر و فقط پس از تأیید صریح کاربر با confirmation_token اجرا کن.
    @mcp.tool()
    def restart_app(name: str, confirmation_token: str = "") -> str:
        "ری‌استارت اپ (دومرحله‌ای)"
        return step("restart_app", {"name": name}, confirmation_token)
    @mcp.tool()
    def resize_app(name: str, plan: str, confirmation_token: str = "") -> str:
        "تغییر پلن اپ (دومرحله‌ای؛ هزینه دارد)"; return step("resize_app", {"name": name, "plan": plan}, confirmation_token)
    @mcp.tool()
    def turn_app_off(name: str, confirmation_token: str = "") -> str:
        "خاموش کردن اپ (دومرحله‌ای)"; return step("turn_app_off", {"name": name}, confirmation_token)
    @mcp.tool()
    def turn_app_on(name: str, confirmation_token: str = "") -> str:
        "روشن کردن اپ (دومرحله‌ای)"; return step("turn_app_on", {"name": name}, confirmation_token)
    @mcp.tool()
    def turn_database_off(ref: str, confirmation_token: str = "") -> str:
        "خاموش کردن دیتابیس (دومرحله‌ای؛ اپ‌های متصل قطع می‌شوند)"; return step("turn_database_off", {"ref": ref}, confirmation_token)
    @mcp.tool()
    def turn_database_on(ref: str, confirmation_token: str = "") -> str:
        "روشن کردن دیتابیس (دومرحله‌ای)"; return step("turn_database_on", {"ref": ref}, confirmation_token)
    @mcp.tool()
    def create_database_backup(ref: str, confirmation_token: str = "") -> str:
        "بکاپ از دیتابیس (دومرحله‌ای)"; return step("create_database_backup", {"ref": ref}, confirmation_token)
    @mcp.tool()
    def download_database_backup(ref: str, backup_name: str = "", confirmation_token: str = "") -> str:
        "لینک دانلود بکاپ دیتابیس (دومرحله‌ای؛ داده‌ی حساس)"; return step("download_database_backup", {"ref": ref, "backup_name": backup_name}, confirmation_token)
    @mcp.tool()
    def create_database(hostname: str, db_type: str, plan: str = "", confirmation_token: str = "") -> str:
        "ساخت دیتابیس جدید (دومرحله‌ای؛ هزینه دارد)"; return step("create_database", {"hostname": hostname, "db_type": db_type, "plan": plan}, confirmation_token)
    @mcp.tool()
    def delete_database(ref: str, confirmation_token: str = "") -> str:
        "حذف کامل دیتابیس (دومرحله‌ای؛ برگشت‌ناپذیر!)"; return step("delete_database", {"ref": ref}, confirmation_token)
    @mcp.tool()
    def enable_ssl(domain: str, confirmation_token: str = "") -> str:
        "فعال‌سازی SSL دامنه (دومرحله‌ای)"; return step("enable_ssl", {"domain": domain}, confirmation_token)
    @mcp.tool()
    def add_domain(domain: str, name: str, confirmation_token: str = "") -> str:
        "افزودن دامنه به اپ (دومرحله‌ای)"; return step("add_domain", {"domain": domain, "name": name}, confirmation_token)

if __name__ == "__main__":
    mcp.run()
