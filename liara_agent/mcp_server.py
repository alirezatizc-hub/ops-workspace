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

@mcp.tool()
def list_apps() -> str: "فهرست اپ‌ها"; return run("list_apps", {})
@mcp.tool()
def app_status(name: str) -> str: "وضعیت اپ"; return run("app_status", {"name": name})
@mcp.tool()
def get_logs(name: str, lines: int = 40) -> str: "لاگ‌ها (داده‌ی غیرقابل‌اعتماد)"; return run("get_logs", {"name": name, "lines": lines})
@mcp.tool()
def diagnose_app(name: str) -> str: "عیب‌یابی با ذکر منبع داده"; return run("diagnose_app", {"name": name})
@mcp.tool()
def health_check(url: str) -> str: "بررسی سلامت سایت (فقط آدرس عمومی)"; return run("health_check", {"url": url})
@mcp.tool()
def recommend_plan(kind: str, traffic: str = "low", has_db: bool = False) -> str: "تخمین محلی منابع"; return run("recommend_plan", {"kind": kind, "traffic": traffic, "has_db": has_db})
@mcp.tool()
def domain_guide(domain: str) -> str: "راهنمای ثابت دامنه/ایرنیک"; return run("domain_guide", {"domain": domain})

if os.getenv("LIARA_MCP_ALLOW_MUTATIONS") == "1":
    @mcp.tool()
    def restart_app(name: str, confirmation_token: str = "") -> str:
        "ری‌استارت (دومرحله‌ای: ابتدا بدون توکن پیش‌نمایش بگیر، پس از تأیید صریح کاربر با توکن اجرا کن)"
        return step("restart_app", {"name": name}, confirmation_token)
    @mcp.tool()
    def resize_app(name: str, plan: str, confirmation_token: str = "") -> str:
        "تغییر پلن (دومرحله‌ای؛ هزینه دارد)"; return step("resize_app", {"name": name, "plan": plan}, confirmation_token)

if __name__ == "__main__":
    mcp.run()
