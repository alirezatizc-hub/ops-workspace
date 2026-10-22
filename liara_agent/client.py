"""کلاینت API لیارا (فقط stdlib).

منبع تطبیق: مستندات رسمی https://developers.liara.ir و فایل liara-cloud/openapi/spec/paas.yaml
(مطالعه‌شده در تاریخ ساخت). ستون «verified» یعنی متد+مسیر در مستندات رسمی دیده شده.
verified=False یعنی تأیید نشده؛ پیش‌فرض غیرفعال است و فقط با LIARA_ALLOW_UNVERIFIED=1 آزمایشی فراخوانی می‌شود.
"""
import json, os, re, time, urllib.error, urllib.parse, urllib.request
from .security import ValidationError, redact, validate_app_name

DEFAULT_BASE = "https://api.iran.liara.ir"   # نمونه‌ی مستندات رسمی؛ spec رسمی https://api.liara.ir را هم ذکر می‌کند
HOST_OK = re.compile(r"^(?:[a-z0-9-]+\.)*liara\.ir$")
MAX_BYTES = 2_000_000

# key: (method, path, verified)
ENDPOINTS = {
    "list_projects": ("GET",  "/v1/projects", True),
    "get_project":   ("GET",  "/v1/projects/{name}", True),                  # پاسخ: {"project": {...}} (تأییدشده)
    "logs":          ("GET",  "/v1/projects/{name}/logs", True),             # پارامتر since اجباری؛ فرمت مقدار و قالب پاسخ تأیید نشد
    "restart":       ("POST", "/v1/projects/{name}/actions/restart", True),
    "resize":        ("POST", "/v1/projects/{name}/resize", True),           # بدنه: {"planID": "..."}
    # بدنه‌ی رسمی: {"project": str, "variables": [{"key","value"}]}؛ اما merge یا replace بودنش مستند نیست
    # (ممکن است سایر envها پاک شوند) ← عمداً غیرفعال تا تأیید شود.
    "set_envs":      ("POST", "/v1/projects/update-envs", False),
    "metrics":       ("GET",  "/v1/projects/{name}/metrics/summary", True),  # رسمی (getAppSummaryReports): cpuUsage/memoryUsage/disksUsage؛ بدون پارامتر query
    "plans":         ("GET",  "/v1/plans", False),                           # در PaaS رسمی وجود ندارد (حدس)؛ فقط changePlan با planID هست
}


class LiaraAPIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message

    @property
    def unsupported(self) -> bool:
        return self.status in (404, 405, 501)


class LiaraClient:
    def __init__(self, token=None, team_id=None, base=None, timeout=20, _allow_any_base=False):
        self.token = (token or os.getenv("LIARA_API_TOKEN", "")).strip()
        self.team_id = (team_id or os.getenv("LIARA_TEAM_ID", "")).strip()
        base = (base or os.getenv("LIARA_API_BASE_URL", DEFAULT_BASE)).rstrip("/")
        self.timeout = timeout
        if not self.token:
            raise LiaraAPIError(401, "توکن API تنظیم نشده (متغیر محیطی LIARA_API_TOKEN). از console.liara.ir/API بسازید.")
        if re.search(r"\s", self.token):
            raise LiaraAPIError(401, "توکن API نامعتبر است (کاراکتر فاصله/خط جدید)")
        u = urllib.parse.urlsplit(base)
        if not _allow_any_base and (u.scheme != "https" or not HOST_OK.match(u.hostname or "")):
            raise ValidationError("آدرس پایه فقط می‌تواند یک دامنه‌ی https زیر liara.ir باشد (جلوگیری از ارسال توکن به سرور دیگر)")
        self.base = base

    def _call(self, key, params=None, body=None, **path):
        method, tpl, verified = ENDPOINTS[key]
        if not verified and os.getenv("LIARA_ALLOW_UNVERIFIED") != "1":
            raise LiaraAPIError(501, f"مسیر «{key}» در مستندات رسمی لیارا تأیید نشده و غیرفعال است "
                                     "(برای تست آزمایشی LIARA_ALLOW_UNVERIFIED=1)")
        for v in path.values():
            validate_app_name(v)
        url = self.base + tpl.format(**{k: urllib.parse.quote(v, safe="") for k, v in path.items()})
        q = dict(params or {})
        if self.team_id:
            q["teamID"] = self.team_id       # طبق مستندات رسمی برای حساب تیمی
        if q:
            url += "?" + urllib.parse.urlencode(q)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
            "Accept": "application/json", "User-Agent": "liara-sre-agent"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                raw = r.read(MAX_BYTES + 1)
        except urllib.error.HTTPError as e:
            detail = redact(e.read(500).decode(errors="ignore"), self.token)
            msg = {401: "توکن نامعتبر یا منقضی است", 403: "دسترسی کافی ندارید",
                   404: "منبع پیدا نشد", 429: "تعداد درخواست‌ها زیاد است"}.get(e.code, f"خطای API ({e.code})")
            raise LiaraAPIError(e.code, f"{msg}: {detail}" if detail and e.code not in (401, 403) else msg)
        except urllib.error.URLError as e:
            raise LiaraAPIError(0, f"اتصال به لیارا برقرار نشد: {redact(e.reason, self.token)}")
        if len(raw) > MAX_BYTES:
            raise LiaraAPIError(502, "پاسخ API بیش از حد بزرگ بود")
        try:
            return json.loads(raw.decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return {"text": raw.decode(errors="ignore")}

    def list_projects(self):
        d = self._call("list_projects")
        return d.get("projects", []) if isinstance(d, dict) else d

    def get_project(self, name):
        d = self._call("get_project", name=name)
        return d.get("project", d) if isinstance(d, dict) else {}

    def logs(self, name, since=None):
        if since is None:
            t = int(time.time()) - 3600
            since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if os.getenv("LIARA_LOGS_SINCE_FORMAT") == "iso" else str(t)
        return self._call("logs", {"since": since}, name=name)

    def restart(self, name): return self._call("restart", name=name)
    def resize(self, name, plan): return self._call("resize", body={"planID": plan}, name=name)

    def set_envs(self, name, envs: dict):  # بدنه طبق مستندات رسمی؛ ولی معنای merge/replace نامشخص ← پیش‌فرض غیرفعال
        return self._call("set_envs", body={"project": name, "variables": [{"key": k, "value": v} for k, v in envs.items()]})

    def metrics(self, name, period=None):   # spec رسمی پارامتری ندارد؛ period عمداً ارسال نمی‌شود
        return self._call("metrics", name=name)
    def plans(self): return self._call("plans")


def make_client():
    if os.getenv("LIARA_MOCK") == "1":
        from .mock import MockClient
        return MockClient()
    return LiaraClient()
