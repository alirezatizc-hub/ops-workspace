"""کلاینت API لیارا (فقط stdlib) — پوشش پنل: اپ‌ها، دیتابیس‌ها، دامنه‌ها، دیسک‌ها و حساب.

منبع تطبیق: مستندات رسمی https://developers.liara.ir و مخزن liara-cloud/openapi
(spec/paas.yaml, spec/dbaas.yaml, spec/me.yaml). ستون «verified» یعنی متد+مسیر در
مستندات رسمی دیده شده. verified=False یعنی تأیید نشده؛ پیش‌فرض غیرفعال است و فقط با
LIARA_ALLOW_UNVERIFIED=1 آزمایشی فراخوانی می‌شود.

نکته‌ها (بر اساس spec رسمی و رفتار مشاهده‌شده‌ی API):
- updateEnvs «جایگزینی کامل» است: هرچه در variables باشد کل مجموعه‌ی متغیرها می‌شود.
  پس tools قبل از ارسال، فهرست فعلی را می‌خواند و merge می‌کند.
- متریک رسمی (metrics/summary): هر مقدار جفت [timestamp, value] است؛ memoryUsage بر حسب
  بایت و cpuUsage بر حسب هسته (مجموع اپلت‌ها) گزارش می‌شود. تبدیل به درصد فقط نسبت به
  سقف پلن (از کاتالوگ GET /v1/me) انجام می‌شود؛ بدون پلنِ شناخته‌شده، درصد ساخته نمی‌شود.
- کاتالوگ پلن‌ها از GET /v1/me می‌آید: plans.projects و plans.databases نگاشت
  planID ← {CPU:{amount}=هسته, RAM:{amount}=گیگابایت, volume, price, available,...}.
"""
import json, os, re, time, urllib.error, urllib.parse, urllib.request
from .security import ValidationError, redact, validate_app_name, validate_id

DEFAULT_BASE = "https://api.liara.ir"   # آدرس پایه‌ی PaaS طبق spec رسمی فعلی liara-cloud/openapi/spec/paas.yaml
HOST_OK = re.compile(r"^(?:[a-z0-9-]+\.)*liara\.ir$")
MAX_BYTES = 2_000_000
METRIC_KINDS = ("cpu", "memory", "network-receive", "network-transmit")
APP_TOGGLES = {"zero-downtime": "zero_downtime", "default-subdomain": "default_subdomain",
               "fixed-ip": "fixed_ip", "read-only": "read_only"}

# key: (method, path, verified)
ENDPOINTS = {
    # ---- اپ‌ها (PaaS) ----
    "list_projects": ("GET",  "/v1/projects", True),
    "create_project": ("POST", "/v1/projects", True),                          # بدنه: {name, platform, planID[, network, readOnlyRootFilesystem]}
    "get_project":   ("GET",  "/v1/projects/{name}", True),                    # پاسخ: {"project": {...}} (تأییدشده)
    "delete_project": ("DELETE", "/v1/projects/{name}", True),
    "logs":          ("GET",  "/v1/projects/{name}/logs", True),               # پارامتر since اجباری
    "restart":       ("POST", "/v1/projects/{name}/actions/restart", True),
    "scale":         ("POST", "/v1/projects/{name}/actions/scale", True),      # بدنه: {"scale": 0|1} خاموش/روشن
    "resize":        ("POST", "/v1/projects/{name}/resize", True),             # بدنه: {"planID": "..."}
    # بدنه‌ی رسمی: {"project": str, "variables": [{"key","value"}]} — جایگزینی کامل است؛ tools قبلش merge می‌کند.
    "set_envs":      ("POST", "/v1/projects/update-envs", True),
    "metrics":       ("GET",  "/v1/projects/{name}/metrics/summary", True),    # رسمی: cpuUsage/memoryUsage/disksUsage
    "metric_series": ("GET",  "/v1/projects/{name}/metrics/{kind}", True),     # kind از METRIC_KINDS؛ پارامتر since اجباری
    "events":        ("GET",  "/v1/projects/{name}/events", True),
    "releases":      ("GET",  "/v1/projects/{name}/releases", True),
    "disks":         ("GET",  "/v1/projects/{id}/disks", True),                # با شناسه‌ی داخلی اپ (_id)
    "create_disk":   ("POST", "/v1/projects/{name}/disks", True),              # بدنه: {"name": ..., "size": "..."}
    "resize_disk":   ("POST", "/v1/projects/{name}/disks/{dname}/resize", True),
    "delete_disk":   ("DELETE", "/v1/projects/{id}/disks/{dname}", True),
    "disk_backups":  ("GET",  "/v1/projects/{id}/disks/{dname}/backups", True),
    "create_disk_backup": ("POST", "/v1/projects/{id}/disks/{dname}/backups", True),
    "download_disk_backup": ("POST", "/v1/projects/{id}/disks/{dname}/backups/{bname}/download", True),
    "app_toggle":    ("POST", "/v1/projects/{id}/{feature}/{status}", True),   # feature از APP_TOGGLES؛ status: enable|disable
    "networks":      ("GET",  "/v1/networks", False),                          # در spec منتشرشده نیست ← پیش‌فرض غیرفعال
    # ---- حساب و کاتالوگ پلن‌ها ----
    "me":            ("GET",  "/v1/me", True),                                 # کاربر + plans.{projects,databases} + نسخه‌های دیتابیس
    # ---- دیتابیس‌ها (DBaaS) ----
    "list_databases": ("GET",    "/v1/databases", True),                       # پاسخ: {"databases": [...]}
    "get_database":   ("GET",    "/v1/databases/{id}", True),                  # پاسخ: {"database": {...}} (شامل root_password؛ در tools پاک می‌شود)
    "create_database": ("POST",  "/v1/databases", True),                       # بدنه: {hostname, type, planID, version, publicNetwork}
    "delete_database": ("DELETE", "/v1/databases/{id}", True),
    "scale_database": ("POST",   "/v1/databases/{id}/actions/scale", True),    # {"scale": 0|1} خاموش/روشن
    "resize_database": ("POST",  "/v1/databases/{id}/resize", True),           # {"planID": "..."}
    "db_backups":     ("GET",    "/v1/databases/{id}/backups", True),
    "create_db_backup": ("POST", "/v1/databases/{id}/backups", True),
    "download_db_backup": ("POST", "/v1/databases/{id}/backups/{bname}/download", True),   # پاسخ: {"link": ...}
    "db_public_network": ("PATCH", "/v1/databases/{id}/public-network/{status}", True),
    "db_control_panel":  ("POST",  "/v1/databases/{id}/control-panel/{status}", True),
    "db_metrics":     ("GET",    "/v1/databases/{id}/metrics/summary", True),
    "db_events":      ("GET",    "/v1/databases/{id}/events", True),           # در spec پارامتر {name} است؛ همان شناسه/هاست ارسال می‌شود
    # ---- دامنه‌ها ----
    "list_domains":   ("GET",    "/v1/domains", True),                         # پاسخ: {"domains": [...]}
    "create_domain":  ("POST",   "/v1/domains", True),                         # {name, project, type: "PROJECT"}
    "set_domain_project": ("POST", "/v1/domains/set-project", True),           # {domainID, projectID}
    "check_domain":   ("GET",    "/v1/domains/{id}/check", True),
    "enable_ssl":     ("POST",   "/v1/domains/provision-ssl-certs", True),     # {domain}
    "disable_ssl":    ("POST",   "/v1/domains/{id}/ssl/disable", True),
    "set_redirect":   ("POST",   "/v1/domains/{id}/set-redirect", True),       # {redirectStatus: 301|302, redirectTo}
    "delete_domain":  ("DELETE", "/v1/domains/{id}", True),
}


class LiaraAPIError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message

    @property
    def unsupported(self) -> bool:
        return self.status in (404, 405, 501)


def _amount(node, *keys):
    """عدد را از شکل‌های مختلف کاتالوگ پلن بیرون می‌کشد: {RAM:{amount:1}} یا {RAM:1} یا کلید مستقیم."""
    for k in keys:
        v = node.get(k) if isinstance(node, dict) else None
        if isinstance(v, dict):
            v = v.get("amount", v.get("value"))
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            return float(v)
    return None


def normalize_plan(pid, p):
    """یک رکورد پلن کاتالوگ /v1/me ← قالب یکدست داخلی. RAM در کاتالوگ گیگابایت، CPU هسته است."""
    if not isinstance(p, dict):
        return None
    ram_gb = _amount(p, "RAM", "ram", "memory")
    cpu = _amount(p, "CPU", "cpu", "vcpu")
    disk = _amount(p, "volume", "disk", "storage")
    price = _amount(p, "price", "hourlyPrice")
    return {"id": str(pid), "ram_mb": ram_gb * 1024 if ram_gb else None, "cpu": cpu,
            "disk_gb": disk, "price": price,
            "available": p.get("available", True) is not False, "region": p.get("region", "")}


class LiaraClient:
    def __init__(self, token=None, team_id=None, base=None, timeout=20, _allow_any_base=False):
        self.token = (token or os.getenv("LIARA_API_TOKEN", "")).strip()
        self.team_id = (team_id or os.getenv("LIARA_TEAM_ID", "")).strip()
        base = (base or os.getenv("LIARA_API_BASE_URL", DEFAULT_BASE)).rstrip("/")
        self.timeout = timeout
        self._me_cache = (0.0, None)
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
        for k, v in path.items():       # ضد دستکاری مسیر: «name» نام اپ است، بقیه شناسه‌اند
            validate_app_name(v) if k == "name" else validate_id(v)
        url = self.base + tpl.format(**{k: urllib.parse.quote(v, safe="") for k, v in path.items()})
        q = dict(params or {})
        if self.team_id and not tpl.startswith("/v1/me"):
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
                   404: "منبع پیدا نشد", 409: "این عملیات با وضعیت فعلی منبع تداخل دارد",
                   429: "تعداد درخواست‌ها زیاد است"}.get(e.code, f"خطای API ({e.code})")
            raise LiaraAPIError(e.code, f"{msg}: {detail}" if detail and e.code not in (401, 403) else msg)
        except urllib.error.URLError as e:
            raise LiaraAPIError(0, f"اتصال به لیارا برقرار نشد: {redact(e.reason, self.token)}")
        if len(raw) > MAX_BYTES:
            raise LiaraAPIError(502, "پاسخ API بیش از حد بزرگ بود")
        try:
            return json.loads(raw.decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return {"text": raw.decode(errors="ignore")}

    # ---------------- اپ‌ها ----------------
    def list_projects(self):
        d = self._call("list_projects")
        return d.get("projects", []) if isinstance(d, dict) else d

    def get_project(self, name):
        d = self._call("get_project", name=name)
        return d.get("project", d) if isinstance(d, dict) else {}

    def create_project(self, name, platform, plan_id, network=""):
        body = {"name": name, "platform": platform, "planID": plan_id}
        if network:
            body["network"] = network
        return self._call("create_project", body=body)

    def delete_project(self, name): return self._call("delete_project", name=name)

    def logs(self, name, since=None):
        if since is None:
            t = int(time.time()) - 3600
            since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t)) if os.getenv("LIARA_LOGS_SINCE_FORMAT") == "iso" else str(t)
        return self._call("logs", {"since": since}, name=name)

    def restart(self, name): return self._call("restart", name=name)

    def scale(self, name, on: bool):
        return self._call("scale", body={"scale": 1 if on else 0}, name=name)

    def resize(self, name, plan): return self._call("resize", body={"planID": plan}, name=name)

    def set_envs(self, name, envs: dict):  # هشدار: جایگزینی کامل است؛ فراخواننده باید مجموعه‌ی کامل را بدهد
        return self._call("set_envs", body={"project": name, "variables": [{"key": k, "value": v} for k, v in envs.items()]})

    def metrics(self, name, period=None):   # spec رسمی پارامتری ندارد؛ period عمداً ارسال نمی‌شود
        return self._call("metrics", name=name)

    def metric_series(self, name, kind, since=None):
        if kind not in METRIC_KINDS:
            raise ValidationError("نوع متریک نامعتبر است")
        if since is None:
            since = int(time.time()) - 3600
        return self._call("metric_series", {"since": int(since)}, name=name, kind=kind)

    def events(self, name): return self._call("events", name=name)
    def releases(self, name): return self._call("releases", name=name)

    def _pid(self, project):  # شناسه‌ی داخلی اپ برای مسیرهای دیسک/تنظیمات
        return str(project.get("_id") or project.get("id") or "")

    def disks(self, project):
        d = self._call("disks", id=self._pid(project))
        return d.get("disks", d) if isinstance(d, dict) else d

    def create_disk(self, name, disk_name, size):
        return self._call("create_disk", body={"name": disk_name, "size": str(size)}, name=name)

    def resize_disk(self, name, disk_name, size):
        return self._call("resize_disk", body={"size": str(size)}, name=name, dname=disk_name)

    def delete_disk(self, project, disk_name):
        return self._call("delete_disk", id=self._pid(project), dname=disk_name)

    def disk_backups(self, project, disk_name):
        d = self._call("disk_backups", id=self._pid(project), dname=disk_name)
        return d.get("backups", d) if isinstance(d, dict) else d

    def create_disk_backup(self, project, disk_name):
        return self._call("create_disk_backup", id=self._pid(project), dname=disk_name)

    def download_disk_backup(self, project, disk_name, backup_name):
        return self._call("download_disk_backup", id=self._pid(project), dname=disk_name, bname=backup_name)

    def app_toggle(self, project, feature, on: bool):
        if feature not in APP_TOGGLES:
            raise ValidationError("تنظیم نامعتبر است")
        return self._call("app_toggle", id=self._pid(project), feature=feature,
                          status="enable" if on else "disable")

    def networks(self):
        d = self._call("networks")
        return d.get("networks", d) if isinstance(d, dict) else d

    # ---------------- حساب و پلن‌ها ----------------
    def me(self, fresh=False):
        t, cached = self._me_cache
        if fresh or cached is None or time.time() - t > 600:   # کش ۱۰ دقیقه‌ای (کاتالوگ بزرگ است)
            cached = self._call("me")
            self._me_cache = (time.time(), cached)
        return cached

    def catalog(self):
        """پلن‌های یکدست‌شده از /v1/me: {projects, databases, database_versions, default_database_versions}."""
        d = self.me()
        plans = d.get("plans", {}) if isinstance(d, dict) else {}
        def conv(group):
            g = plans.get(group, {})
            items = [normalize_plan(k, v) for k, v in g.items()] if isinstance(g, dict) else []
            return sorted((p for p in items if p), key=lambda p: (p["price"] is None, p["price"] or 0, p["ram_mb"] or 0))
        return {"projects": conv("projects"), "databases": conv("databases"),
                "database_versions": d.get("databaseVersions", {}) if isinstance(d, dict) else {},
                "default_database_versions": d.get("defaultDatabaseVersions", {}) if isinstance(d, dict) else {}}

    def plans(self):    # سازگار با مصرف‌کننده‌های قبلی: {"plans": [{id, ram_mb, ...}]}
        return {"plans": self.catalog()["projects"]}

    # ---------------- دیتابیس‌ها ----------------
    def list_databases(self):
        d = self._call("list_databases")
        return d.get("databases", []) if isinstance(d, dict) else d

    def get_database(self, db_id):
        d = self._call("get_database", id=str(db_id))
        return d.get("database", d) if isinstance(d, dict) else {}

    def create_database(self, hostname, db_type, plan_id, version="", public_network=False):
        body = {"hostname": hostname, "type": db_type, "planID": plan_id, "publicNetwork": bool(public_network)}
        if version:
            body["version"] = str(version)
        return self._call("create_database", body=body)

    def delete_database(self, db_id): return self._call("delete_database", id=str(db_id))

    def scale_database(self, db_id, on: bool):
        return self._call("scale_database", body={"scale": 1 if on else 0}, id=str(db_id))

    def resize_database(self, db_id, plan_id):
        return self._call("resize_database", body={"planID": plan_id}, id=str(db_id))

    def db_backups(self, db_id):
        d = self._call("db_backups", id=str(db_id))
        return d.get("backups", d) if isinstance(d, dict) else d

    def create_db_backup(self, db_id): return self._call("create_db_backup", id=str(db_id))

    def download_db_backup(self, db_id, backup_name):
        return self._call("download_db_backup", id=str(db_id), bname=str(backup_name))

    def db_public_network(self, db_id, on: bool):
        return self._call("db_public_network", id=str(db_id), status="enable" if on else "disable")

    def db_control_panel(self, db_id, on: bool):
        return self._call("db_control_panel", id=str(db_id), status="enable" if on else "disable")

    def db_metrics(self, db_id): return self._call("db_metrics", id=str(db_id))
    def db_events(self, ref): return self._call("db_events", id=str(ref))

    # ---------------- دامنه‌ها ----------------
    def list_domains(self):
        d = self._call("list_domains")
        return d.get("domains", []) if isinstance(d, dict) else d

    def create_domain(self, domain, project):
        return self._call("create_domain", body={"name": domain, "project": project, "type": "PROJECT"})

    def set_domain_project(self, domain_id, project_id):
        return self._call("set_domain_project", body={"domainID": str(domain_id), "projectID": str(project_id)})

    def check_domain(self, domain_id): return self._call("check_domain", id=str(domain_id))
    def enable_ssl(self, domain): return self._call("enable_ssl", body={"domain": domain})
    def disable_ssl(self, domain_id): return self._call("disable_ssl", id=str(domain_id))

    def set_redirect(self, domain_id, to, status=301):
        return self._call("set_redirect", body={"redirectStatus": int(status), "redirectTo": to}, id=str(domain_id))

    def delete_domain(self, domain_id): return self._call("delete_domain", id=str(domain_id))


def make_client():
    if os.getenv("LIARA_MOCK") == "1":
        from .mock import MockClient
        return MockClient()
    return LiaraClient()
