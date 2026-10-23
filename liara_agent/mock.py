"""کلاینت دمو (شبیه‌سازی، نه داده‌ی واقعی لیارا): سناریوی «خطای ۵۰۰ به‌خاطر کمبود RAM» + پنل کامل."""
import time
from .client import LiaraAPIError

OOM_LOGS = [
    "GET /products 200 85ms",
    "GET /cart 200 120ms",
    "<--- Last few GCs --->",
    "FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory",
    "GET /checkout 500 30ms",
    "Error: Internal Server Error at /checkout",
    "GET /checkout 500 28ms",
    "Container restarted (OOMKilled)",
    "GET /products 500 31ms",
]
OK_LOGS = ["Server listening on :3000", "GET /products 200 80ms", "GET /checkout 200 95ms"]

PLANS = [{"id": "small", "ram_mb": 512, "cpu": 0.5, "disk_gb": 5, "price": 100, "available": True, "region": "iran"},
         {"id": "medium", "ram_mb": 1024, "cpu": 1, "disk_gb": 10, "price": 200, "available": True, "region": "iran"},
         {"id": "large", "ram_mb": 2048, "cpu": 2, "disk_gb": 20, "price": 400, "available": True, "region": "iran"}]
DB_PLANS = [{"id": "db-small", "ram_mb": 512, "cpu": 0.5, "disk_gb": 5, "price": 120, "available": True, "region": "iran"},
            {"id": "db-medium", "ram_mb": 1024, "cpu": 1, "disk_gb": 10, "price": 240, "available": True, "region": "iran"}]


class MockClient:
    def __init__(self):
        self.plan, self.env = "small", {"NODE_ENV": "production"}
        self.token = "mock-token"
        self.apps_on = {"my-shop": True}
        self.apps = {"my-shop": {"project_id": "my-shop", "type": "node"}}
        self.dbs = {
            "db1": {"id": "db1", "DBId": "db1", "hostname": "shop-db", "type": "mysql", "status": "ACTIVE",
                    "scale": 1, "planID": "db-small", "version": "8.0", "publicNetwork": False,
                    "volumeSize": 5, "created_at": "2026-01-01", "port": 3306, "internalPort": 3306,
                    "username": "root", "dbName": "shop", "root_password": "mock-secret-never-show",
                    "node": {"_id": "n1", "host": "shop-db.liara"}},
            "db2": {"id": "db2", "DBId": "db2", "hostname": "cache-redis", "type": "redis", "status": "ACTIVE",
                    "scale": 0, "planID": "db-small", "version": "7.2", "publicNetwork": False,
                    "volumeSize": 1, "created_at": "2026-02-01", "port": 6379, "internalPort": 6379,
                    "username": "default", "dbName": "", "root_password": "mock-secret-never-show",
                    "node": {"_id": "n1", "host": "cache-redis.liara"}},
        }
        self.db_backups_data = {"db1": [{"name": "backup-2026-10-20.gz", "lastModified": "2026-10-20", "size": 2048000}], "db2": []}
        self.domains = [{"_id": "dom1", "name": "shop.ir", "status": "ACTIVE", "certificatesStatus": "ISSUED",
                         "project": {"project_id": "my-shop"}, "redirectTo": ""}]
        self._disks_data = [{"name": "uploads", "size": "5", "usage": "1.2"}]
        self.disk_backups_data = {"uploads": []}
        self._seq = 100

    def _bad(self): return self.plan == "small"

    # ---- اپ‌ها ----
    def list_projects(self):
        return [{"project_id": n, "status": "ACTIVE" if self.apps_on.get(n, True) else "STOPPED",
                 "planID": self.plan if n == "my-shop" else "small", "type": d.get("type", "node"),
                 "scale": 1 if self.apps_on.get(n, True) else 0} for n, d in self.apps.items()]

    def get_project(self, name):
        self._chk(name)
        on = self.apps_on.get(name, True)
        return {"_id": f"pid-{name}", "project_id": name, "status": "ACTIVE" if on else "STOPPED",
                "planID": self.plan if name == "my-shop" else "small", "type": self.apps[name].get("type", "node"),
                "scale": 1 if on else 0, "isDeployed": True, "defaultSubdomain": True,
                "created_at": "2026-01-01", "hourlyPrice": 100,
                "envs": [{"key": k, "value": v, "encrypted": False} for k, v in self.env.items()]}

    def create_project(self, name, platform, plan_id, network=""):
        if name in self.apps:
            raise LiaraAPIError(409, "اپی با این نام وجود دارد")
        self.apps[name] = {"project_id": name, "type": platform}
        self.apps_on[name] = True
        return {"ok": True}

    def delete_project(self, name):
        self._chk(name); del self.apps[name]; self.apps_on.pop(name, None); return {}

    def metrics(self, name, period="1h"):
        self._chk(name)
        return {"metrics": {"cpu": 38 if self._bad() else 22, "memory": 97 if self._bad() else 54, "disk": 31}}

    def metric_series(self, name, kind, since=None):
        self._chk(name)
        now = int(time.time())
        base = (97 if self._bad() else 54) / 100 * 512 * 1024 * 1024 if kind == "memory" else 0.19
        return {"result": [{"applet": name, "values": [[now - i * 300, str(base * (0.9 + 0.02 * i))] for i in range(12, 0, -1)]}]}

    def logs(self, name, since=None):
        self._chk(name)
        return {"logs": [{"message": m} for m in (OOM_LOGS if self._bad() else OK_LOGS)]}

    def restart(self, name):
        self._chk(name); return {"ok": True}

    def scale(self, name, on):
        self._chk(name); self.apps_on[name] = bool(on); return {"ok": True}

    def resize(self, name, plan):
        self._chk(name); self.plan = plan; return {"ok": True}

    def set_envs(self, name, envs):     # مثل لیارای واقعی: جایگزینی کامل
        self._chk(name); self.env = dict(envs); return {"ok": True}

    def events(self, name):
        self._chk(name)
        return {"events": [{"type": "OOMKilled", "message": "کانتینر به‌خاطر کمبود حافظه ری‌استارت شد", "created_at": "2026-10-23 05:01"},
                           {"type": "Deployed", "message": "ریلیز v12 منتشر شد", "created_at": "2026-10-22 18:30"}] if self._bad()
                else [{"type": "Deployed", "message": "ریلیز v13 منتشر شد", "created_at": "2026-10-23 06:10"}]}

    def releases(self, name):
        self._chk(name)
        return {"total": 2, "currentRelease": "v12", "releases": [
            {"tag": "v12", "state": "READY", "createdAt": "2026-10-22 18:30"},
            {"tag": "v11", "state": "READY", "createdAt": "2026-10-20 10:00"}]}

    def disks(self, project):
        return {"disks": list(self._disks_data)}

    def create_disk(self, name, disk_name, size):
        self._chk(name); self._disks_data.append({"name": disk_name, "size": str(size), "usage": "0"}); return {}

    def resize_disk(self, name, disk_name, size):
        self._chk(name)
        for d in self._disks_data:
            if d["name"] == disk_name:
                d["size"] = str(size)
        return {}

    def delete_disk(self, project, disk_name):
        self._disks_data = [d for d in self._disks_data if d["name"] != disk_name]; return {}

    def disk_backups(self, project, disk_name):
        return {"backups": self.disk_backups_data.get(disk_name, [])}

    def create_disk_backup(self, project, disk_name):
        self._seq += 1
        self.disk_backups_data.setdefault(disk_name, []).append({"name": f"disk-backup-{self._seq}.tar", "size": 1048576})
        return {}

    def download_disk_backup(self, project, disk_name, backup_name):
        return {"link": f"https://example.invalid/mock-download/{backup_name}?demo=1"}

    def app_toggle(self, project, feature, on):
        return {"ok": True}

    def networks(self):
        return [{"_id": "net1", "name": "default"}]

    # ---- حساب/کاتالوگ ----
    def me(self, fresh=False):
        return {"user": {"fullname": "کاربر دمو", "email": "demo@example.com", "balance": 125000},
                "plans": {}, "databaseVersions": {}, "defaultDatabaseVersions": {}}

    def catalog(self):
        return {"projects": PLANS, "databases": DB_PLANS, "database_versions": {},
                "default_database_versions": {"mysql": "8.0", "postgres": "16", "mongodb": "7.0", "redis": "7.2"}}

    def plans(self):
        return {"plans": PLANS}

    # ---- دیتابیس‌ها ----
    def list_databases(self):
        return list(self.dbs.values())

    def get_database(self, db_id):
        d = self.dbs.get(str(db_id))
        if not d:
            raise LiaraAPIError(404, "دیتابیس پیدا نشد")
        return dict(d)

    def create_database(self, hostname, db_type, plan_id, version="", public_network=False):
        self._seq += 1
        dbid = f"db{self._seq}"
        self.dbs[dbid] = {"id": dbid, "DBId": dbid, "hostname": hostname, "type": db_type, "status": "ACTIVE",
                          "scale": 1, "planID": plan_id, "version": version or "latest",
                          "publicNetwork": bool(public_network), "volumeSize": 5,
                          "created_at": "2026-10-23", "port": 3306, "internalPort": 3306,
                          "username": "root", "dbName": hostname, "root_password": "mock-secret-never-show",
                          "node": {"_id": "n1", "host": f"{hostname}.liara"}}
        self.db_backups_data[dbid] = []
        return {"databaseID": dbid}

    def delete_database(self, db_id):
        self.dbs.pop(str(db_id), None); return {}

    def scale_database(self, db_id, on):
        d = self.get_database(db_id)
        self.dbs[str(db_id)]["scale"] = 1 if on else 0
        self.dbs[str(db_id)]["status"] = "ACTIVE" if on else "STOPPED"
        return {}

    def resize_database(self, db_id, plan_id):
        self.get_database(db_id); self.dbs[str(db_id)]["planID"] = plan_id; return {}

    def db_backups(self, db_id):
        return {"backups": self.db_backups_data.get(str(db_id), [])}

    def create_db_backup(self, db_id):
        self._seq += 1
        self.db_backups_data.setdefault(str(db_id), []).append(
            {"name": f"backup-{self._seq}.gz", "lastModified": "2026-10-23", "size": 1024000})
        return {}

    def download_db_backup(self, db_id, backup_name):
        return {"link": f"https://example.invalid/mock-download/{backup_name}?demo=1"}

    def db_public_network(self, db_id, on):
        self.get_database(db_id); self.dbs[str(db_id)]["publicNetwork"] = bool(on); return {}

    def db_control_panel(self, db_id, on):
        return {"controlPanelID": f"cp-{db_id}" if on else ""}

    def db_metrics(self, db_id):
        self.get_database(db_id)
        return {"metrics": {"cpu": 21, "memory": 43, "disk": 18}}

    def db_events(self, ref):
        return {"events": [{"type": "Backup", "message": "بکاپ خودکار گرفته شد", "created_at": "2026-10-23 03:00"}]}

    # ---- دامنه‌ها ----
    def list_domains(self):
        return list(self.domains)

    def create_domain(self, domain, project):
        self._seq += 1
        self.domains.append({"_id": f"dom{self._seq}", "name": domain, "status": "PENDING",
                             "certificatesStatus": "NONE", "project": {"project_id": project}, "redirectTo": ""})
        return {"domain": {"_id": f"dom{self._seq}"}}

    def set_domain_project(self, domain_id, project_id):
        for d in self.domains:
            if d["_id"] == str(domain_id):
                d["project"] = {"project_id": str(project_id).removeprefix("pid-")}
        return {}

    def check_domain(self, domain_id):
        return {"verified": True, "message": "(دمو) DNS به لیارا اشاره می‌کند"}

    def enable_ssl(self, domain):
        for d in self.domains:
            if d["name"] == domain:
                d["certificatesStatus"] = "ISSUED"
        return {"code": "OK"}

    def disable_ssl(self, domain_id):
        for d in self.domains:
            if d["_id"] == str(domain_id):
                d["certificatesStatus"] = "NONE"
        return {}

    def set_redirect(self, domain_id, to, status=301):
        for d in self.domains:
            if d["_id"] == str(domain_id):
                d["redirectTo"] = to
        return {}

    def delete_domain(self, domain_id):
        self.domains = [d for d in self.domains if d["_id"] != str(domain_id)]
        return {}

    def _chk(self, name):
        if name not in self.apps:
            raise LiaraAPIError(404, f"اپ «{name}» پیدا نشد")
