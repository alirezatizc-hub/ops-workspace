"""کلاینت دمو (شبیه‌سازی، نه داده‌ی واقعی لیارا): سناریوی «خطای ۵۰۰ به‌خاطر کمبود RAM»."""
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


class MockClient:
    def __init__(self):
        self.plan, self.env = "small", {"NODE_ENV": "production"}
        self.token = "mock-token"

    def _bad(self): return self.plan == "small"

    def list_projects(self):
        return [{"project_id": "my-shop", "status": "RUNNING", "planID": self.plan, "type": "node"}]

    def get_project(self, name):
        self._chk(name)
        return {"project_id": name, "status": "RUNNING", "planID": self.plan, "type": "node", "scale": 1,
                "isDeployed": True, "defaultSubdomain": True,
                "envs": [{"key": k, "value": v, "encrypted": False} for k, v in self.env.items()]}

    def metrics(self, name, period="1h"):
        self._chk(name)
        return {"metrics": {"cpu": 38 if self._bad() else 22, "memory": 97 if self._bad() else 54, "disk": 31}}

    def logs(self, name, since=None):
        self._chk(name)
        return {"logs": [{"message": m} for m in (OOM_LOGS if self._bad() else OK_LOGS)]}

    def restart(self, name):
        self._chk(name); return {"ok": True}

    def resize(self, name, plan):
        self._chk(name); self.plan = plan; return {"ok": True}

    def set_envs(self, name, envs):
        self._chk(name); self.env.update(envs); return {"ok": True}

    def plans(self):
        return {"plans": [{"id": "small", "ram_mb": 512}, {"id": "medium", "ram_mb": 1024}, {"id": "large", "ram_mb": 2048}]}

    def _chk(self, name):
        if name != "my-shop":
            raise LiaraAPIError(404, f"اپ «{name}» پیدا نشد")
