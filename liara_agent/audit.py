"""تاریخچه‌ی اقدامات (Audit Log): هر تصمیم کاربر و نتیجه‌ی آن ثبت می‌شود."""
import json, os, time
from .security import redact

_LOG = []


def _path(): return os.getenv("LIARA_AUDIT_FILE", "audit.jsonl")


def load():
    try:
        with open(_path(), encoding="utf-8") as f:
            _LOG[:] = [json.loads(l) for l in f.readlines()[-200:] if l.strip()]
    except (OSError, ValueError):
        pass


def record(**e):
    for k in ("summary", "detail"):
        if k in e:
            e[k] = redact(e[k], os.getenv("LIARA_API_TOKEN", ""))
    e["ts"] = time.strftime("%Y-%m-%d %H:%M:%S")
    _LOG.append(e)
    try:
        with open(_path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")
    except OSError:
        pass


def entries(): return list(reversed(_LOG))[:100]
