"""اجرای تست‌ها بدون نیاز به pytest:  python tests/run.py"""
import importlib, os, sys, traceback
sys.path.insert(0, os.path.dirname(__file__)); sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
if os.path.exists("/tmp/liara_test_audit.jsonl"):
    os.remove("/tmp/liara_test_audit.jsonl")
fails = n = 0
for mod in ("test_core", "test_client", "test_security", "test_metrics"):
    m = importlib.import_module(mod)
    for name in sorted(x for x in dir(m) if x.startswith("test_")):
        n += 1
        try:
            getattr(m, name)(); print("PASS", mod, name)
        except Exception:
            fails += 1; print("FAIL", mod, name); traceback.print_exc()
print(f"\n{n - fails}/{n} passed"); sys.exit(1 if fails else 0)
