"""تست قرارداد کلاینت با سرور جعلی (شبیه‌ساز مستندات رسمی؛ نه لیارای واقعی)."""
import os
from helpers import FakeLiara
from liara_agent.client import LiaraAPIError, LiaraClient
from liara_agent.security import ValidationError


def _c(f, **kw): return LiaraClient(token="TOK-abcdefgh12345", base=f.base, _allow_any_base=True, **kw)


def test_auth_header_paths_and_shapes():
    f = FakeLiara(); c = _c(f)
    assert c.list_projects()[0]["project_id"] == "my-shop"
    assert c.get_project("my-shop")["planID"] == "p1"           # از کلید «project» باز می‌شود
    c.restart("my-shop"); c.resize("my-shop", "plan-2")
    assert all(x["auth"] == "Bearer TOK-abcdefgh12345" for x in f.calls)
    assert any(x["m"] == "POST" and x["path"] == "/v1/projects/my-shop/actions/restart" for x in f.calls)
    rs = [x for x in f.calls if x["path"].endswith("/resize")][0]
    assert rs["body"] == {"planID": "plan-2"}
    assert all("TOK-abcdefgh12345" not in x["path"] for x in f.calls)   # توکن هرگز در URL نیست
    f.stop()


def test_logs_sends_required_since_and_team_id():
    f = FakeLiara(); c = _c(f, team_id="team1")
    assert c.logs("my-shop")["logs"][0]["message"] == "hello"
    p = f.calls[-1]["path"]
    assert "since=" in p and "teamID=team1" in p
    f.stop()


def test_unverified_endpoints_disabled_by_default():
    f = FakeLiara(); c = _c(f)
    for fn in (lambda: c.plans(), lambda: c.set_envs("my-shop", {"A": "1"})):
        try:
            fn(); assert False
        except LiaraAPIError as e:
            assert e.status == 501 and e.unsupported
    assert f.calls == []                                      # حتی یک درخواست هم ارسال نشد
    os.environ["LIARA_ALLOW_UNVERIFIED"] = "1"
    try:
        try:
            c.set_envs("my-shop", {"A": "1"})
        except LiaraAPIError:
            pass
        assert f.calls[-1]["path"] == "/v1/projects/update-envs"
        assert f.calls[-1]["body"] == {"project": "my-shop", "variables": [{"key": "A", "value": "1"}]}   # بدنه‌ی رسمی
    finally:
        os.environ.pop("LIARA_ALLOW_UNVERIFIED")
    f.stop()


def test_metrics_summary_is_official_and_enabled():
    f = FakeLiara(); c = _c(f)
    d = c.metrics("my-shop", "1h")                            # period ارسال نمی‌شود
    assert f.calls[-1]["path"] == "/v1/projects/my-shop/metrics/summary" and set(d) == {"cpuUsage", "memoryUsage", "disksUsage"}
    f.stop()


def test_base_url_allowlist_protects_token():
    for bad in ("http://api.iran.liara.ir", "https://evil.com", "https://liara.ir.evil.com", "https://api.liara.ir@evil.com"):
        try:
            LiaraClient(token="t" * 12, base=bad); assert False, bad
        except ValidationError:
            pass
    assert LiaraClient(token="t" * 12, base="https://api.iran.liara.ir").base == "https://api.iran.liara.ir"
    assert LiaraClient(token="t" * 12, base="https://api.liara.ir")


def test_token_required_and_header_injection_rejected():
    os.environ.pop("LIARA_API_TOKEN", None)
    for t in ("", None, "abc\r\nX-Evil: 1"):
        try:
            LiaraClient(token=t); assert False
        except LiaraAPIError as e:
            assert e.status == 401


def test_app_name_validation_blocks_path_tricks():
    f = FakeLiara(); c = _c(f)
    for bad in ("../etc", "a/b", "A B", "my-shop?x=1", "", "-x", "x" * 80):
        try:
            c.get_project(bad); assert False, bad
        except ValidationError:
            pass
    assert f.calls == []
    f.stop()


def test_errors_are_mapped_and_never_leak_token():
    f = FakeLiara(leak_token_in_401=True)
    c = LiaraClient(token="BADTOKEN12345", base=f.base, _allow_any_base=True)
    try:
        c.list_projects(); assert False
    except LiaraAPIError as e:
        assert e.status == 401 and "BADTOKEN12345" not in e.message
    c2 = _c(f)
    try:
        c2.get_project("other-app"); assert False
    except LiaraAPIError as e:
        assert e.status == 404 and e.unsupported
    f.stop()


def test_network_error_is_reported():
    c = LiaraClient(token="TOK-abcdefgh12345", base="http://127.0.0.1:1", _allow_any_base=True, timeout=2)
    try:
        c.list_projects(); assert False
    except LiaraAPIError as e:
        assert e.status == 0 and "اتصال" in e.message
