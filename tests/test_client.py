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
    try:
        c.networks(); assert False
    except LiaraAPIError as e:
        assert e.status == 501 and e.unsupported
    assert f.calls == []                                      # حتی یک درخواست هم ارسال نشد
    os.environ["LIARA_ALLOW_UNVERIFIED"] = "1"
    try:
        try:
            c.networks()
        except LiaraAPIError:
            pass
        assert f.calls and f.calls[-1]["path"].startswith("/v1/networks")
    finally:
        os.environ.pop("LIARA_ALLOW_UNVERIFIED")
    f.stop()


def test_update_envs_is_official_with_official_body():
    f = FakeLiara(); c = _c(f)
    c.set_envs("my-shop", {"A": "1", "B": "2"})
    assert f.calls[-1]["path"].split("?")[0] == "/v1/projects/update-envs"
    assert f.calls[-1]["body"] == {"project": "my-shop",
                                   "variables": [{"key": "A", "value": "1"}, {"key": "B", "value": "2"}]}   # بدنه‌ی رسمی
    f.stop()


def test_plans_come_from_me_catalog():
    f = FakeLiara(); c = _c(f)
    plans = c.plans()["plans"]
    assert [p["id"] for p in plans] == ["p1", "p2"]                       # مرتب بر اساس قیمت
    assert plans[0]["ram_mb"] == 512 and plans[0]["cpu"] == 0.5           # گیگابایت←مگابایت، هسته
    assert f.calls[0]["path"].split("?")[0] == "/v1/me"
    c.plans()                                                              # کش: درخواست دوباره نمی‌رود
    assert len([x for x in f.calls if x["path"].startswith("/v1/me")]) == 1
    f.stop()


def test_database_and_domain_endpoints_contract():
    f = FakeLiara(); c = _c(f)
    assert c.list_databases()[0]["hostname"] == "shop-db"
    assert c.get_database("db1")["root_password"] == "FAKE-SECRET"        # خام در کلاینت؛ پاک‌سازی وظیفه‌ی tools است
    c.scale_database("db1", False)
    sc = [x for x in f.calls if x["path"].split("?")[0] == "/v1/databases/db1/actions/scale"][0]
    assert sc["m"] == "POST" and sc["body"] == {"scale": 0}
    c.db_public_network("db1", True)
    pn = f.calls[-1]
    assert pn["m"] == "PATCH" and pn["path"].split("?")[0] == "/v1/databases/db1/public-network/enable"
    assert c.download_db_backup("db1", "b1.gz")["link"].startswith("https://")
    assert c.list_domains()[0]["name"] == "shop.ir"
    c.enable_ssl("shop.ir")
    assert f.calls[-1]["body"] == {"domain": "shop.ir"}
    c.create_database("new-db", "mysql", "dbp1", "8.0")
    assert f.calls[-1]["body"] == {"hostname": "new-db", "type": "mysql", "planID": "dbp1",
                                   "publicNetwork": False, "version": "8.0"}
    c.scale("my-shop", False)
    assert f.calls[-1]["body"] == {"scale": 0}
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
