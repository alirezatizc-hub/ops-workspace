"""اعتبارسنجی ورودی، ضدّ SSRF، ذخیره‌ی تأیید یک‌بارمصرف و پاک‌سازی رازها."""
import ipaddress, re, secrets, socket, ssl, threading, time, urllib.parse


class ValidationError(ValueError):
    pass


APP_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
PLAN_RE = re.compile(r"^[A-Za-z0-9._-]{1,40}$")
PLATFORM_RE = re.compile(r"^[a-z0-9-]{2,24}$")
GH_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]{1,39})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}$")
ALLOWED_PORTS = (80, 443)


def validate_app_name(n):
    if not isinstance(n, str) or not APP_RE.match(n):
        raise ValidationError("نام اپ نامعتبر است (فقط حروف کوچک انگلیسی، عدد و خط تیره)")
    return n


def validate_env(key, value):
    if not isinstance(key, str) or not ENV_KEY_RE.match(key):
        raise ValidationError("نام متغیر محیطی نامعتبر است")
    if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
        raise ValidationError("مقدار متغیر محیطی نامعتبر یا طولانی است")


def validate_plan(p):
    if not isinstance(p, str) or not PLAN_RE.match(p):
        raise ValidationError("شناسه‌ی پلن نامعتبر است")
    return p


def validate_platform(p):
    if not isinstance(p, str) or not PLATFORM_RE.match(p):
        raise ValidationError("نام پلتفرم نامعتبر است")
    return p


def validate_port(p):
    if isinstance(p, bool) or not isinstance(p, int) or not 1 <= p <= 65535:
        raise ValidationError("پورت باید عددی بین ۱ تا ۶۵۵۳۵ باشد")
    return p


def validate_github_url(u):
    m = GH_RE.match(u or "")
    if not m or ".." in (m.group(1), m.group(2)):
        raise ValidationError("آدرس باید به شکل https://github.com/user/repo باشد")
    return u


def validate_domain(d):
    if not isinstance(d, str) or not DOMAIN_RE.match(d.lower()):
        raise ValidationError("دامنه نامعتبر است")
    return d.lower()


def is_public_ip(ip):
    a = ipaddress.ip_address(ip)
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return a.is_global and not a.is_multicast


def parse_public_url(url):
    if not isinstance(url, str) or len(url) > 2048:
        raise ValidationError("آدرس نامعتبر است")
    u = urllib.parse.urlsplit(url.strip())
    if u.scheme not in ("http", "https"):
        raise ValidationError("فقط http و https مجاز است")
    if u.username or u.password:
        raise ValidationError("آدرس نباید شامل نام‌کاربری/رمز باشد")
    if not u.hostname:
        raise ValidationError("نام میزبان آدرس خالی است")
    port = u.port or (443 if u.scheme == "https" else 80)
    return u, u.hostname, port


def safe_http_check(url, timeout=8, allow_private=False, ports=ALLOWED_PORTS):
    """درخواست HEAD-مانند امن: فقط پورت‌های مجاز، فقط IP عمومی (اتصال مستقیم به همان IP
    برای جلوگیری از DNS-rebinding)، بدون دنبال‌کردن ریدایرکت، بدون خواندن بدنه."""
    u, host, port = parse_public_url(url)
    if not allow_private and port not in ports:
        raise ValidationError("پورت مجاز نیست (فقط ۸۰ و ۴۴۳)")
    try:
        addrs = [i[4][0] for i in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]
    except socket.gaierror:
        return {"url": url, "ok": False, "error": "نام دامنه پیدا نشد"}
    if not addrs or (not allow_private and not all(is_public_ip(a) for a in addrs)):
        raise ValidationError("آدرس به شبکه داخلی/خصوصی اشاره می‌کند و مجاز نیست")
    t = time.time()
    try:
        s = socket.create_connection((addrs[0], port), timeout=timeout)
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=host)
        s.settimeout(timeout)
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: liara-sre-agent\r\nConnection: close\r\n\r\n".encode())
        line = s.recv(256).split(b"\r\n", 1)[0].decode("latin1")
        s.close()
        code = int(line.split()[1])
    except ssl.SSLError:
        return {"url": url, "ok": False, "error": "گواهی TLS نامعتبر است"}
    except (OSError, ValueError, IndexError) as e:
        return {"url": url, "ok": False, "error": f"اتصال ناموفق ({type(e).__name__})"}
    ms = int((time.time() - t) * 1000)
    return {"url": url, "status_code": code, "latency_ms": ms, "ok": code < 400,
            "verdict": "کند" if ms > 2000 else "سالم" if code < 400 else "خطا"}


class ConfirmStore:
    """تأییدهای یک‌بارمصرف و زمان‌دار؛ پارامترها سمت سرور نگه داشته می‌شوند و کلاینت نمی‌تواند تغییرشان دهد."""
    def __init__(self, ttl=300):
        self.ttl, self._d, self._l = ttl, {}, threading.Lock()

    def create(self, tool, args):
        with self._l:
            now = time.time()
            self._d = {k: v for k, v in self._d.items() if v[0] > now}
            cid = secrets.token_urlsafe(16)
            self._d[cid] = (now + self.ttl, tool, dict(args))
            return cid

    def consume(self, cid):
        with self._l:
            item = self._d.pop(cid, None)
        if not item or item[0] < time.time():
            return None
        return item[1], item[2]


def redact(text, *secrets_):
    text = str(text)
    for s in secrets_:
        if s:
            text = text.replace(s, "***")
    return re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{8,}", r"\1***", text)
