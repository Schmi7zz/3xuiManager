"""Admin session against whatever 3x-ui is installed on this machine.

Restricted users never see this session. The proxy borrows it when it needs to
read or change an inbound on their behalf.
"""

import json
import re
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

_CSRF_RE = re.compile(
    r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)
_CSRF_RE_REV = re.compile(
    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
    re.I,
)


_LIST_TRIES = (
    ("POST", "/panel/inbound/list"),
    ("POST", "/panel/api/inbounds/list"),
    ("GET", "/panel/api/inbounds/list"),
    ("POST", "/xui/inbound/list"),
)
_ONLINE_TRIES = (
    ("POST", "/panel/inbound/onlines"),
    ("POST", "/panel/api/inbounds/onlines"),
)


def _parse_obj_list(status, raw):
    if status != 200 or not raw:
        return None
    try:
        msg = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None
    if not isinstance(msg, dict) or not msg.get("success"):
        return None
    rows = msg.get("obj")
    if rows is None:
        return []
    return rows if isinstance(rows, list) else None


class PanelError(RuntimeError):
    pass


class PanelClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["panel_url"].rstrip("/")
        parts = urllib.parse.urlsplit(self.base)
        self.origin = "{}://{}".format(parts.scheme, parts.netloc)
        self.root = parts.path.rstrip("/")
        self.jar = CookieJar()
        self.lock = threading.RLock()
        self.logged_in = False
        self._csrf = ""
        self._csrf_at = 0.0
        self._inbounds_at = 0.0
        self._inbounds = []
        ctx = None
        if parts.scheme == "https" and not cfg.get("verify_tls", True):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = [urllib.request.HTTPCookieProcessor(self.jar)]
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)

    def cookie_header(self):
        req = urllib.request.Request(self.origin + "/")
        self.jar.add_cookie_header(req)
        return req.get_header("Cookie") or ""

    def _request(self, method, path, body=None, headers=None, timeout=25):
        target = path if path.startswith("http") else self.origin + path
        req = urllib.request.Request(target, data=body, method=method, headers=headers or {})
        try:
            with self.opener.open(req, timeout=timeout) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def _login_csrf(self):
        for path in (self.root + "/", self.root + "/login", self.root + "/panel/"):
            status, body, _headers = self._request("GET", path, headers={"Accept": "text/html"})
            if status >= 400:
                continue
            text = body.decode("utf-8", "replace")
            match = _CSRF_RE.search(text) or _CSRF_RE_REV.search(text)
            if match:
                return match.group(1)
        return ""

    def login(self, force=False):
        with self.lock:
            if self.logged_in and not force:
                return
            self.jar.clear()
            self.logged_in = False
            self._csrf = ""
            token = self._login_csrf()
            form = {
                "username": self.cfg["panel_username"],
                "password": self.cfg["panel_password"],
            }
            code = self.cfg.get("panel_2fa_code") or ""
            if code:
                form["twoFactorCode"] = code
            headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
            if token:
                headers["X-CSRF-Token"] = token
            path = self.root + "/login"
            attempts = (
                (
                    json.dumps(form).encode("utf-8"),
                    dict(headers, **{"Content-Type": "application/json"}),
                ),
                (
                    urllib.parse.urlencode(form).encode("utf-8"),
                    dict(headers, **{"Content-Type": "application/x-www-form-urlencoded"}),
                ),
            )
            last = ""
            for body, hdrs in attempts:
                status, raw, _headers = self._request("POST", path, body=body, headers=hdrs)
                text = raw.decode("utf-8", "replace")
                last = text[:240]
                try:
                    ok = bool(json.loads(text).get("success"))
                except ValueError:
                    ok = False
                if ok:
                    self.logged_in = True
                    self._refresh_csrf()
                    return
                # A normal rejection means the username and password were read.
                # Trying the other encoding would only burn another login attempt.
                if "invalid username" in text.lower() or "two-factor" in text.lower():
                    break
                if status not in (400, 403, 404, 415):
                    break
            raise PanelError("3x-ui login failed: {}".format(last or "no response"))

    def _refresh_csrf(self):
        status, raw, _headers = self._request(
            "GET",
            self.root + "/panel/csrf-token",
            headers={"Accept": "application/json"},
        )
        if status != 200:
            self._csrf = ""
            self._csrf_at = time.time()
            return ""
        try:
            token = json.loads(raw.decode("utf-8", "replace")).get("obj") or ""
        except ValueError:
            token = ""
        self._csrf = token if isinstance(token, str) else ""
        self._csrf_at = time.time()
        return self._csrf

    def ensure_login(self):
        with self.lock:
            if not self.logged_in:
                self.login()

    def auth_headers(self):
        """Cookie and CSRF for a scoped forward. Safe to use after the lock is released."""
        with self.lock:
            self.ensure_login()
            if not self._csrf or time.time() - self._csrf_at > 600:
                self._refresh_csrf()
            return self.cookie_header(), self._csrf

    def relogin(self):
        with self.lock:
            self.login(force=True)
            return self.cookie_header(), self._csrf

    def _api(self, method, path, form=None):
        with self.lock:
            self.ensure_login()
            headers = {"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"}
            body = None
            if form is not None:
                body = urllib.parse.urlencode(form).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if method.upper() not in ("GET", "HEAD") and self._csrf:
                headers["X-CSRF-Token"] = self._csrf
            status, raw, _resp_headers = self._request(method, self.root + path, body=body, headers=headers)
            text = raw.decode("utf-8", "replace")
            if status in (401, 403) or text.lstrip().startswith("<"):
                self.login(force=True)
                if method.upper() not in ("GET", "HEAD") and self._csrf:
                    headers["X-CSRF-Token"] = self._csrf
                status, raw, _resp_headers = self._request(method, self.root + path, body=body, headers=headers)
                text = raw.decode("utf-8", "replace")
        try:
            msg = json.loads(text)
        except ValueError:
            raise PanelError("Unexpected answer from 3x-ui (HTTP {})".format(status))
        if not msg.get("success"):
            raise PanelError(msg.get("msg") or "3x-ui returned an error")
        return msg.get("obj")

    def inbounds(self, fresh=False):
        with self.lock:
            if not fresh and self._inbounds and time.time() - self._inbounds_at < 3:
                return list(self._inbounds)
        last = None
        for method, path in _LIST_TRIES:
            try:
                rows = self._api(method, path, {} if method == "POST" else None)
            except PanelError as exc:
                last = exc
                continue
            if isinstance(rows, list):
                with self.lock:
                    self._inbounds = rows
                    self._inbounds_at = time.time()
                return rows
        if last:
            raise last
        return []

    def onlines(self):
        for method, path in _ONLINE_TRIES:
            try:
                rows = self._api(method, path, {}) or []
            except PanelError:
                continue
            if isinstance(rows, list):
                return [str(item) for item in rows]
        return []

    def inbounds_from_cookie(self, cookie_header):
        """Inbound list using the browser's own 3x-ui session, not the saved password."""
        if not cookie_header:
            return None
        for method, path in _LIST_TRIES:
            body = b"{}" if method == "POST" else None
            ctype = "application/json" if method == "POST" else None
            status, raw = self._bare(self.root + path, cookie_header, method, body, ctype)
            rows = _parse_obj_list(status, raw)
            if rows is not None:
                return rows
        return None

    def browser_is_admin(self, cookie_header):
        """True when the browser cookie is a real 3x-ui admin session."""
        rows = self.inbounds_from_cookie(cookie_header)
        return rows is not None

    def _bare(self, path, cookie_header, method="GET", body=None, content_type=None):
        headers = {"Accept": "application/json"}
        if cookie_header:
            headers["Cookie"] = cookie_header
        if content_type:
            headers["Content-Type"] = content_type
        if method == "POST" and body is None:
            body = b""
        req = urllib.request.Request(
            self.origin + path,
            data=body,
            headers=headers,
            method=method,
        )
        handlers = []
        if self.origin.startswith("https") and not self.cfg.get("verify_tls", True):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        opener = urllib.request.build_opener(*handlers)
        try:
            with opener.open(req, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except urllib.error.URLError:
            return 0, b""
