"""Reverse proxy that serves the real 3x-ui dashboard and enforces scoped users."""

import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.parse
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xui_management.auth import (
    check_password,
    clear_fails,
    hash_password,
    login_blocked,
    make_token,
    note_fail,
    read_token,
)
from xui_management.config import normalize_user
from xui_management.panel import PanelError
from xui_management.scope import (
    assert_ids_allowed,
    client_count,
    client_emails,
    collect_inbound_ids,
    decide,
    filter_payload,
    inbound_allowed,
)
from xui_management.telegram_bot import TelegramError, send_message

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
MAX_BODY = 32 * 1024 * 1024
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
TOKEN_RE = re.compile(r"^\d+:[A-Za-z0-9_-]{20,}$")
CHAT_RE = re.compile(r"^-?\d+$")
DROP_RES_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "te",
    "trailer",
    "trailers",
    "upgrade",
    "content-length",
    "content-encoding",
}
def explain_login_failure(text):
    lower = (text or "").lower()
    if "invalid username" in lower or "two-factor" in lower or "password" in lower:
        return (
            "3x-ui rejected the saved admin username or password. "
            "Turn two-factor login off for the admin account, then enter the correct username and password below. "
            "Restricted users and Telegram bots stay broken until this login works."
        )
    return "Could not sign in to 3x-ui. " + (text or "")[:180]


STATIC_FILES = {
    "/__xmgmt/inject.js": ("inject.js", "application/javascript"),
    "/__xmgmt/ui": ("manage.html", "text/html"),
    "/__xmgmt/manage.js": ("manage.js", "application/javascript"),
    "/__xmgmt/manage.css": ("manage.css", "text/css"),
}


def strip_base(path, base):
    if base != "/" and path.startswith(base.rstrip("/")):
        rest = path[len(base.rstrip("/")) :]
        return rest or "/"
    return path


def client_ip(handler, trusted):
    peer = handler.client_address[0]
    if peer in trusted:
        forwarded = handler.headers.get("X-Forwarded-For") or ""
        if forwarded:
            return forwarded.split(",")[0].strip()
    return peer


def cookie_value(header, name):
    for part in (header or "").split(";"):
        key, _, value = part.strip().partition("=")
        if key == name:
            return value
    return ""


class App:
    def __init__(self, store, panel):
        self.store = store
        self.panel = panel

    def handler(self):
        app = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "xui-management"
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                sys.stderr.write("%s - %s\n" % (self.client_address[0], fmt % args))

            def handle_one_request(self):
                self.close_connection = True
                return BaseHTTPRequestHandler.handle_one_request(self)

            def do_GET(self):
                app.dispatch(self)

            def do_HEAD(self):
                app.dispatch(self)

            def do_POST(self):
                app.dispatch(self)

            def do_PUT(self):
                app.dispatch(self)

            def do_PATCH(self):
                app.dispatch(self)

            def do_DELETE(self):
                app.dispatch(self)

            def do_OPTIONS(self):
                app.dispatch(self)

        return Handler

    def dispatch(self, handler):
        try:
            self._dispatch(handler)
        except Exception as exc:
            sys.stderr.write("proxy error: {}\n".format(exc))
            if not getattr(handler, "_sent", False):
                self._send(handler, 502, {"success": False, "msg": "The panel request failed"})

    def _dispatch(self, handler):
        parsed = urllib.parse.urlsplit(handler.path)
        base = self.store.data["public_base_path"]
        rel = strip_base(parsed.path, base)
        if handler.command == "GET" and rel in STATIC_FILES:
            self._static(handler, rel)
            return
        length = int(handler.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            self._send(handler, 413, {"success": False, "msg": "Request is too large"})
            return
        body = handler.rfile.read(length) if length else b""
        if rel.startswith("/__xmgmt/api/"):
            self._api(handler, rel, body)
            return
        upgrade = (handler.headers.get("Upgrade") or "").lower()
        if upgrade == "websocket":
            self._websocket(handler, parsed)
            return
        if handler.command == "POST" and rel.rstrip("/") == "/login":
            self._login(handler, body)
            return
        if handler.command == "POST" and rel.rstrip("/") in ("/logout", "/panel/logout"):
            self._logout(handler, parsed, body)
            return
        user = self._subuser(handler)
        if user:
            self._scoped(handler, parsed, body, user)
            return
        self._forward(handler, parsed, body, scoped=False)

    def _subuser(self, handler):
        token = cookie_value(handler.headers.get("Cookie"), "xmgmt")
        if not token:
            return None
        username = read_token(token, self.store.data["secret_key"], self.store.users_by_name())
        if not username:
            return None
        return self.store.users_by_name()[username]

    def _admin(self, handler):
        return self.panel.browser_is_admin(handler.headers.get("Cookie") or "")

    def _static(self, handler, rel):
        name, ctype = STATIC_FILES[rel]
        path = os.path.join(STATIC_DIR, name)
        try:
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            self._send(handler, 404, {"success": False, "msg": "Missing file"})
            return
        self._send(handler, 200, data, ctype, cache=name == "inject.js")

    def _api(self, handler, rel, body):
        method = handler.command
        if method == "GET" and rel == "/__xmgmt/api/me":
            user = self._subuser(handler)
            if user:
                self._send(handler, 200, {
                    "success": True,
                    "obj": {
                        "role": "user",
                        "username": user["username"],
                        "permissions": user["permissions"],
                        "inbound_ids": user["inbound_ids"],
                        "inbound_ports": user["inbound_ports"],
                    },
                })
                return
            if self._admin(handler):
                self._send(handler, 200, {"success": True, "obj": {"role": "admin"}})
                return
            self._send(handler, 401, {"success": False, "msg": "Not logged in"})
            return
        if not self._admin(handler):
            self._send(handler, 401, {"success": False, "msg": "Not logged in"})
            return
        if method != "GET" and handler.headers.get("X-XMGMT") != "1":
            self._send(handler, 403, {"success": False, "msg": "Forbidden"})
            return
        try:
            if method == "GET" and rel == "/__xmgmt/api/users":
                self._send(handler, 200, {"success": True, "obj": self.store.public_users()})
                return
            if method == "GET" and rel == "/__xmgmt/api/inbounds":
                rows, warning = self._inbound_choices(handler.headers.get("Cookie") or "")
                self._send(handler, 200, {
                    "success": True,
                    "obj": rows,
                    "warning": warning,
                    "panel_username": self.store.data.get("panel_username") or "",
                })
                return
            payload = json.loads(body.decode("utf-8") or "{}")
            if method == "POST" and rel == "/__xmgmt/api/panel-login":
                self._save_panel_login(payload)
                self._send(handler, 200, {"success": True})
                return
            if method == "POST" and rel == "/__xmgmt/api/users/save":
                self._save_user(payload)
                self._send(handler, 200, {"success": True})
                return
            if method == "POST" and rel == "/__xmgmt/api/users/delete":
                self._delete_user(payload)
                self._send(handler, 200, {"success": True})
                return
            if method == "POST" and rel == "/__xmgmt/api/telegram/test":
                send_message(
                    payload.get("bot_token", ""),
                    payload.get("chat_id", ""),
                    "xui-management test\nThis bot will only report the inbounds you assign, plus CPU.",
                )
                self._send(handler, 200, {"success": True})
                return
        except (ValueError, TelegramError, PanelError) as exc:
            self._send(handler, 400, {"success": False, "msg": str(exc)})
            return
        except json.JSONDecodeError:
            self._send(handler, 400, {"success": False, "msg": "Invalid JSON"})
            return
        self._send(handler, 404, {"success": False, "msg": "Not found"})

    def _summarize_inbounds(self, rows):
        cleaned = []
        for inbound in rows or []:
            cleaned.append({
                "id": inbound.get("id"),
                "remark": inbound.get("remark") or "",
                "protocol": inbound.get("protocol") or "",
                "port": inbound.get("port"),
                "enable": bool(inbound.get("enable", True)),
            })
        return cleaned

    def _inbound_choices(self, cookie):
        rows = self.panel.inbounds_from_cookie(cookie)
        if rows is None:
            rows = self.panel.inbounds(fresh=True)
            return self._summarize_inbounds(rows), ""
        return self._summarize_inbounds(rows), self._service_warning()

    def _service_warning(self):
        if self.panel.logged_in:
            return ""
        now = time.time()
        if now < getattr(self, "_login_fail_until", 0):
            return self._login_fail_msg
        try:
            self.panel.login()
        except PanelError as exc:
            self._login_fail_until = now + 900
            self._login_fail_msg = explain_login_failure(str(exc))
            return self._login_fail_msg
        self._login_fail_until = 0
        self._login_fail_msg = ""
        return ""

    def _save_panel_login(self, payload):
        username = str(payload.get("username") or "").strip()
        password = str(payload.get("password") or "")
        if not username or not password:
            raise ValueError("Enter the 3x-ui admin username and password")
        previous_user = self.store.data.get("panel_username")
        previous_password = self.store.data.get("panel_password")
        self.store.data["panel_username"] = username
        self.store.data["panel_password"] = password
        self.panel.logged_in = False
        try:
            self.panel.login(force=True)
        except PanelError as exc:
            self.store.data["panel_username"] = previous_user
            self.store.data["panel_password"] = previous_password
            self.panel.logged_in = False
            raise ValueError(explain_login_failure(str(exc)))
        self._login_fail_until = 0
        self._login_fail_msg = ""
        self.store.save()

    def _save_user(self, payload):
        username = str(payload.get("username") or "").strip()
        if not USERNAME_RE.match(username):
            raise ValueError("Username must be 1-32 letters, numbers, dot, dash or underscore")
        if username == str(self.store.data.get("panel_username") or ""):
            raise ValueError("This username is the 3x-ui admin. Pick another.")
        password = str(payload.get("password") or "")
        with self.store.lock:
            current = {u["username"]: u for u in self.store.data.get("users") or []}
            existing = current.get(username)
            if password or not existing:
                if len(password) < 8:
                    raise ValueError("Password must be at least 8 characters")
                password_hash = hash_password(password)
            else:
                password_hash = existing["password_hash"]
            ids = []
            for value in payload.get("inbound_ids") or []:
                try:
                    ids.append(int(value))
                except (TypeError, ValueError):
                    raise ValueError("Inbound ids must be numbers")
            ports = []
            for value in payload.get("inbound_ports") or []:
                try:
                    port = int(value)
                except (TypeError, ValueError):
                    raise ValueError("Ports must be numbers")
                if port < 1 or port > 65535:
                    raise ValueError("Ports must be between 1 and 65535")
                ports.append(port)
            if not ids and not ports:
                raise ValueError("Choose at least one inbound or port")
            tg = payload.get("telegram") or {}
            token = str(tg.get("bot_token") or "").strip()
            chat_id = str(tg.get("chat_id") or "").strip()
            enabled = bool(tg.get("enabled"))
            if token and not TOKEN_RE.match(token):
                raise ValueError("Bot token should look like 123456:ABC...")
            if chat_id and not CHAT_RE.match(chat_id):
                raise ValueError("Chat id must be a number")
            if enabled and (not token or not chat_id):
                raise ValueError("A bot token and chat id are required when the bot is enabled")
            try:
                minutes = int(tg.get("report_minutes") or 60)
                threshold = int(tg.get("cpu_threshold") or 0)
                max_clients = int(payload.get("max_clients") or 0)
            except (TypeError, ValueError):
                raise ValueError("Numbers only for limits, report interval and CPU threshold")
            if max_clients < 0:
                raise ValueError("Client limit can't be negative")
            perms = payload.get("permissions") or {}
            row = normalize_user({
                "username": username,
                "password_hash": password_hash,
                "inbound_ids": ids,
                "inbound_ports": ports,
                "max_clients": max_clients,
                "permissions": {
                    "add": bool(perms.get("add")),
                    "edit": bool(perms.get("edit")),
                    "delete": bool(perms.get("delete")),
                    "reset": bool(perms.get("reset")),
                },
                "telegram": {
                    "enabled": enabled,
                    "bot_token": token,
                    "chat_id": chat_id,
                    "report_minutes": minutes,
                    "cpu_threshold": threshold,
                },
            })
            self.store.data["users"] = [u for u in self.store.data.get("users") or [] if u["username"] != username]
            self.store.data["users"].append(row)
            self.store.save()

    def _delete_user(self, payload):
        username = str(payload.get("username") or "").strip()
        with self.store.lock:
            before = len(self.store.data.get("users") or [])
            self.store.data["users"] = [u for u in self.store.data.get("users") or [] if u["username"] != username]
            if len(self.store.data["users"]) == before:
                raise ValueError("User not found")
            self.store.save()

    def _login(self, handler, body):
        ip = client_ip(handler, set(self.store.data.get("trusted_proxies") or []))
        if login_blocked(ip):
            self._send(handler, 429, {"success": False, "msg": "Too many attempts, wait 15 minutes"})
            return
        username, password = self._login_fields(handler, body)
        user = self.store.users_by_name().get(username)
        if user:
            if not check_password(password, user["password_hash"]):
                note_fail(ip)
                time.sleep(0.3)
                self._send(handler, 401, {"success": False, "msg": "Wrong username or password"})
                return
            clear_fails(ip)
            token = make_token(username, self.store.data["secret_key"])
            self._send(
                handler,
                200,
                {"success": True},
                extra=[self._session_cookie(token)],
            )
            return
        parsed = urllib.parse.urlsplit(handler.path)
        self._forward(handler, parsed, body, scoped=False)

    def _logout(self, handler, parsed, body):
        if self._subuser(handler):
            self._send(handler, 200, {"success": True}, extra=[self._session_cookie("", clear=True)])
            return
        self._forward(handler, parsed, body, scoped=False, extra_cookie=self._session_cookie("", clear=True))

    def _login_fields(self, handler, body):
        ctype = (handler.headers.get("Content-Type") or "").lower()
        if "json" in ctype or (body[:1:] == b"{"):
            try:
                data = json.loads(body.decode("utf-8") or "{}")
            except ValueError:
                return "", ""
            return str(data.get("username") or ""), str(data.get("password") or "")
        form = urllib.parse.parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True)
        return (form.get("username") or [""])[0], (form.get("password") or [""])[0]

    def _session_cookie(self, token, clear=False):
        base = self.store.data["public_base_path"]
        secure = "; Secure" if self.store.data.get("tls_cert") and self.store.data.get("tls_key") else ""
        age = "0" if clear else str(12 * 3600)
        return (
            "Set-Cookie",
            "xmgmt={}; Path={}; HttpOnly; SameSite=Lax; Max-Age={}{}".format(token, base, age, secure),
        )

    def _scoped(self, handler, parsed, body, user):
        action, perm = decide(handler.command, parsed.path)
        if action == "pass" and handler.command not in ("GET", "HEAD", "OPTIONS"):
            action = "deny"
        if action == "deny":
            self._send(handler, 403, {"success": False, "msg": "You don't have access to this"})
            return
        chosen, ids, emails = [], set(), set()
        if action in ("filter", "mutation"):
            try:
                chosen, ids, emails = self._access(user)
            except PanelError as exc:
                self._send(handler, 502, {"success": False, "msg": str(exc)})
                return
        if action == "mutation":
            if not user["permissions"].get(perm):
                self._send(handler, 403, {"success": False, "msg": "Not allowed: {}".format(perm)})
                return
            try:
                found = collect_inbound_ids(parsed.path, body, handler.headers.get("Content-Type"))
                assert_ids_allowed(found, ids)
            except PermissionError as exc:
                self._send(handler, 403, {"success": False, "msg": str(exc)})
                return
            if perm == "add":
                target = next((row for row in chosen if int(row.get("id")) in found), None)
                limit = user["max_clients"]
                if target is not None and limit and client_count(target) >= limit:
                    self._send(handler, 400, {"success": False, "msg": "Client limit reached ({})".format(limit)})
                    return
        if action == "filter" and handler.command not in ("GET", "HEAD", "OPTIONS"):
            lowered = parsed.path.lower()
            if "clientip" in lowered:
                try:
                    found_emails = self._emails_in_request(parsed.path, body)
                except PermissionError as exc:
                    self._send(handler, 403, {"success": False, "msg": str(exc)})
                    return
                if found_emails and not found_emails <= emails:
                    self._send(handler, 403, {"success": False, "msg": "You don't have access to this client"})
                    return
        self._forward(handler, parsed, body, scoped=True, user=user, ids=ids, emails=emails, action=action)

    def _emails_in_request(self, path, body):
        found = set()
        for match in re.finditer(r"/clientIps/([^/?]+)", path, re.I):
            found.add(urllib.parse.unquote(match.group(1)).lower())
        if body:
            try:
                payload = json.loads(body.decode("utf-8"))
            except ValueError:
                payload = None
            if isinstance(payload, dict) and payload.get("email"):
                found.add(str(payload["email"]).lower())
        return found

    def _access(self, user):
        rows = self.panel.inbounds()
        ids = set(user["inbound_ids"])
        ports = set(user["inbound_ports"])
        chosen = [row for row in rows if inbound_allowed(row, ids, ports)]
        resolved = set()
        emails = set()
        for row in chosen:
            resolved.add(int(row["id"]))
            emails |= client_emails(row)
        return chosen, resolved, emails

    def _forward(self, handler, parsed, body, scoped, user=None, ids=None, emails=None, action=None, extra_cookie=None):
        admin_cookie = ""
        admin_csrf = ""
        if scoped:
            try:
                admin_cookie, admin_csrf = self.panel.auth_headers()
            except PanelError as exc:
                self._send(handler, 502, {"success": False, "msg": str(exc)})
                return
        status, headers, payload, error = self._upstream(
            handler, parsed, body, admin_cookie, admin_csrf, scoped
        )
        if error:
            self._send(handler, 502, {"success": False, "msg": "The panel is not responding"})
            return
        if scoped and status in (401, 403) and handler.command not in ("GET", "HEAD", "OPTIONS"):
            try:
                admin_cookie, admin_csrf = self.panel.relogin()
            except PanelError:
                admin_cookie = ""
            if admin_cookie:
                status, headers, payload, error = self._upstream(
                    handler, parsed, body, admin_cookie, admin_csrf, True
                )
                if error:
                    self._send(handler, 502, {"success": False, "msg": "The panel is not responding"})
                    return
        content_type = ""
        for key, value in headers:
            if key.lower() == "content-type":
                content_type = value
        if scoped and action == "filter":
            try:
                payload = self._filter_body(parsed.path, content_type, payload, ids, user["inbound_ports"], emails)
            except PermissionError as exc:
                self._send(handler, 403, {"success": False, "msg": str(exc)})
                return
            except ValueError:
                self._send(handler, 502, {"success": False, "msg": "Could not read the panel response"})
                return
        if "text/html" in content_type.lower():
            payload = inject_html(payload, self.store.data["public_base_path"])
        out_headers = []
        for key, value in headers:
            low = key.lower()
            if low in DROP_RES_HEADERS:
                continue
            if scoped and low == "set-cookie":
                continue
            out_headers.append((key, value))
        if extra_cookie:
            out_headers.append(extra_cookie)
        self._send_raw(handler, status, payload, content_type or "application/octet-stream", out_headers)

    def _filter_body(self, path, content_type, payload, ids, ports, emails):
        if not payload:
            return payload
        if "json" not in content_type.lower() and payload.lstrip()[:1] not in (b"{", b"["):
            return payload
        data = json.loads(payload.decode("utf-8"))
        filtered = filter_payload(path, data, set(ids), set(ports), emails)
        return json.dumps(filtered, ensure_ascii=False).encode("utf-8")

    def _upstream(self, handler, parsed, body, admin_cookie, admin_csrf, scoped):
        parts = urllib.parse.urlsplit(self.panel.base)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parsed.path
        if parsed.query:
            path = path + "?" + parsed.query
        headers = {}
        for key, value in handler.headers.items():
            low = key.lower()
            if low in DROP_RES_HEADERS or low in ("cookie", "host", "accept-encoding", "x-csrf-token"):
                continue
            headers[key] = value
        headers["Host"] = handler.headers.get("Host") or parts.netloc
        headers["Accept-Encoding"] = "identity"
        if scoped:
            if admin_cookie:
                headers["Cookie"] = admin_cookie
            if handler.command not in ("GET", "HEAD", "OPTIONS") and admin_csrf:
                headers["X-CSRF-Token"] = admin_csrf
        else:
            cookie = handler.headers.get("Cookie")
            if cookie:
                headers["Cookie"] = cookie
            csrf = handler.headers.get("X-CSRF-Token")
            if csrf:
                headers["X-CSRF-Token"] = csrf
        if body:
            headers["Content-Length"] = str(len(body))
        try:
            conn = self._connect(host, port, parts.scheme)
            conn.request(handler.command, path, body=body or None, headers=headers)
            response = conn.getresponse()
            payload = response.read()
            forwarded = list(iter_response_headers(response.headers))
            status = response.status
            conn.close()
            return status, forwarded, payload, None
        except (OSError, HTTPException) as exc:
            return 0, [], b"", exc

    def _connect(self, host, port, scheme):
        timeout = 60
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not self.store.data.get("verify_tls", True):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            return HTTPSConnection(host, port, timeout=timeout, context=ctx)
        return HTTPConnection(host, port, timeout=timeout)

    def _websocket(self, handler, parsed):
        if self._subuser(handler):
            self._send(handler, 403, {"success": False, "msg": "Live updates are off for restricted users"})
            return
        parts = urllib.parse.urlsplit(self.panel.base)
        host = parts.hostname
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parsed.path + (("?" + parsed.query) if parsed.query else "")
        try:
            conn = self._connect(host, port, parts.scheme)
            conn.connect()
            sock = conn.sock
        except (OSError, HTTPException):
            self._send(handler, 502, {"success": False, "msg": "The panel is not responding"})
            return
        lines = ["{} {} HTTP/1.1".format(handler.command, path)]
        for key, value in handler.headers.items():
            if key.lower() == "accept-encoding":
                continue
            lines.append("{}: {}".format(key, value))
        if not any(line.lower().startswith("host:") for line in lines):
            lines.append("Host: {}".format(handler.headers.get("Host") or parts.netloc))
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1", "replace")
        try:
            sock.sendall(raw)
            relay(handler.connection, sock)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _send(self, handler, code, body, content_type="application/json", extra=None, cache=False):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        handler._sent = True
        handler.send_response(code)
        handler.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type.endswith("json") or content_type.endswith("javascript") else ""))
        handler.send_header("Content-Length", str(len(body)))
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.send_header("Cache-Control", "no-cache" if cache else "no-store")
        handler.send_header("Referrer-Policy", "no-referrer")
        for key, value in extra or []:
            handler.send_header(key, value)
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)

    def _send_raw(self, handler, code, body, content_type, headers):
        handler._sent = True
        handler.send_response(code)
        sent_type = False
        sent_len = False
        for key, value in headers:
            low = key.lower()
            if low == "content-type":
                sent_type = True
            handler.send_header(key, value)
        if not sent_type:
            handler.send_header("Content-Type", content_type)
        handler.send_header("Content-Length", str(len(body)))
        sent_len = True
        handler.send_header("Cache-Control", "no-store")
        if not sent_len:
            pass
        handler.end_headers()
        if handler.command != "HEAD":
            handler.wfile.write(body)


def iter_response_headers(headers):
    for key in headers.keys():
        if not key:
            continue
        for value in headers.get_all(key):
            yield key, value


def inject_html(body, base):
    try:
        text = body.decode("utf-8")
    except UnicodeError:
        return body
    if "__xmgmt/inject.js" in text:
        return body
    tag = '<script src="{}__xmgmt/inject.js"></script>'.format(base)
    lower = text.lower()
    index = lower.rfind("</head>")
    if index == -1:
        return (tag + text).encode("utf-8")
    return (text[:index] + tag + text[index:]).encode("utf-8")


def relay(left, right):
    def pipe(src, dst):
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                dst.sendall(chunk)
        except OSError:
            pass
        try:
            dst.shutdown(1)
        except OSError:
            pass

    thread = threading.Thread(target=pipe, args=(right, left), daemon=True)
    thread.start()
    pipe(left, right)
    thread.join(timeout=2)
