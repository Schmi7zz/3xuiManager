import json
import os
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from xui_management.auth import check_password, hash_password, make_token, read_token
from xui_management.config import Store
from xui_management.panel import PanelClient
from xui_management.report import build_cpu_alert, build_report
from xui_management.scope import (
    collect_inbound_ids,
    decide,
    filter_payload,
    inbound_allowed,
)
from xui_management.server import make_server
from xui_management.xui_db import inspect_db, update_settings


INBOUNDS = [
    {
        "id": 25,
        "port": 1337,
        "protocol": "vless",
        "remark": "Devilish",
        "enable": True,
        "settings": json.dumps({"clients": [{"email": "alice", "enable": True, "totalGB": 0, "expiryTime": 0}]}),
        "streamSettings": json.dumps({
            "network": "tcp",
            "security": "reality",
            "realitySettings": {"privateKey": "SECRET-KEY", "settings": {"publicKey": "pub"}},
        }),
        "up": 10,
        "down": 20,
        "clientStats": [{"email": "alice", "up": 5, "down": 7}],
    },
    {
        "id": 8,
        "port": 443,
        "protocol": "vmess",
        "remark": "Other",
        "enable": True,
        "settings": json.dumps({"clients": [{"email": "bob", "enable": True}]}),
        "streamSettings": "{}",
        "up": 1,
        "down": 1,
        "clientStats": [],
    },
]


class FakePanel(BaseHTTPRequestHandler):
    hits = {"login": 0, "setting": 0, "add25": 0, "add8": 0}

    def log_message(self, fmt, *args):
        return

    def _json(self, code, obj, cookie=None):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def _authed(self):
        return "3x-ui=adminsession" in (self.headers.get("Cookie") or "")

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path.endswith("/panel/api/inbounds/list"):
            if not self._authed():
                return self._json(401, {"success": False, "msg": "login"})
            return self._json(200, {"success": True, "obj": INBOUNDS})
        if path.endswith("/panel/csrf-token"):
            if not self._authed():
                return self._json(401, {"success": False})
            return self._json(200, {"success": True, "obj": "csrf-token"})
        if path.endswith("/panel/api/server/status"):
            return self._json(200, {"success": True, "obj": {"cpu": 12.5, "mem": 40, "config": "SECRET-CONFIG"}})
        html = "<!doctype html><html><head><title>3x-ui</title></head><body><div id=\"app\"></div></body></html>"
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        path = self.path.split("?", 1)[0]
        if path.endswith("/panel/inbound/list") or path.endswith("/panel/api/inbounds/list"):
            if not self._authed():
                return self._json(401, {"success": False, "msg": "login"})
            return self._json(200, {"success": True, "obj": INBOUNDS})
        if path.endswith("/login"):
            FakePanel.hits["login"] += 1
            try:
                data = json.loads(body.decode("utf-8"))
            except ValueError:
                data = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8")).items()}
            if data.get("username") == "admin" and data.get("password") == "admin":
                return self._json(200, {"success": True}, "3x-ui=adminsession; Path=/; HttpOnly")
            return self._json(401, {"success": False, "msg": "wrong"})
        if "/setting/update" in path:
            FakePanel.hits["setting"] += 1
            return self._json(200, {"success": True, "obj": {"token": "should-not-leak"}})
        if path.endswith("/addClient"):
            form = urllib.parse.parse_qs(body.decode("utf-8"))
            inbound_id = (form.get("id") or ["0"])[0]
            FakePanel.hits["add" + inbound_id] = FakePanel.hits.get("add" + inbound_id, 0) + 1
            if not self._authed():
                return self._json(401, {"success": False})
            return self._json(200, {"success": True, "obj": {"email": "new"}})
        if path.endswith("/onlines"):
            return self._json(200, {"success": True, "obj": ["alice", "bob"]})
        return self._json(404, {"success": False, "msg": path})


class ScopeTests(unittest.TestCase):
    def test_pages_and_apis(self):
        self.assertEqual(decide("GET", "/secret/panel/api/inbounds/list")[0], "filter")
        self.assertEqual(decide("POST", "/secret/panel/inbound/list")[0], "filter")
        self.assertEqual(decide("POST", "/secret/panel/inbound/add")[0], "deny")
        self.assertEqual(decide("GET", "/secret/panel/xray")[0], "deny")
        self.assertEqual(decide("POST", "/secret/panel/api/setting/update")[0], "deny")
        self.assertEqual(decide("POST", "/secret/panel/api/inbounds/addClient"), ("mutation", "add"))
        self.assertEqual(decide("GET", "/secret/assets/index-abc.js")[0], "pass")
        self.assertEqual(decide("GET", "/secret/panel/api/server/status")[0], "filter")
        self.assertEqual(decide("POST", "/secret/panel/api/server/restartXrayService")[0], "deny")

    def test_filter_strips_other_inbounds_and_private_key(self):
        payload = {"success": True, "obj": json.loads(json.dumps(INBOUNDS))}
        filtered = filter_payload("/panel/api/inbounds/list", payload, {25}, set(), {"alice"})
        self.assertEqual([row["remark"] for row in filtered["obj"]], ["Devilish"])
        blob = json.dumps(filtered)
        self.assertNotIn("SECRET-KEY", blob)
        self.assertNotIn("Other", blob)
        self.assertIn("pub", blob)
        self.assertIn("alice", blob)

    def test_onlines_and_clients_are_scoped(self):
        onlines = filter_payload(
            "/panel/api/inbounds/onlines",
            {"success": True, "obj": ["alice", "bob"]},
            {25},
            set(),
            {"alice"},
        )
        self.assertEqual(onlines["obj"], ["alice"])
        clients = filter_payload(
            "/panel/api/clients",
            {"success": True, "obj": {"total": 2, "clients": [
                {"email": "alice", "inboundId": 25},
                {"email": "bob", "inboundId": 8},
            ]}},
            {25},
            set(),
            {"alice"},
        )
        self.assertEqual(clients["obj"]["total"], 1)
        self.assertEqual(clients["obj"]["clients"][0]["email"], "alice")

    def test_status_keeps_cpu_and_drops_config(self):
        status = filter_payload(
            "/panel/api/server/status",
            {"success": True, "obj": {"cpu": 10, "config": "SECRET-CONFIG"}},
            {25},
            set(),
            set(),
        )
        self.assertEqual(status["obj"]["cpu"], 10)
        self.assertNotIn("config", status["obj"])

    def test_port_access_and_request_ids(self):
        self.assertTrue(inbound_allowed({"id": 9, "port": 1337, "protocol": "vless"}, set(), {1337}))
        self.assertFalse(inbound_allowed({"id": 9, "port": 443, "protocol": "vless"}, {25}, {1337}))
        ids = collect_inbound_ids("/panel/api/inbounds/addClient", b"id=25&settings={}", "application/x-www-form-urlencoded")
        self.assertEqual(ids, {25})
        ids = collect_inbound_ids("/panel/api/inbounds/addClient", json.dumps({"id": 8, "settings": "{}"}).encode(), "application/json")
        self.assertEqual(ids, {8})

    def test_report_mentions_only_the_assigned_inbound(self):
        text = build_report([INBOUNDS[0]], {"alice"}, 23.2)
        self.assertIn("Devilish", text)
        self.assertIn("CPU: 23%", text)
        self.assertNotIn("Other", text)
        self.assertNotIn("bob", text)
        alert = build_cpu_alert([INBOUNDS[0]], 91, 80)
        self.assertIn("Devilish", alert)
        self.assertNotIn("Other", alert)


class AuthTests(unittest.TestCase):
    def test_password_and_token(self):
        stored = hash_password("correct-horse")
        self.assertTrue(check_password("correct-horse", stored))
        self.assertFalse(check_password("wrong-horse", stored))
        token = make_token("devilish", "secret")
        self.assertEqual(read_token(token, "secret", {"devilish": {}}), "devilish")
        self.assertIsNone(read_token(token, "other", {"devilish": {}}))
        self.assertIsNone(read_token(token + "x", "secret", {"devilish": {}}))


class DatabaseTests(unittest.TestCase):
    def test_round_trip(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            con = sqlite3.connect(path)
            con.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")
            con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
            con.execute("INSERT INTO settings (key, value) VALUES ('webPort', '2053')")
            con.execute("INSERT INTO settings (key, value) VALUES ('webBasePath', '/abc/')")
            con.execute("INSERT INTO users (username, password) VALUES ('admin', 'hashed')")
            con.commit()
            con.close()
            info = inspect_db(path)
            self.assertEqual(info["settings"]["webPort"], "2053")
            self.assertEqual(info["admin_username"], "admin")
            update_settings(path, {"webPort": "3053", "webListen": "127.0.0.1"})
            info = inspect_db(path)
            self.assertEqual(info["settings"]["webPort"], "3053")
            self.assertEqual(info["settings"]["webListen"], "127.0.0.1")
            self.assertEqual(info["settings"]["webBasePath"], "/abc/")
        finally:
            os.remove(path)


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        FakePanel.hits = {"login": 0, "setting": 0, "add25": 0, "add8": 0}
        cls.fake = ThreadingHTTPServer(("127.0.0.1", 0), FakePanel)
        cls.fake.daemon_threads = True
        threading.Thread(target=cls.fake.serve_forever, daemon=True).start()
        fake_port = cls.fake.server_address[1]
        fd, cls.config_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        password = hash_password("user-pass-1")
        with open(cls.config_path, "w", encoding="utf-8") as handle:
            json.dump({
                "panel_url": "http://127.0.0.1:%d/secret" % fake_port,
                "panel_username": "admin",
                "panel_password": "admin",
                "verify_tls": False,
                "listen_host": "127.0.0.1",
                "listen_port": 0,
                "public_base_path": "/secret/",
                "secret_key": "test-secret",
                "users": [{
                    "username": "devilish",
                    "password_hash": password,
                    "inbound_ids": [25],
                    "inbound_ports": [],
                    "max_clients": 0,
                    "permissions": {"add": True, "edit": True, "delete": False, "reset": True},
                    "telegram": {"enabled": False, "bot_token": "", "chat_id": "", "report_minutes": 60, "cpu_threshold": 0},
                }],
            }, handle)
        cls.store = Store(cls.config_path)
        cls.store.load()
        cls.panel = PanelClient(cls.store.data)
        cls.httpd = make_server(cls.store, cls.panel)
        cls.httpd.daemon_threads = True
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()
        cls.proxy = "http://127.0.0.1:%d" % cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.fake.shutdown()
        cls.httpd.server_close()
        cls.fake.server_close()
        os.remove(cls.config_path)

    def _opener(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

    def _open(self, opener, method, path, body=None, headers=None):
        data = None if body is None else body if isinstance(body, bytes) else body.encode("utf-8")
        req = urllib.request.Request(self.proxy + path, data=data, method=method, headers=headers or {})
        try:
            with opener.open(req, timeout=10) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), exc.headers

    def test_restricted_user_sees_only_their_inbound(self):
        opener = self._opener()
        before_login = FakePanel.hits["login"]
        status, body, _headers = self._open(
            opener, "POST", "/secret/login",
            json.dumps({"username": "devilish", "password": "user-pass-1"}),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(FakePanel.hits["login"], before_login)
        status, body, _headers = self._open(
            opener, "POST", "/secret/__xmgmt/api/client/inbounds",
            "{}",
            {"Content-Type": "application/json", "X-XS": "1"},
        )
        self.assertEqual(status, 200, body)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual([row["remark"] for row in payload["data"]], ["Devilish"])
        self.assertNotIn("SECRET-KEY", body.decode("utf-8"))
        status, _body, _headers = self._open(
            opener, "POST", "/secret/panel/api/setting/update",
            "{}",
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(FakePanel.hits["setting"], 0)
        status, _body, _headers = self._open(
            opener, "POST", "/secret/panel/api/inbounds/addClient",
            "id=8&settings={}",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(FakePanel.hits.get("add8", 0), 0)

    def test_restricted_user_is_sent_to_the_original_panel(self):
        import http.client
        from urllib.parse import urlsplit

        opener = self._opener()
        self._open(
            opener, "POST", "/secret/login",
            json.dumps({"username": "devilish", "password": "user-pass-1"}),
            {"Content-Type": "application/json"},
        )
        cookie = ""
        for handler in opener.handlers:
            jar = getattr(handler, "cookiejar", None)
            if jar:
                req = urllib.request.Request(self.proxy + "/secret/panel/inbounds")
                jar.add_cookie_header(req)
                cookie = req.get_header("Cookie") or ""
        parts = urlsplit(self.proxy)
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
        conn.request("GET", "/secret/panel/inbounds", headers={"Cookie": cookie})
        response = conn.getresponse()
        location = response.getheader("Location") or ""
        response.read()
        self.assertEqual(response.status, 302)
        self.assertIn("/__xmgmt/client", location)
        conn.request(
            "POST",
            "/secret/__xmgmt/api/client/inbounds",
            b"{}",
            {"Cookie": cookie, "Content-Type": "application/json", "X-XS": "1"},
        )
        listed = conn.getresponse()
        payload = json.loads(listed.read().decode("utf-8"))
        self.assertEqual(listed.status, 200, payload)
        self.assertTrue(payload.get("ok"), payload)
        self.assertEqual([row["port"] for row in payload["data"]], [1337])
        self.assertNotIn("Other", json.dumps(payload))
        conn.close()
        conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
        conn.request(
            "POST",
            "/secret/__xmgmt/api/client/links",
            json.dumps({"inbound_id": 25, "email": "alice"}).encode("utf-8"),
            {"Cookie": cookie, "Content-Type": "application/json", "X-XS": "1"},
        )
        linked = conn.getresponse()
        link_body = linked.read().decode("utf-8")
        self.assertEqual(linked.status, 200, link_body)
        link_payload = json.loads(link_body)
        self.assertTrue(link_payload["data"]["links"][0].startswith("vless://"), link_payload)

    def test_dashboard_html_contains_management_hook(self):
        opener = self._opener()
        self._open(
            opener, "POST", "/secret/login",
            json.dumps({"username": "admin", "password": "admin"}),
            {"Content-Type": "application/json"},
        )
        status, body, _headers = self._open(opener, "GET", "/secret/panel/inbounds")
        self.assertEqual(status, 200)
        self.assertIn("/secret/__xmgmt/inject.js", body.decode("utf-8"))
        status, body, _headers = self._open(opener, "GET", "/secret/panel/api/inbounds/list")
        text = body.decode("utf-8")
        self.assertIn("Devilish", text)
        self.assertIn("Other", text)

    def test_admin_can_create_a_user(self):
        opener = self._opener()
        self._open(
            opener, "POST", "/secret/login",
            json.dumps({"username": "admin", "password": "admin"}),
            {"Content-Type": "application/json"},
        )
        status, body, _headers = self._open(
            opener, "POST", "/secret/__xmgmt/api/users/save",
            json.dumps({
                "username": "shop",
                "password": "shop-pass-1",
                "inbound_ids": [25],
                "inbound_ports": [1337],
                "max_clients": 10,
                "permissions": {"add": True, "edit": True, "delete": False, "reset": True},
                "telegram": {"enabled": False, "bot_token": "", "chat_id": "", "report_minutes": 30, "cpu_threshold": 90},
            }),
            {"Content-Type": "application/json", "X-XMGMT": "1"},
        )
        self.assertEqual(status, 200, body)
        status, body, _headers = self._open(opener, "GET", "/secret/__xmgmt/api/users")
        names = [row["username"] for row in json.loads(body.decode("utf-8"))["obj"]]
        self.assertIn("shop", names)
        self.assertIn("devilish", names)

    def test_inbounds_load_from_the_browser_session_when_saved_password_is_wrong(self):
        previous = self.store.data["panel_password"]
        self.store.data["panel_password"] = "not-the-password"
        self.panel.logged_in = False
        opener = self._opener()
        try:
            self._open(
                opener, "POST", "/secret/login",
                json.dumps({"username": "admin", "password": "admin"}),
                {"Content-Type": "application/json"},
            )
            status, body, _headers = self._open(opener, "GET", "/secret/__xmgmt/api/inbounds")
            self.assertEqual(status, 200, body)
            data = json.loads(body.decode("utf-8"))
            self.assertEqual(sorted(row["port"] for row in data["obj"]), [443, 1337])
            self.assertTrue(data.get("warning"))
        finally:
            self.store.data["panel_password"] = previous
            self.panel.logged_in = False


if __name__ == "__main__":
    unittest.main()
