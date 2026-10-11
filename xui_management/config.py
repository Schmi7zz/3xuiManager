import json
import os
import secrets
import tempfile
import threading

DEFAULT_PERMISSIONS = {"add": True, "edit": True, "delete": True, "reset": True}


def normalize_base(path):
    path = (path or "").strip()
    if path in ("", "/"):
        return "/"
    return "/" + path.strip("/") + "/"


def base_from_panel_url(panel_url):
    from urllib.parse import urlsplit

    return normalize_base(urlsplit(panel_url).path)


def default_telegram():
    return {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
        "report_minutes": 60,
        "cpu_threshold": 80,
    }


def normalize_user(raw):
    perms = dict(DEFAULT_PERMISSIONS)
    perms.update(raw.get("permissions") or {})
    tg = default_telegram()
    tg.update(raw.get("telegram") or {})
    minutes = int(tg.get("report_minutes") or 60)
    threshold = int(tg.get("cpu_threshold") or 0)
    return {
        "username": str(raw["username"]).strip(),
        "password_hash": raw.get("password_hash") or "",
        "inbound_ids": [int(i) for i in raw.get("inbound_ids") or []],
        "inbound_ports": [int(p) for p in raw.get("inbound_ports") or []],
        "max_clients": int(raw.get("max_clients") or 0),
        "permissions": {
            "add": bool(perms.get("add")),
            "edit": bool(perms.get("edit")),
            "delete": bool(perms.get("delete")),
            "reset": bool(perms.get("reset")),
        },
        "telegram": {
            "enabled": bool(tg.get("enabled")),
            "bot_token": str(tg.get("bot_token") or "").strip(),
            "chat_id": str(tg.get("chat_id") or "").strip(),
            "report_minutes": min(1440, max(5, minutes)),
            "cpu_threshold": min(100, max(0, threshold)),
        },
    }


class Store:
    def __init__(self, path):
        self.path = path
        self.lock = threading.RLock()
        self.data = {}

    def load(self):
        with self.lock:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            data["panel_url"] = str(data["panel_url"]).rstrip("/")
            data["listen_host"] = data.get("listen_host") or "0.0.0.0"
            data["listen_port"] = int(data.get("listen_port") or 2053)
            data["verify_tls"] = bool(data.get("verify_tls", False))
            data["public_base_path"] = normalize_base(
                data.get("public_base_path") or base_from_panel_url(data["panel_url"])
            )
            data["trusted_proxies"] = list(data.get("trusted_proxies") or [])
            data["panel_2fa_code"] = data.get("panel_2fa_code") or ""
            data["tls_cert"] = data.get("tls_cert") or ""
            data["tls_key"] = data.get("tls_key") or ""
            data["client_port"] = int(data.get("client_port") or 0)
            data["users"] = [normalize_user(u) for u in data.get("users") or []]
            generated = False
            if not data.get("secret_key"):
                data["secret_key"] = secrets.token_hex(32)
                generated = True
            self.data = data
            if generated:
                self.save()
            return data

    def save(self):
        with self.lock:
            payload = dict(self.data)
            payload["users"] = [normalize_user(u) for u in payload.get("users") or []]
            self.data["users"] = payload["users"]
            directory = os.path.dirname(os.path.abspath(self.path)) or "."
            fd, tmp = tempfile.mkstemp(prefix=".config-", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2)
                    handle.write("\n")
                os.replace(tmp, self.path)
            except Exception:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                raise
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass

    def users_by_name(self):
        with self.lock:
            return {u["username"]: u for u in self.data.get("users") or []}

    def public_users(self):
        rows = []
        with self.lock:
            for user in self.data.get("users") or []:
                tg = user["telegram"]
                rows.append({
                    "username": user["username"],
                    "inbound_ids": list(user["inbound_ids"]),
                    "inbound_ports": list(user["inbound_ports"]),
                    "max_clients": user["max_clients"],
                    "permissions": dict(user["permissions"]),
                    "telegram": {
                        "enabled": tg["enabled"],
                        "bot_token": tg["bot_token"],
                        "chat_id": tg["chat_id"],
                        "report_minutes": tg["report_minutes"],
                        "cpu_threshold": tg["cpu_threshold"],
                    },
                })
        return rows
