"""Server side of the original restricted-user panel."""

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
import uuid

from xui_management.panel import PanelError

GB = 1024 ** 3
SESSION_TTL = 12 * 3600
XUI_API = None
CFG = {}
_LOCK = threading.Lock()

def _as_dict(value):
    if isinstance(value, dict):
        return value
    if not value or isinstance(value, (int, float)):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


_DEFAULTS = {"t": 0, "v": {}}


def panel_defaults():
    """subURI / remarkModel from 3x-ui settings, cached for 60s."""
    if time.time() - _DEFAULTS["t"] > 60:
        try:
            value = XUI_API.call_path("POST", "/panel/setting/defaultSettings", {}) or {}
            _DEFAULTS["v"] = value if isinstance(value, dict) else {}
        except Exception as e:
            sys.stderr.write(f"could not read panel settings: {e}\n")
        _DEFAULTS["t"] = time.time()
    return _DEFAULTS["v"]


# ------------------------------------------------- config link generation --
# Port of 3x-ui's sub/subService.go so links match what the panel shows.
def _search_key(data, key):
    if isinstance(data, dict):
        for k, v in data.items():
            if k == key:
                return v, True
            r, ok = _search_key(v, key)
            if ok:
                return r, True
    elif isinstance(data, list):
        for v in data:
            r, ok = _search_key(v, key)
            if ok:
                return r, True
    return None, False


def _search_host(headers):
    for k, v in (headers or {}).items():
        if k.lower() == "host":
            if isinstance(v, list):
                return v[0] if v else ""
            return v
    return ""


def _host_of(obj):
    return obj.get("host") or _search_host(obj.get("headers"))


def _remark(inbound, email, extra=""):
    model = panel_defaults().get("remarkModel") or "-ieo"
    sep, order = model[0], model[1:]
    parts = {"i": inbound.get("remark", ""), "e": email, "o": extra}
    return sep.join(parts[ch] for ch in order if parts.get(ch))


def _net_params(stream):
    net = stream.get("network", "tcp")
    p = {"type": net}
    if net == "tcp":
        header = (stream.get("tcpSettings") or {}).get("header") or {}
        if header.get("type") == "http":
            req = header.get("request") or {}
            p["path"] = (req.get("path") or ["/"])[0]
            p["host"] = _search_host(req.get("headers"))
            p["headerType"] = "http"
    elif net == "kcp":
        kcp = stream.get("kcpSettings") or {}
        p["headerType"] = (kcp.get("header") or {}).get("type", "none")
        p["seed"] = kcp.get("seed", "")
    elif net in ("ws", "httpupgrade", "xhttp"):
        s = stream.get(net + "Settings") or {}
        p["path"] = s.get("path", "/")
        p["host"] = _host_of(s)
        if net == "xhttp":
            p["mode"] = s.get("mode", "auto")
    elif net == "grpc":
        g = stream.get("grpcSettings") or {}
        p["serviceName"] = g.get("serviceName", "")
        p["authority"] = g.get("authority", "")
        if g.get("multiMode"):
            p["mode"] = "multi"
    return net, p


def _sec_params(stream, net, flow, allow_tls_flow):
    sec = stream.get("security", "none")
    p = {}
    if sec == "tls":
        p["security"] = "tls"
        t = stream.get("tlsSettings") or {}
        if t.get("alpn"):
            p["alpn"] = ",".join(t["alpn"])
        v, ok = _search_key(t, "serverName")
        if ok:
            p["sni"] = v
        v, ok = _search_key(t.get("settings") or {}, "fingerprint")
        if ok:
            p["fp"] = v
        if allow_tls_flow and net == "tcp" and flow:
            p["flow"] = flow
    elif sec == "reality":
        p["security"] = "reality"
        r = stream.get("realitySettings") or {}
        rs = r.get("settings") or {}
        if r.get("serverNames"):
            p["sni"] = secrets.choice(r["serverNames"])
        if rs.get("publicKey"):
            p["pbk"] = rs["publicKey"]
        if r.get("shortIds"):
            p["sid"] = secrets.choice(r["shortIds"])
        if rs.get("fingerprint"):
            p["fp"] = rs["fingerprint"]
        if rs.get("mldsa65Verify"):
            p["pqv"] = rs["mldsa65Verify"]
        p["spx"] = "/" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(15))
        if net == "tcp" and flow:
            p["flow"] = flow
    else:
        p["security"] = "none"
    return sec, p


def _fmt_host(h):
    return f"[{h}]" if ":" in h and not h.startswith("[") else h


def gen_links(inbound, client, default_host):
    proto = inbound.get("protocol")
    listen = inbound.get("listen") or ""
    addr = default_host if listen in ("", "0.0.0.0", "::", "::0") else listen
    stream = _as_dict(inbound.get("streamSettings"))
    settings = _as_dict(inbound.get("settings"))
    email = client.get("email", "")
    net, params = _net_params(stream)
    flow = client.get("flow", "")
    sec, sp = _sec_params(stream, net, flow, allow_tls_flow=(proto == "vless"))
    params.update(sp)
    if proto == "vless" and isinstance(settings.get("encryption"), str):
        params["encryption"] = settings["encryption"]
    targets = [(addr, inbound.get("port"), "same", "")]
    eps = stream.get("externalProxy") or []
    if eps:
        targets = [(ep.get("dest", addr), int(ep.get("port", 0)), ep.get("forceTls", "same"), ep.get("remark", "")) for ep in eps]

    links = []
    for dest, port, force, extra in targets:
        name = _remark(inbound, email, extra)
        if proto == "vmess":
            obj = {"v": "2", "add": dest, "port": port, "type": params.get("headerType", "none"),
                   "net": net, "id": client.get("id", ""), "scy": client.get("security", "auto"),
                   "tls": sec, "ps": name}
            for k_src, k_dst in (("path", "path"), ("host", "host"), ("serviceName", "path"),
                                 ("authority", "authority"), ("seed", "path"), ("sni", "sni"),
                                 ("alpn", "alpn"), ("fp", "fp")):
                if k_src in params:
                    obj[k_dst] = params[k_src]
            if net == "grpc" and params.get("mode") == "multi":
                obj["type"] = "multi"
            if net == "xhttp":
                obj["mode"] = params.get("mode", "auto")
            if force != "same":
                obj["tls"] = force
                if force == "none":
                    for k in ("alpn", "sni", "fp"):
                        obj.pop(k, None)
            raw = json.dumps(obj, indent=2, ensure_ascii=False)
            links.append("vmess://" + base64.b64encode(raw.encode()).decode())
            continue

        q = dict(params)
        if force != "same":
            q["security"] = force
            if force == "none":
                for k in ("alpn", "sni", "fp"):
                    q.pop(k, None)
        clean = []
        for key, value in q.items():
            if value is None or isinstance(value, (dict, list)):
                continue
            clean.append((key, value))
        query = urllib.parse.urlencode(sorted(clean))
        frag = urllib.parse.quote(name, safe="")
        hp = f"{_fmt_host(dest)}:{port}"
        if proto == "vless":
            links.append(f"vless://{client.get('id','')}@{hp}?{query}#{frag}")
        elif proto == "trojan":
            pw = urllib.parse.quote(client.get("password", ""), safe="")
            links.append(f"trojan://{pw}@{hp}?{query}#{frag}")
        elif proto == "shadowsocks":
            method = settings.get("method", "")
            enc = f"{method}:{client.get('password','')}"
            if method.startswith("2"):
                enc = f"{method}:{settings.get('password','')}:{client.get('password','')}"
            b = base64.b64encode(enc.encode()).decode()
            links.append(f"ss://{b}@{hp}?{query}#{frag}")
    return links


def sub_url(client, request_host):
    d = panel_defaults()
    sid = client.get("subId", "")
    if not sid:
        return ""
    base = CFG.get("sub_base_url") or ""
    if not base:
        if not d.get("subEnable") or not d.get("subURI"):
            return ""
        base = d["subURI"]
        # 3x-ui builds subURI from the host *we* used (127.0.0.1) -> swap in the real one
        u = urllib.parse.urlsplit(base)
        if u.hostname in ("127.0.0.1", "localhost", "::1"):
            netloc = _fmt_host(request_host) + (f":{u.port}" if u.port else "")
            base = urllib.parse.urlunsplit((u.scheme, netloc, u.path, "", ""))
    return base.rstrip("/") + "/" + sid


# --------------------------------------------------------------- sessions --
def make_token(username):
    exp = int(time.time()) + SESSION_TTL
    payload = f"{username}|{exp}"
    sig = hmac.new(CFG["secret_key"].encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()


def read_token(tok):
    try:
        raw = base64.urlsafe_b64decode(tok.encode()).decode()
        username, exp, sig = raw.rsplit("|", 2)
        good = hmac.new(CFG["secret_key"].encode(), f"{username}|{exp}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good) or int(exp) < time.time():
            return None
        return username if username in CFG["_users"] else None
    except Exception:
        return None


LOGIN_FAILS = {}  # ip -> [count, first_ts]


def login_blocked(ip):
    c = LOGIN_FAILS.get(ip)
    if not c:
        return False
    if time.time() - c[1] > 900:
        LOGIN_FAILS.pop(ip, None)
        return False
    return c[0] >= 5


def note_fail(ip):
    c = LOGIN_FAILS.setdefault(ip, [0, time.time()])
    c[0] += 1


# ------------------------------------------------------------ permissions --
def allowed_ids(username):
    """Resolve the user's allowed inbound ids (by id and/or by port)."""
    u = CFG["_users"][username]
    ids = set(u["inbound_ids"])
    if u["inbound_ports"]:
        for ib in XUI_API.inbounds():
            if int(ib.get("port", 0)) in u["inbound_ports"]:
                ids.add(int(ib["id"]))
    return ids


def require_inbound(username, iid):
    iid = int(iid)
    if iid not in allowed_ids(username):
        raise PermissionError("You don't have access to this inbound")
    return iid


def require_perm(username, perm):
    if not CFG["_users"][username]["perms"].get(perm):
        raise PermissionError(f"Not allowed: {perm}")


def client_id_of(protocol, c):
    if protocol == "trojan":
        return c.get("password", "")
    if protocol == "shadowsocks":
        return c.get("email", "")
    return c.get("id", "")


def find_client(inbound, email):
    settings = _as_dict(inbound.get("settings"))
    for c in settings.get("clients", []):
        if c.get("email", "").lower() == email.lower():
            return settings, c
    raise LookupError("Client not found in this inbound")


def safe_inbound_view(ib, onlines):
    """Strip anything sensitive (keys, private stream settings) before sending."""
    settings = _as_dict(ib.get("settings"))
    stats = {s["email"].lower(): s for s in (ib.get("clientStats") or [])}
    now = time.time() * 1000
    clients = []
    for idx, c in enumerate(settings.get("clients", [])):
        st = stats.get(c.get("email", "").lower(), {})
        used = st.get("up", 0) + st.get("down", 0)
        tot = c.get("totalGB", 0)
        exp = c.get("expiryTime", 0)
        clients.append({
            "email": c.get("email", ""),
            "enable": c.get("enable", True),
            "totalGB": tot,
            "expiryTime": exp,
            "limitIp": c.get("limitIp", 0),
            "comment": c.get("comment", ""),
            "up": st.get("up", 0),
            "down": st.get("down", 0),
            "lastOnline": st.get("lastOnline", 0),
            "online": c.get("email", "") in onlines,
            "createdAt": c.get("created_at", 0) or 0,
            "idx": idx,
            "depleted": bool((tot and used >= tot) or (exp > 0 and exp < now)),
        })
    return {
        "id": ib["id"], "remark": ib.get("remark", ""), "port": ib.get("port"),
        "protocol": ib.get("protocol"), "enable": ib.get("enable"),
        "up": ib.get("up", 0), "down": ib.get("down", 0), "total": ib.get("total", 0),
        "expiryTime": ib.get("expiryTime", 0), "clients": clients,
    }


def parse_common(data, c):
    """Apply editable fields from the UI onto a client dict."""
    if "total_gb" in data:
        g = float(data["total_gb"] or 0)
        if g < 0:
            raise ValueError("Traffic can't be negative")
        c["totalGB"] = int(g * GB)
    if "expiry_time" in data:
        c["expiryTime"] = int(data["expiry_time"] or 0)
    if "limit_ip" in data:
        c["limitIp"] = max(0, int(data["limit_ip"] or 0))
    if "comment" in data:
        c["comment"] = str(data["comment"])[:200]
    if "enable" in data:
        c["enable"] = bool(data["enable"])
    return c


def check_email(email):
    if not email or len(email) > 64 or any(ch in email for ch in "/ ?#%\\"):
        raise ValueError("Enter a valid client name (no spaces or / ? # %)")
    return email


def new_client(inbound, email):
    proto = inbound.get("protocol")
    settings = _as_dict(inbound.get("settings"))
    existing = settings.get("clients", [])
    tmpl = existing[0] if existing else {}
    c = {
        "email": email, "limitIp": 0, "totalGB": 0, "expiryTime": 0,
        "enable": True, "tgId": 0, "subId": secrets.token_hex(8),
        "comment": "", "reset": 0,
        "created_at": int(time.time() * 1000), "updated_at": int(time.time() * 1000),
    }
    if proto in ("vless", "vmess"):
        c["id"] = str(uuid.uuid4())
        if proto == "vless":
            c["flow"] = tmpl.get("flow", "")
        else:
            c["security"] = tmpl.get("security", "auto")
    elif proto == "trojan":
        c["password"] = secrets.token_urlsafe(12)
    elif proto == "shadowsocks":
        method = settings.get("method", "")
        if "2022" in method:
            n = 16 if "128" in method else 32
            c["password"] = base64.b64encode(os.urandom(n)).decode()
        else:
            c["password"] = secrets.token_urlsafe(12)
        c["method"] = tmpl.get("method", "")
    else:
        raise ValueError(f"Protocol '{proto}' has no clients to manage")
    return c


# ------------------------------------------------------------- API logic --
def api_dispatch(username, action, data, host):
    if action == "me":
        u = CFG["_users"][username]
        return {"username": username, "perms": u["perms"]}

    if action == "inbounds":
        ids = allowed_ids(username)
        onl = set(XUI_API.onlines())
        return [safe_inbound_view(ib, onl) for ib in XUI_API.inbounds() if int(ib["id"]) in ids]

    iid = require_inbound(username, data.get("inbound_id"))

    if action == "add":
        require_perm(username, "add")
        email = check_email((data.get("email") or "").strip())
        ib = XUI_API.inbound(iid)
        mx = CFG["_users"][username]["max_clients"]
        if mx and len(_as_dict(ib.get("settings")).get("clients", [])) >= mx:
            raise ValueError(f"Client limit reached ({mx})")
        c = parse_common(data, new_client(ib, email))
        XUI_API.call("POST", "/addClient",
                     {"id": iid, "settings": json.dumps({"clients": [c]})})
        return {"email": email}

    email = (data.get("email") or "").strip()
    ib = XUI_API.inbound(iid)
    settings, c = find_client(ib, email)  # proves the client belongs to this inbound

    if action == "links":
        h = CFG.get("server_address") or host
        return {"links": gen_links(ib, c, h), "sub": sub_url(c, h)}

    if action in ("toggle", "edit"):
        require_perm(username, "edit")
        cid = client_id_of(ib.get("protocol"), c)
        c = dict(c)
        if action == "toggle":
            c["enable"] = not c.get("enable", True)
        else:
            parse_common(data, c)
            if data.get("new_email") and data["new_email"].strip() != c["email"]:
                c["email"] = check_email(data["new_email"].strip())
        XUI_API.call("POST", f"/updateClient/{urllib.parse.quote(cid, safe='')}",
                     {"id": iid, "settings": json.dumps({"clients": [c]})})
        return {"ok": True}

    if action == "reset":
        require_perm(username, "reset")
        XUI_API.call("POST", f"/{iid}/resetClientTraffic/{urllib.parse.quote(c['email'], safe='')}", {})
        return {"ok": True}

    if action == "delete":
        require_perm(username, "delete")
        XUI_API.call("POST", f"/{iid}/delClientByEmail/{urllib.parse.quote(c['email'], safe='')}", {})
        return {"ok": True}

    raise ValueError("Unknown action")



class _Bridge(object):
    def __init__(self, panel):
        self.panel = panel

    def inbounds(self):
        return self.panel.inbounds(fresh=True)

    def onlines(self):
        return self.panel.onlines()

    def inbound(self, iid):
        wanted = int(iid)
        for row in self.inbounds():
            if int(row.get("id")) == wanted:
                return row
        raise LookupError("Inbound not found")

    def call(self, method, path, form=None):
        return self.panel.call_first(method, [
            "/panel/api/inbounds" + path,
            "/panel/inbound" + path,
        ], form)

    def call_path(self, method, path, form=None):
        paths = [path]
        if path.endswith("defaultSettings"):
            paths.append("/panel/api/setting/defaultSettings")
            paths.append("/panel/setting/defaultSettings")
        return self.panel.call_first(method, paths, form)


def run(panel, store, username, action, data, host):
    global XUI_API, CFG
    users = {}
    for user in store.data.get("users") or []:
        users[user["username"]] = {
            "password_hash": user.get("password_hash") or "",
            "inbound_ids": list(user.get("inbound_ids") or []),
            "inbound_ports": list(user.get("inbound_ports") or []),
            "perms": dict(user.get("permissions") or {}),
            "max_clients": int(user.get("max_clients") or 0),
        }
    with _LOCK:
        CFG = {
            "sub_base_url": store.data.get("sub_base_url") or "",
            "server_address": store.data.get("server_address") or "",
            "secret_key": store.data.get("secret_key") or "",
            "_users": users,
        }
        XUI_API = _Bridge(panel)
        return api_dispatch(username, action, data, host)
