"""Decide what a restricted user may do, and strip other inbounds out of API payloads.

The path rules are intentionally narrow. A new 3x-ui release can rename a page
and the admin panel still works, because admin traffic is not filtered. A
restricted user only gets through when the path is a known inbound/client read
or a client change on an inbound they were assigned.
"""

import json
import re

_PAGE_DENY = re.compile(
    r"/(?:xray|nodes|hosts|settings|setting|api-docs|groups|outbound|routing)(?:/|$)"
)

_DENY_PARTS = (
    "/panel/api/setting",
    "/panel/api/xray",
    "/panel/api/nodes",
    "/panel/api/node",
    "/panel/api/hosts",
    "/panel/api/outbound",
    "/panel/api/routing",
    "/panel/api/groups",
    "/panel/api/custom-geo",
    "/panel/setting",
    "/panel/xray",
    "/xui/setting",
    "/xui/xray",
    "/xui/api/setting",
    "backuptotgbot",
    "getconfigjson",
    "importdb",
    "getdb",
    "exportdb",
    "/ws",
)

_SECRET_KEYS = {"privatekey"}

_ADD = ("addclient", "/clients/add", "createclient")
_EDIT = ("updateclient", "/clients/update", "editclient")
_DELETE = ("delclient", "deleteclient", "/clients/del", "deldepletedclients")
_RESET = ("resetclient", "resettraffic", "resetallclienttraffics")
_READ_POST = ("onlines", "lastonline", "clientips", "/inbound/list", "/inbounds/list")


def _path(path):
    return (path or "").split("?", 1)[0].lower()


def decide(method, path):
    """Return (action, permission).

    action is "pass" (html/assets), "filter" (read and strip), "mutation", or "deny".
    """
    method = (method or "GET").upper()
    p = _path(path)
    if any(part in p for part in _DENY_PARTS):
        return "deny", None
    if "/api/" not in p and _PAGE_DENY.search(p):
        return "deny", None
    if "/panel/api/server/" in p or p.endswith("/panel/api/server"):
        if method in ("GET", "HEAD") and p.rstrip("/").endswith("/status"):
            return "filter", None
        return "deny", None

    if method in ("GET", "HEAD", "OPTIONS"):
        if _is_api(p):
            return "filter", None
        return "pass", None

    if any(part in p for part in _READ_POST):
        return "filter", None
    if any(part in p for part in _ADD):
        return "mutation", "add"
    if any(part in p for part in _EDIT):
        return "mutation", "edit"
    if any(part in p for part in _DELETE):
        return "mutation", "delete"
    if any(part in p for part in _RESET):
        return "mutation", "reset"
    if _is_api(p) or "/inbound" in p:
        return "deny", None
    return "pass", None


def _is_api(path):
    return any(
        part in path
        for part in (
            "/panel/api/",
            "/xui/api/",
            "/xui/inbound",
            "/server/status",
            "/csrf-token",
        )
    )


def inbound_allowed(inbound, ids, ports):
    try:
        iid = int(inbound.get("id"))
    except (TypeError, ValueError):
        return False
    if iid in ids:
        return True
    try:
        port = int(inbound.get("port") or 0)
    except (TypeError, ValueError):
        port = 0
    return bool(port and port in ports)


def _is_inbound(obj):
    return (
        isinstance(obj, dict)
        and "id" in obj
        and "port" in obj
        and any(key in obj for key in ("protocol", "settings", "streamSettings", "stream_settings"))
    )


def _client_inbound_id(obj):
    if not isinstance(obj, dict):
        return None
    for key in ("inboundId", "inbound_id", "inboundID"):
        if key in obj and obj[key] not in (None, ""):
            try:
                return int(obj[key])
            except (TypeError, ValueError):
                return None
    return None


def scrub(value):
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if str(key).lower() in _SECRET_KEYS:
                continue
            if key in ("settings", "streamSettings", "stream_settings", "sniffing") and isinstance(item, str):
                cleaned[key] = _scrub_json_string(item)
            else:
                cleaned[key] = scrub(item)
        return cleaned
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value


def _scrub_json_string(text):
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return text
    if not isinstance(parsed, (dict, list)):
        return text
    return json.dumps(scrub(parsed), ensure_ascii=False, separators=(",", ":"))


def _scrub_status(payload):
    if not isinstance(payload, dict):
        return payload
    obj = payload.get("obj")
    if isinstance(obj, dict):
        for key in list(obj):
            if str(key).lower() in ("config", "xrayconfig", "configjson"):
                obj.pop(key, None)
    return payload


def filter_payload(path, payload, ids, ports, emails):
    """Return a payload that only contains this user's inbounds.

    Raises PermissionError when the payload is a single inbound they cannot see.
    """
    if not isinstance(payload, dict):
        return payload
    p = _path(path)
    if p.rstrip("/").endswith("/csrf-token"):
        return payload
    if "/server/" in p and p.rstrip("/").endswith("/status"):
        return _scrub_status(payload)

    key = "obj" if "obj" in payload else "data" if "data" in payload else None
    if key is None:
        if _is_api(p):
            raise PermissionError("This response is not available for a restricted user")
        return payload
    payload[key] = _filter_obj(p, payload[key], ids, ports, emails)
    return payload


def _filter_obj(path, obj, ids, ports, emails):
    if isinstance(obj, list):
        if not obj:
            return obj
        if all(isinstance(item, str) for item in obj):
            if "online" not in path and "clientip" not in path:
                raise PermissionError("This response is not available for a restricted user")
            allowed = {email.lower() for email in emails}
            return [item for item in obj if item.lower() in allowed]
        if isinstance(obj[0], dict) and _is_inbound(obj[0]):
            return [scrub(item) for item in obj if inbound_allowed(item, ids, ports)]
        if isinstance(obj[0], dict) and _client_inbound_id(obj[0]) is not None:
            return [item for item in obj if _client_inbound_id(item) in ids]
        raise PermissionError("This response is not available for a restricted user")
    if isinstance(obj, dict):
        if _is_inbound(obj):
            if not inbound_allowed(obj, ids, ports):
                raise PermissionError("You don't have access to this inbound")
            return scrub(obj)
        if obj and ("lastonline" in path or "online" in path):
            allowed = {email.lower() for email in emails}
            return {key: value for key, value in obj.items() if str(key).lower() in allowed}
        for key in ("clients", "inbounds", "items", "rows"):
            if isinstance(obj.get(key), list):
                obj[key] = _filter_obj(path, obj[key], ids, ports, emails)
                if "total" in obj and isinstance(obj[key], list):
                    obj["total"] = len(obj[key])
                return obj
        if not obj:
            return obj
        raise PermissionError("This response is not available for a restricted user")
    return obj


_ID_KEYS = ("inboundId", "inbound_id", "inboundID")
_PATH_ID = re.compile(r"/(?:get|del|update|resetallclienttraffics|deldepletedclients)/(\d+)(?:/|$)", re.I)
_NESTED_ID = re.compile(r"/inbounds/(\d+)/", re.I)


def collect_inbound_ids(path, body, content_type):
    found = set()
    for match in _PATH_ID.finditer(path or ""):
        found.add(int(match.group(1)))
    for match in _NESTED_ID.finditer(path or ""):
        found.add(int(match.group(1)))
    if not body:
        return found
    ctype = (content_type or "").lower()
    if "json" in ctype or (body[:1] in (b"{", b"[")):
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise PermissionError("Could not read this request")
        _collect_from_json(parsed, found, depth=0)
        return found
    from urllib.parse import parse_qs

    try:
        form = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except UnicodeError:
        raise PermissionError("Could not read this request")
    for key in ("id", "inboundId", "inbound_id"):
        for value in form.get(key, []):
            if value.isdigit():
                found.add(int(value))
    return found


def _collect_from_json(value, found, depth):
    if depth > 6:
        return
    if isinstance(value, dict):
        for key in _ID_KEYS:
            if key in value and _as_int(value[key]) is not None:
                found.add(_as_int(value[key]))
        if "id" in value and _as_int(value["id"]) is not None and "email" not in value and "password" not in value:
            # A bare numeric id on a client object is the client uuid's sibling, not the inbound.
            # Inbound mutations use "id" for the inbound. Client objects also carry "email".
            if "protocol" in value or "streamSettings" in value or "settings" in value or "clients" not in value:
                if "email" not in value:
                    found.add(_as_int(value["id"]))
        if "id" in value and _as_int(value["id"]) is not None and ("clients" in value or "protocol" in value):
            found.add(_as_int(value["id"]))
        for item in value.values():
            _collect_from_json(item, found, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _collect_from_json(item, found, depth + 1)


def _as_int(value):
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def assert_ids_allowed(ids, allowed_ids):
    if not ids:
        raise PermissionError("This action needs an inbound you were assigned")
    for iid in ids:
        if iid not in allowed_ids:
            raise PermissionError("You don't have access to this inbound")


def parse_settings(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def client_count(inbound):
    return len(parse_settings(inbound.get("settings")).get("clients") or [])


def client_emails(inbound):
    emails = set()
    for client in parse_settings(inbound.get("settings")).get("clients") or []:
        email = client.get("email")
        if email:
            emails.add(str(email).lower())
    return emails
