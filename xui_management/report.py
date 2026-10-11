import time

from xui_management.scope import client_emails, parse_settings


def format_bytes(value):
    value = float(value or 0)
    units = ("B", "KB", "MB", "GB", "TB")
    index = 0
    while value >= 1024 and index < len(units) - 1:
        value /= 1024.0
        index += 1
    if index == 0:
        return "{} {}".format(int(value), units[index])
    return "{:.2f} {}".format(value, units[index])


def summarize_inbound(inbound, online_emails):
    settings = parse_settings(inbound.get("settings"))
    clients = settings.get("clients") or []
    stats = {}
    for row in inbound.get("clientStats") or []:
        email = str(row.get("email") or "").lower()
        if email:
            stats[email] = row
    now = time.time() * 1000
    expired = disabled = depleted = online = 0
    up = down = 0
    for client in clients:
        email = str(client.get("email") or "")
        if not client.get("enable", True):
            disabled += 1
        expiry = client.get("expiryTime") or 0
        try:
            expiry = int(expiry)
        except (TypeError, ValueError):
            expiry = 0
        if expiry > 0 and expiry < now:
            expired += 1
        row = stats.get(email.lower(), {})
        used = int(row.get("up") or 0) + int(row.get("down") or 0)
        up += int(row.get("up") or 0)
        down += int(row.get("down") or 0)
        total = int(client.get("totalGB") or 0)
        if total and used >= total:
            depleted += 1
        if email.lower() in online_emails:
            online += 1
    if not stats:
        up = int(inbound.get("up") or 0)
        down = int(inbound.get("down") or 0)
    return {
        "remark": inbound.get("remark") or "Inbound {}".format(inbound.get("id")),
        "port": inbound.get("port"),
        "protocol": inbound.get("protocol") or "",
        "enable": bool(inbound.get("enable", True)),
        "up": up,
        "down": down,
        "clients": len(clients),
        "online": online,
        "expired": expired,
        "disabled": disabled,
        "depleted": depleted,
        "emails": client_emails(inbound),
    }


def build_report(inbounds, online_emails, cpu):
    """Text for one user's bot. Callers must pass only that user's inbounds."""
    lines = []
    if not inbounds:
        lines.append("No inbound is assigned to you.")
    for inbound in inbounds:
        row = summarize_inbound(inbound, online_emails)
        state = "enabled" if row["enable"] else "disabled"
        lines.append(row["remark"])
        lines.append("port {} · {} · {}".format(row["port"], row["protocol"], state))
        lines.append("↑ {}    ↓ {}".format(format_bytes(row["up"]), format_bytes(row["down"])))
        lines.append("online {} / {} clients".format(row["online"], row["clients"]))
        extra = []
        if row["expired"]:
            extra.append("expired {}".format(row["expired"]))
        if row["depleted"]:
            extra.append("traffic ended {}".format(row["depleted"]))
        if row["disabled"]:
            extra.append("disabled {}".format(row["disabled"]))
        if extra:
            lines.append(" · ".join(extra))
        lines.append("")
    if cpu is None:
        lines.append("CPU: unavailable")
    else:
        lines.append("CPU: {:.0f}%".format(cpu))
    text = "\n".join(lines).strip()
    if len(text) > 3900:
        text = text[:3900] + "\n…"
    return text


def build_cpu_alert(inbounds, cpu, threshold):
    names = []
    for inbound in inbounds:
        remark = inbound.get("remark") or "Inbound {}".format(inbound.get("id"))
        names.append("{} (port {})".format(remark, inbound.get("port")))
    lines = [
        "CPU alert",
        "CPU: {:.0f}% (threshold {}%)".format(cpu, threshold),
    ]
    if names:
        lines.append("Your inbounds: " + ", ".join(names))
    return "\n".join(lines)
