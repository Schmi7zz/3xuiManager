#!/usr/bin/env bash
# Install xui-management in front of an existing 3x-ui. The public URL stays
# the same. 3x-ui itself moves to localhost so a restricted user cannot skip
# this add-on. Running it again updates the files and keeps config.json.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root on the 3x-ui server."
  exit 1
fi

DIR=/opt/xui-management
SRC="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$DIR"
if [ "$SRC" != "$DIR" ]; then
  rm -rf "$DIR/xui_management"
  cp -a "$SRC/xui_management" "$DIR/xui_management"
fi
export PYTHONPATH="$DIR"

if ! id xui-mgmt >/dev/null 2>&1; then
  useradd --system --home "$DIR" --shell /usr/sbin/nologin xui-mgmt || true
fi
command -v python3 >/dev/null || { apt-get update && apt-get install -y python3; }

if [ -f "$DIR/config.json" ] && [ -f "$DIR/restore.json" ]; then
  chown -R xui-mgmt:xui-mgmt "$DIR" 2>/dev/null || true
  systemctl daemon-reload
  systemctl restart xui-management
  echo "Updated. Config and the 3x-ui port were left as they are."
  exit 0
fi

python3 - <<'PY'
import json
import os
from xui_management.xui_db import find_db, inspect_db

path = find_db()
out = {"found": False}
if path:
    info = inspect_db(path)
    settings = info["settings"]
    out = {
        "found": True,
        "db": path,
        "admin_username": info.get("admin_username") or "",
        "webPort": settings.get("webPort") or "2053",
        "webBasePath": settings.get("webBasePath") or "/",
        "webListen": settings.get("webListen") or "",
        "webCertFile": settings.get("webCertFile") or "",
        "webKeyFile": settings.get("webKeyFile") or "",
    }
with open("/opt/xui-management/discovered.json", "w", encoding="utf-8") as handle:
    json.dump(out, handle)
PY

FOUND="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['found'])")"
if [ "$FOUND" != "True" ]; then
  echo "Could not find x-ui.db. Set XUI_DB_FOLDER and run again, or copy config.example.json to config.json."
  exit 1
fi

DB="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['db'])")"
ADMIN_USER="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['admin_username'])")"
WEB_PORT="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['webPort'])")"
WEB_PATH="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['webBasePath'])")"
WEB_LISTEN="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['webListen'])")"
CERT="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['webCertFile'])")"
KEY="$(python3 -c "import json; print(json.load(open('$DIR/discovered.json'))['webKeyFile'])")"
rm -f "$DIR/discovered.json"

echo "Found 3x-ui database: $DB"
echo "Current panel port: $WEB_PORT  base path: $WEB_PATH"
if [ -n "$ADMIN_USER" ]; then
  echo "Admin username in the database: $ADMIN_USER"
fi
read -rp "3x-ui admin username [${ADMIN_USER:-admin}]: " AUSER
AUSER="${AUSER:-${ADMIN_USER:-admin}}"
read -rsp "3x-ui admin password: " APASS
echo
read -rp "Keep this public port [$WEB_PORT]: " PUBLIC_PORT
PUBLIC_PORT="${PUBLIC_PORT:-$WEB_PORT}"

INTERNAL="$(PUBLIC_PORT="$PUBLIC_PORT" python3 - <<'PY'
import os
import socket
public = int(os.environ["PUBLIC_PORT"])
for port in (public + 10000, 20530, 39999, 28765):
    if port == public or port < 1 or port > 65535:
        continue
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        continue
    finally:
        sock.close()
    print(port)
    break
PY
)"
if [ -z "$INTERNAL" ]; then
  echo "Could not choose an internal port for 3x-ui."
  exit 1
fi

SCHEME=http
TLS_CERT=""
TLS_KEY=""
if [ -n "$CERT" ] && [ -n "$KEY" ] && [ -f "$CERT" ] && [ -f "$KEY" ]; then
  SCHEME=https
  mkdir -p "$DIR/tls"
  cp "$CERT" "$DIR/tls/cert.pem"
  cp "$KEY" "$DIR/tls/key.pem"
  TLS_CERT="$DIR/tls/cert.pem"
  TLS_KEY="$DIR/tls/key.pem"
fi

LISTEN_HOST="$WEB_LISTEN"
if [ -z "$LISTEN_HOST" ] || [ "$LISTEN_HOST" = "0.0.0.0" ] || [ "$LISTEN_HOST" = "::" ]; then
  LISTEN_HOST="0.0.0.0"
fi

export PANEL_URL="$SCHEME://127.0.0.1:$INTERNAL"
export AUSER APASS PUBLIC_PORT LISTEN_HOST TLS_CERT TLS_KEY WEB_PATH
python3 - <<'PY' > "$DIR/config.json"
import json
import os
from xui_management.config import normalize_base

base = normalize_base(os.environ["WEB_PATH"])
panel = os.environ["PANEL_URL"].rstrip("/")
if base != "/":
    panel += base.rstrip("/")
print(json.dumps({
    "panel_url": panel,
    "panel_username": os.environ["AUSER"],
    "panel_password": os.environ["APASS"],
    "panel_2fa_code": "",
    "verify_tls": False,
    "listen_host": os.environ["LISTEN_HOST"],
    "listen_port": int(os.environ["PUBLIC_PORT"]),
    "public_base_path": base,
    "tls_cert": os.environ.get("TLS_CERT") or "",
    "tls_key": os.environ.get("TLS_KEY") or "",
    "trusted_proxies": [],
    "users": [],
}, indent=2))
PY

export RESTORE_DB="$DB" RESTORE_PORT="$WEB_PORT" RESTORE_LISTEN="$WEB_LISTEN"
python3 - <<'PY' > "$DIR/restore.json"
import json
import os
print(json.dumps({
    "db": os.environ["RESTORE_DB"],
    "service": "x-ui",
    "settings": {
        "webPort": os.environ["RESTORE_PORT"],
        "webListen": os.environ["RESTORE_LISTEN"],
    },
}, indent=2))
PY

if systemctl cat x-ui.service >/dev/null 2>&1; then
  SERVICE=x-ui
else
  SERVICE=x-ui
fi

export REBIND_DB="$DB" REBIND_PORT="$INTERNAL"
python3 - <<'PY'
import os
from xui_management.xui_db import update_settings
update_settings(os.environ["REBIND_DB"], {
    "webPort": os.environ["REBIND_PORT"],
    "webListen": "127.0.0.1",
})
PY

systemctl restart "$SERVICE" || echo "Restart $SERVICE yourself so 3x-ui binds 127.0.0.1:$INTERNAL"

export INTERNAL
python3 - <<'PY'
import os
import socket
import sys
import time
port = int(os.environ["INTERNAL"])
for _ in range(20):
    try:
        sock = socket.create_connection(("127.0.0.1", port), 1)
        sock.close()
        raise SystemExit(0)
    except OSError:
        time.sleep(0.5)
sys.exit("3x-ui did not start on 127.0.0.1:%s" % port)
PY

RUN_USER=xui-mgmt
if ! id xui-mgmt >/dev/null 2>&1; then
  RUN_USER=root
  echo "Could not create user xui-mgmt. The service will run as root."
fi

cat > /etc/systemd/system/xui-management.service <<EOF
[Unit]
Description=xui-management (scoped users inside 3x-ui)
After=network.target ${SERVICE}.service

[Service]
User=$RUN_USER
WorkingDirectory=$DIR
Environment=PYTHONPATH=$DIR
ExecStart=/usr/bin/python3 -m xui_management -c $DIR/config.json
Restart=always
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

chown -R "$RUN_USER":"$RUN_USER" "$DIR"
chmod 600 "$DIR/config.json" "$DIR/restore.json"
systemctl daemon-reload
if ! systemctl enable --now xui-management; then
  echo "xui-management failed to start. Restoring the 3x-ui port."
  export REBIND_DB="$DB" REBIND_PORT="$WEB_PORT" REBIND_LISTEN="$WEB_LISTEN"
  python3 - <<'PY'
import os
from xui_management.xui_db import update_settings
update_settings(os.environ["REBIND_DB"], {
    "webPort": os.environ["REBIND_PORT"],
    "webListen": os.environ["REBIND_LISTEN"],
})
PY
  systemctl restart "$SERVICE" || true
  exit 1
fi

echo
echo "Done. Open the panel on the same URL as before."
echo "Management is in the sidebar, under Xray Configs."
echo "Logs: journalctl -u xui-management -f"
