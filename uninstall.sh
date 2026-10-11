#!/usr/bin/env bash
# Put 3x-ui back on its original port and stop xui-management.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root."
  exit 1
fi

DIR=/opt/xui-management
if [ ! -f "$DIR/restore.json" ]; then
  echo "No $DIR/restore.json, so the original port is unknown."
  exit 1
fi

systemctl disable --now xui-management >/dev/null 2>&1 || true
python3 - <<PY
import json, sys
sys.path.insert(0, "$DIR")
from xui_management.xui_db import update_settings
restore = json.load(open("$DIR/restore.json", encoding="utf-8"))
update_settings(restore["db"], restore["settings"])
print(restore.get("service") or "x-ui")
PY
SERVICE="$(python3 -c "import json; print(json.load(open('$DIR/restore.json', encoding='utf-8')).get('service') or 'x-ui')")"
systemctl restart "$SERVICE" || true
echo "3x-ui is restored. xui-management is stopped. Files are still in $DIR."
