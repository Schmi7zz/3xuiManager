"""Read and update a 3x-ui SQLite settings database.

The key names have stayed stable across panel versions (`webPort`, `webBasePath`,
`webListen`, `webCertFile`, `webKeyFile`). Values are returned as strings.
"""

import os
import sqlite3

SETTING_KEYS = ("webPort", "webBasePath", "webListen", "webCertFile", "webKeyFile", "webDomain")
DB_CANDIDATES = (
    "/etc/x-ui/x-ui.db",
    "/usr/local/x-ui/x-ui.db",
    "/etc/x-ui/db/x-ui.db",
    "/usr/local/x-ui/db/x-ui.db",
)


def find_db():
    folder = os.environ.get("XUI_DB_FOLDER") or ""
    candidates = []
    if folder:
        candidates.append(os.path.join(folder, "x-ui.db"))
    candidates.extend(DB_CANDIDATES)
    for path in candidates:
        if path and os.path.isfile(path):
            return path
    return ""


def _connect(path):
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    return con


def _settings_layout(con):
    tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    table = ""
    for name in ("settings", "setting"):
        if name in tables:
            table = name
            break
    if not table:
        raise LookupError("This database has no settings table. It does not look like 3x-ui.")
    cols = [row[1] for row in con.execute("PRAGMA table_info(%s)" % table)]
    key_col = "key" if "key" in cols else ""
    value_col = "value" if "value" in cols else ""
    if not key_col or not value_col:
        raise LookupError("Settings table is missing key/value columns: {}".format(", ".join(cols)))
    return table, key_col, value_col


def inspect_db(path):
    con = _connect(path)
    try:
        table, key_col, value_col = _settings_layout(con)
        query = 'SELECT "{}" AS k, "{}" AS v FROM {}'.format(key_col, value_col, table)
        settings = {}
        for row in con.execute(query):
            settings[str(row["k"])] = "" if row["v"] is None else str(row["v"])
        username = ""
        tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        if "users" in tables:
            user_cols = [row[1] for row in con.execute("PRAGMA table_info(users)")]
            if "username" in user_cols:
                found = con.execute("SELECT username FROM users ORDER BY id LIMIT 1").fetchone()
                if found and found[0]:
                    username = str(found[0])
        return {"path": path, "settings": settings, "admin_username": username}
    finally:
        con.close()


def update_settings(path, updates):
    con = _connect(path)
    try:
        table, key_col, value_col = _settings_layout(con)
        for key, value in updates.items():
            cur = con.execute(
                'UPDATE {} SET "{}"=? WHERE "{}"=?'.format(table, value_col, key_col),
                (str(value), key),
            )
            if cur.rowcount == 0:
                con.execute(
                    'INSERT INTO {} ("{}", "{}") VALUES (?, ?)'.format(table, key_col, value_col),
                    (key, str(value)),
                )
        con.commit()
    finally:
        con.close()
