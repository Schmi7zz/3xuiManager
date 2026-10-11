"""Per-user Telegram bots.

Each bot only receives the inbounds assigned to that user, plus CPU. It never
includes other inbounds, panel settings, or the admin account.
"""

import json
import sys
import threading
import time
import urllib.error
import urllib.request

from xui_management.cpu import cpu_percent
from xui_management.report import build_cpu_alert, build_report
from xui_management.scope import client_emails, inbound_allowed


class TelegramError(RuntimeError):
    pass


def api(token, method, payload, timeout=20):
    url = "https://api.telegram.org/bot{}/{}".format(token, method)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:200]
        raise TelegramError("Telegram HTTP {}: {}".format(exc.code, detail))
    except urllib.error.URLError as exc:
        raise TelegramError("Telegram unreachable: {}".format(exc.reason))
    if not body.get("ok"):
        raise TelegramError(body.get("description") or "Telegram request failed")
    return body.get("result")


def send_message(token, chat_id, text):
    return api(token, "sendMessage", {"chat_id": chat_id, "text": text})


class Reporter(threading.Thread):
    def __init__(self, store, panel):
        super().__init__(name="xui-management-telegram", daemon=True)
        self.store = store
        self.panel = panel
        self.stop = threading.Event()
        self.last_report = {}
        self.last_alert = {}
        self.offsets = {}

    def shutdown(self):
        self.stop.set()

    def run(self):
        # The first periodic report waits for a full interval. CPU alerts still fire.
        now = time.time()
        for user in self.store.users_by_name().values():
            self.last_report[user["username"]] = now
        while not self.stop.wait(3):
            try:
                self._tick()
            except Exception as exc:
                sys.stderr.write("telegram tick failed: {}\n".format(exc))

    def _tick(self):
        users = [
            user
            for user in self.store.users_by_name().values()
            if user["telegram"]["enabled"] and user["telegram"]["bot_token"] and user["telegram"]["chat_id"]
        ]
        if not users:
            return
        try:
            inbounds = self.panel.inbounds(fresh=True)
            online = {item.lower() for item in self.panel.onlines()}
        except Exception as exc:
            sys.stderr.write("telegram could not read the panel: {}\n".format(exc))
            return
        cpu = cpu_percent(0.3)
        for user in users:
            allowed = [
                row for row in inbounds
                if inbound_allowed(row, set(user["inbound_ids"]), set(user["inbound_ports"]))
            ]
            emails = set()
            for row in allowed:
                emails |= client_emails(row)
            self._commands(user, allowed, online & emails if emails else set(), cpu)
            self._scheduled(user, allowed, online, cpu)

    def _commands(self, user, allowed, online, cpu):
        tg = user["telegram"]
        token = tg["bot_token"]
        try:
            updates = api(
                token,
                "getUpdates",
                {"offset": self.offsets.get(token, 0), "timeout": 0, "allowed_updates": ["message"]},
                timeout=15,
            ) or []
        except TelegramError as exc:
            sys.stderr.write("telegram poll for {}: {}\n".format(user["username"], exc))
            return
        for update in updates:
            self.offsets[token] = max(self.offsets.get(token, 0), int(update.get("update_id", 0)) + 1)
            message = update.get("message") or {}
            chat = message.get("chat") or {}
            if str(chat.get("id", "")) != str(tg["chat_id"]):
                continue
            text = (message.get("text") or "").strip().lower()
            if text.startswith("/status") or text.startswith("/start"):
                try:
                    send_message(token, tg["chat_id"], build_report(allowed, online, cpu))
                except TelegramError as exc:
                    sys.stderr.write("telegram reply failed: {}\n".format(exc))

    def _scheduled(self, user, allowed, online, cpu):
        tg = user["telegram"]
        now = time.time()
        name = user["username"]
        if now - self.last_report.get(name, 0) >= tg["report_minutes"] * 60:
            try:
                send_message(tg["bot_token"], tg["chat_id"], build_report(allowed, online, cpu))
                self.last_report[name] = now
            except TelegramError as exc:
                sys.stderr.write("telegram report for {} failed: {}\n".format(name, exc))
        threshold = tg["cpu_threshold"]
        if threshold and cpu is not None and cpu >= threshold:
            if now - self.last_alert.get(name, 0) >= 600:
                try:
                    send_message(
                        tg["bot_token"],
                        tg["chat_id"],
                        build_cpu_alert(allowed, cpu, threshold),
                    )
                    self.last_alert[name] = now
                except TelegramError as exc:
                    sys.stderr.write("telegram cpu alert for {} failed: {}\n".format(name, exc))
