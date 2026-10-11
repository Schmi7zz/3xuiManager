import base64
import hashlib
import hmac
import secrets
import threading
import time

SESSION_TTL = 12 * 3600
PBKDF2_ROUNDS = 200_000

_FAILS = {}
_FAILS_LOCK = threading.Lock()


def hash_password(password, salt=None, rounds=PBKDF2_ROUNDS):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds)
    return "pbkdf2${}${}${}".format(rounds, salt, dk.hex())


def check_password(password, stored):
    try:
        _, rounds, salt, hexd = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt.encode("utf-8"), int(rounds)
        )
        return hmac.compare_digest(dk.hex(), hexd)
    except Exception:
        return False


def make_token(username, secret):
    exp = int(time.time()) + SESSION_TTL
    payload = "{}|{}".format(username, exp)
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = "{}|{}".format(payload, sig)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def read_token(token, secret, users):
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii")).decode("utf-8")
        username, exp, sig = raw.rsplit("|", 2)
        good = hmac.new(
            secret.encode("utf-8"),
            "{}|{}".format(username, exp).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, good) or int(exp) < time.time():
            return None
        return username if username in users else None
    except Exception:
        return None


def login_blocked(ip, limit=8, window=900):
    now = time.time()
    with _FAILS_LOCK:
        row = _FAILS.get(ip)
        if not row:
            return False
        if now - row[1] > window:
            _FAILS.pop(ip, None)
            return False
        return row[0] >= limit


def note_fail(ip):
    now = time.time()
    with _FAILS_LOCK:
        row = _FAILS.get(ip)
        if not row or now - row[1] > 900:
            _FAILS[ip] = [1, now]
        else:
            row[0] += 1


def clear_fails(ip):
    with _FAILS_LOCK:
        _FAILS.pop(ip, None)
