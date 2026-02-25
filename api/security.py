from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_agent_token() -> str:
    # 32 bytes -> 43-ish chars URL-safe; prefix keeps tokens recognizable.
    return "svr_live_" + secrets.token_urlsafe(32)


def hash_agent_token(raw_token: str, pepper: str) -> str:
    return hmac.new(pepper.encode("utf-8"), raw_token.encode("utf-8"), hashlib.sha256).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
