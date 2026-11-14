"""Signed access tokens:  base64url(header) . base64url(payload) . base64url(RSA signature).

The payload is ENCODED, not encrypted: anyone can read it. The signature only guarantees that it
was not changed. Verification order matters: structure -> algorithm allow-list -> key -> signature
-> claims. The algorithm comes from OUR allow-list, never from the token (blocks 'alg: none' and
RS256/HS256 confusion).
"""
import base64
import json
import secrets
import time

from . import rsa

ALG = "RS256"
ISSUER = "securehub-auth"
AUDIENCE = "securehub-api"
TAMPER_REASONS = {"malformed", "alg_not_allowed", "unknown_kid", "bad_signature"}


class TokenError(Exception):
    def __init__(self, reason, message=""):
        super().__init__(message or reason)
        self.reason = reason


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        raise TokenError("malformed", "not base64url")


class Keyring:
    """kid -> key. Rotation adds a new active key and retires the old one (tokens signed by a
    retired key are refused with reason 'retired_key')."""

    def __init__(self, bits=1024, keys=None):
        self.bits = bits
        self.keys = {}
        self.active = None
        if keys:
            for kid, rec in keys["keys"].items():
                self.keys[kid] = {"key": rsa.KeyPair.from_dict(rec["key"]), "status": rec["status"]}
            self.active = keys["active"]
        else:
            self.rotate()

    def rotate(self):
        if self.active:
            self.keys[self.active]["status"] = "retired"
        kid = "k%d" % (len(self.keys) + 1)
        self.keys[kid] = {"key": rsa.generate(self.bits), "status": "active"}
        self.active = kid
        return kid

    def to_dict(self):
        return {"active": self.active,
                "keys": {k: {"key": v["key"].to_dict(), "status": v["status"]} for k, v in self.keys.items()}}

    def public_info(self):
        out = []
        for kid, v in self.keys.items():
            k = v["key"]
            out.append({"kid": kid, "status": v["status"], "bits": k.bits, "n": str(k.n), "e": k.e,
                        "pem": rsa.public_pem(k.n, k.e)})
        return {"alg": ALG, "active": self.active, "keys": out}


def issue(keyring, sub, role, ttl=900, now=None, aud=AUDIENCE, extra=None):
    now = int(time.time() if now is None else now)
    header = {"alg": ALG, "typ": "SHT", "kid": keyring.active}
    payload = {"iss": ISSUER, "sub": sub, "role": role, "aud": aud, "iat": now, "exp": now + int(ttl),
               "jti": secrets.token_hex(8)}
    if extra:
        payload.update(extra)
    signing_input = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
        b64u(json.dumps(payload, separators=(",", ":")).encode())
    sig = rsa.sign(keyring.keys[keyring.active]["key"], signing_input.encode())
    return signing_input + "." + b64u(sig), payload


def decode_unverified(token):
    """For display only (token inspector). NEVER use the result to make a decision."""
    parts = token.split(".")
    if len(parts) != 3:
        raise TokenError("malformed", "a token has exactly three parts")
    try:
        return (json.loads(unb64u(parts[0])), json.loads(unb64u(parts[1])), unb64u(parts[2]))
    except TokenError:
        raise
    except Exception:
        raise TokenError("malformed", "header or payload is not JSON")


def verify(keyring, token, now=None, aud=AUDIENCE, revoked=()):
    now = int(time.time() if now is None else now)
    if not isinstance(token, str) or len(token) > 4096:
        raise TokenError("malformed", "missing or too long")
    header, payload, sig = decode_unverified(token)
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise TokenError("malformed", "header and payload must be objects")
    if header.get("alg") != ALG:                       # allow-list: refuses none, HS256, ...
        raise TokenError("alg_not_allowed", "algorithm %r is not accepted" % (header.get("alg"),))
    kid = header.get("kid")
    rec = keyring.keys.get(kid) if isinstance(kid, str) else None
    if rec is None:
        raise TokenError("unknown_kid", "unknown key id")
    signing_input = token.rsplit(".", 1)[0].encode()
    if not rsa.verify(rec["key"].n, rec["key"].e, signing_input, sig):
        raise TokenError("bad_signature", "signature does not match")
    if rec["status"] != "active":
        raise TokenError("retired_key", "signed with a retired key")
    for field in ("iss", "sub", "role", "aud", "iat", "exp", "jti"):
        if field not in payload:
            raise TokenError("malformed", "missing claim " + field)
    if not isinstance(payload["exp"], int) or not isinstance(payload["iat"], int):
        raise TokenError("malformed", "iat and exp must be integers")
    if payload["iss"] != ISSUER:
        raise TokenError("wrong_issuer", "unexpected issuer")
    if payload["aud"] != aud:
        raise TokenError("wrong_audience", "token is for another service")
    if payload["exp"] <= now:
        raise TokenError("expired", "token has expired")
    if payload["iat"] > now + 30:
        raise TokenError("not_yet_valid", "issued in the future")
    if payload["jti"] in revoked:
        raise TokenError("revoked", "token was logged out")
    return payload
