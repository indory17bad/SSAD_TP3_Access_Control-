"""Password storage: salted, deliberately slow PBKDF2-HMAC-SHA256. Format  pbkdf2_sha256$iterations$salt$hash."""
import hashlib
import hmac
import secrets

ITERATIONS = 100_000


def hash_password(password, iterations=ITERATIONS, salt=None):
    salt = salt if salt is not None else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return "pbkdf2_sha256$%d$%s$%s" % (iterations, salt.hex(), dk.hex())


def verify_password(password, stored):
    try:
        algo, it, salt, good = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
    except Exception:
        return False
    return hmac.compare_digest(dk.hex(), good)          # constant-time comparison


def md5_unsalted(password):
    """The weak way, kept ONLY to compare in the lab: fast, no salt -> same password = same hash."""
    return hashlib.md5(password.encode()).hexdigest()
