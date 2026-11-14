"""Teaching implementation of RSA (key generation, signing, verification).

NOT for real security: pure Python, no side-channel protection. It exists so that every step of
RSA can be read, tested and compared with OpenSSL. Two signing modes are provided:
  * sign / verify           : SHA-256 + PKCS#1 v1.5 padding (what RS256 tokens use)
  * textbook_sign / ..verify: s = m^d mod n with NO padding (shown only to explain why it is unsafe)
"""
import hashlib
import hmac
import math
import secrets

_SMALL_PRIMES = [p for p in range(2, 1000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]
# DER prefix of DigestInfo for SHA-256 (RFC 8017, section 9.2)
DIGEST_INFO_SHA256 = bytes.fromhex("3031300d060960864801650304020105000420")


def is_probable_prime(n, rounds=40):
    """Miller-Rabin test. Error probability <= 4**-rounds for a random composite."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits):
    """Random prime of exactly `bits` bits (top two bits set so that p*q has full length)."""
    if bits < 8:
        raise ValueError("prime too small")
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(c):
            return c


class KeyPair:
    def __init__(self, n, e, d, p, q):
        self.n, self.e, self.d, self.p, self.q = n, e, d, p, q
        self.bits = n.bit_length()

    def public(self):
        return {"n": self.n, "e": self.e}

    def to_dict(self):
        return {"n": str(self.n), "e": self.e, "d": str(self.d), "p": str(self.p), "q": str(self.q)}

    @classmethod
    def from_dict(cls, d):
        return cls(int(d["n"]), int(d["e"]), int(d["d"]), int(d["p"]), int(d["q"]))


def generate(bits=1024, e=65537):
    """n = p*q, phi = (p-1)(q-1), d = e^-1 mod phi."""
    if bits < 512:
        raise ValueError("use toy_keys() for small educational keys; real keys need >= 512 bits here")
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits - bits // 2)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) != 1:
            continue
        return KeyPair(n, e, pow(e, -1, phi), p, q)


def toy_keys(p, q, e):
    """Small keys for the explanation panel (e.g. p=61, q=53, e=17 -> n=3233, d=2753)."""
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p and q must both be prime")
    if p == q:
        raise ValueError("p and q must differ")
    n, phi = p * q, (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError("e must be coprime with phi = %d" % phi)
    return {"p": p, "q": q, "n": n, "phi": phi, "e": e, "d": pow(e, -1, phi)}


def _i2b(x, k):
    return x.to_bytes(k, "big")


def emsa_pkcs1_v15(message, k):
    t = DIGEST_INFO_SHA256 + hashlib.sha256(message).digest()
    if k < len(t) + 11:
        raise ValueError("key too short for SHA-256 PKCS#1 v1.5")
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def sign(key, message):
    k = (key.n.bit_length() + 7) // 8
    m = int.from_bytes(emsa_pkcs1_v15(message, k), "big")
    return _i2b(pow(m, key.d, key.n), k)


def verify(n, e, message, signature):
    """Recompute the expected padded block and compare it with s^e mod n (no parsing of the block)."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    try:
        expected = emsa_pkcs1_v15(message, k)
    except ValueError:
        return False
    return hmac.compare_digest(_i2b(pow(s, e, n), k), expected)


# ---- textbook RSA (no padding) : for the lab only -------------------------------------------
def textbook_sign(n, d, m):
    return pow(m % n, d, n)


def textbook_verify(n, e, m, s):
    return pow(s, e, n) == m % n


def forge_multiplicative(n, m1, s1, m2, s2):
    """Without padding, sig(m1)*sig(m2) is a valid signature of m1*m2: the attacker signs a message
    nobody ever signed. Padding (PKCS#1 v1.5 / PSS) destroys this algebra."""
    return (m1 * m2) % n, (s1 * s2) % n


def factor_small(n, limit=2 ** 48):
    """Trial division: only works for tiny moduli. Shows why key size matters."""
    if n >= limit:
        raise ValueError("modulus too large for the classroom factoring demo (limit 2^48)")
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f * f <= n:
        if n % f == 0:
            return f, n // f
        f += 2
    return None


# ---- DER / PEM so that OpenSSL can read our public key ---------------------------------------
def _der(tag, body):
    ln = len(body)
    if ln < 128:
        head = bytes([tag, ln])
    else:
        lb = ln.to_bytes((ln.bit_length() + 7) // 8, "big")
        head = bytes([tag, 0x80 | len(lb)]) + lb
    return head + body


def _der_int(x):
    b = x.to_bytes((x.bit_length() + 8) // 8, "big")
    return _der(0x02, b)


def public_pem(n, e):
    import base64
    rsa_pub = _der(0x30, _der_int(n) + _der_int(e))
    algo = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + _der(0x05, b""))
    spki = _der(0x30, algo + _der(0x03, b"\x00" + rsa_pub))
    b64 = base64.encodebytes(spki).decode().replace("\n", "")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"
