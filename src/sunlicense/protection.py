"""Protection for a licensed product: core unlock, tamper reports, the ownership notice and protected files.

The same behaviour as the Java SDK's ``SunLicenseProtection``, in Python's idiom::

    client = SunLicense(base_url="https://api.sunlicense.com", token=os.environ["SUNLICENSE_API_KEY"])
    protection = client.protection(
        license_key=key, fingerprint=machine_id,
        product="My Bot", owner="Example Studio", terms="https://example.com/terms",
        product_code="my-bot",              # for protected files
        cache_directory="data",             # where the 7-day unlock cache lives
    )
    print(protection.notice())              # one line: product, owner, masked key
    client.validate(key, fingerprint=machine_id)   # sends integrity, keeps or forgets the unlock
    core = protection.unseal(SEALED_CORE)   # raises Locked without a valid unlock
    protection.integrity(os.path.dirname(__file__))  # "OK" / "MODIFIED", sent with the next check
    rules = protection.protected_file("rules.dat")   # Standard plan

Core unlock: ``sunlicense seal`` encrypts part of the product (its "core") under a key only SunLicense holds. A
valid license check answers with that key (``unlock``); a rejected one (suspended, expired, revoked...) doesn't, and
the unlock this install had is forgotten. So a copy whose license check was cut out can't run its core. To keep
working through outages the unlock from the last valid check is cached on disk for 7 days, encrypted with a key
derived from the license key, the machine id and this machine.

Needs nothing but the standard library: AES-GCM uses ``cryptography`` when it is installed and a small pure-Python
implementation otherwise. Offline license files (``accept_offline``) need ``cryptography`` (Ed25519).

Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then fails
its integrity check and is reported. Protection raises the cost and makes leaks visible.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

try:  # pragma: no cover - depends on the environment
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except Exception:  # pragma: no cover
    _AESGCM = None

DEFAULT_BASE_URL = "https://api.sunlicense.com"
CACHE_TTL = 7 * 24 * 3600  # seconds the unlock from the last valid check keeps working without an answer
_SKEW = 10 * 60
SEALED_PREFIX = "SLS1."
_SEALED_AAD = b"SLS1"
_CACHE_PREFIX = "SLC1."
_CACHE_FILE = ".sunlicense-unlock-"
_MAX_DETAIL = 200


class Locked(Exception):
    """No unlock: the license wasn't confirmed valid (online, cached or offline), or the data was sealed for another
    product."""


class Refused(IOError):
    """A protected file SunLicense refused (license not valid, file missing, plan without protected files).

    ``status``: 401/403 refused, 404 no such file, 402 plan without protected files.
    """

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


# ---- AES-256-GCM: cryptography when installed, else pure Python ----

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def _xtime(x: int) -> int:
    x <<= 1
    return x ^ 0x11B if x & 0x100 else x


_TE = [[0] * 256 for _ in range(4)]
for _i in range(256):
    _s = _SBOX[_i]
    _s2 = _xtime(_s)
    _s3 = _s2 ^ _s
    _TE[0][_i] = (_s2 << 24) | (_s << 16) | (_s << 8) | _s3
    _TE[1][_i] = (_s3 << 24) | (_s2 << 16) | (_s << 8) | _s
    _TE[2][_i] = (_s << 24) | (_s3 << 16) | (_s2 << 8) | _s
    _TE[3][_i] = (_s << 24) | (_s << 16) | (_s3 << 8) | _s2


def _sub_word(w: int) -> int:
    return (_SBOX[w >> 24] << 24) | (_SBOX[(w >> 16) & 255] << 16) | (_SBOX[(w >> 8) & 255] << 8) | _SBOX[w & 255]


def _expand_key(key: bytes) -> List[int]:
    nk = len(key) // 4
    rounds = nk + 6
    w = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (rounds + 1)):
        t = w[i - 1]
        if i % nk == 0:
            t = _sub_word(((t << 8) | (t >> 24)) & 0xFFFFFFFF) ^ (rcon << 24)
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = _sub_word(t)
        w.append(w[i - nk] ^ t)
    return w


def _encrypt_block(rk: List[int], block: bytes) -> bytes:
    te0, te1, te2, te3 = _TE
    s = [int.from_bytes(block[4 * i:4 * i + 4], "big") ^ rk[i] for i in range(4)]
    rounds = len(rk) // 4 - 1
    k = 4
    for _ in range(rounds - 1):
        s = [te0[s[i] >> 24] ^ te1[(s[(i + 1) % 4] >> 16) & 255] ^ te2[(s[(i + 2) % 4] >> 8) & 255]
             ^ te3[s[(i + 3) % 4] & 255] ^ rk[k + i] for i in range(4)]
        k += 4
    out = b""
    for i in range(4):
        w = (_SBOX[s[i] >> 24] << 24) | (_SBOX[(s[(i + 1) % 4] >> 16) & 255] << 16) \
            | (_SBOX[(s[(i + 2) % 4] >> 8) & 255] << 8) | _SBOX[s[(i + 3) % 4] & 255]
        out += (w ^ rk[k + i]).to_bytes(4, "big")
    return out


def _gf_mul(x: int, y: int) -> int:
    r = 0xE1 << 120
    z = 0
    for i in range(127, -1, -1):
        if (y >> i) & 1:
            z ^= x
        x = (x >> 1) ^ r if x & 1 else x >> 1
    return z


def _ghash(h: int, aad: bytes, ct: bytes) -> bytes:
    y = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            block = data[i:i + 16].ljust(16, b"\0")
            y = _gf_mul(y ^ int.from_bytes(block, "big"), h)
    y = _gf_mul(y ^ ((len(aad) * 8) << 64 | (len(ct) * 8)), h)
    return y.to_bytes(16, "big")


def _gcm(key: bytes, nonce: bytes, data: bytes, aad: bytes) -> Tuple[bytes, bytes, int]:
    rk = _expand_key(key)
    h = int.from_bytes(_encrypt_block(rk, b"\0" * 16), "big")
    if len(nonce) == 12:
        j0 = nonce + b"\0\0\0\1"
    else:
        j0 = _ghash(h, b"", nonce)
    counter = int.from_bytes(j0[12:], "big")
    out = bytearray()
    for i in range(0, len(data), 16):
        counter = (counter + 1) & 0xFFFFFFFF
        ks = _encrypt_block(rk, j0[:12] + counter.to_bytes(4, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out), j0, h


def gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """AES-GCM: ciphertext || 16-byte tag."""
    if _AESGCM is not None:
        return _AESGCM(key).encrypt(nonce, plaintext, aad or None)
    ct, j0, h = _gcm(key, nonce, plaintext, aad)
    tag = bytes(a ^ b for a, b in zip(_encrypt_block(_expand_key(key), j0), _ghash(h, aad, ct)))
    return ct + tag


def gcm_decrypt(key: bytes, nonce: bytes, data: bytes, aad: bytes = b"") -> Optional[bytes]:
    """AES-GCM decryption of ciphertext || tag; None when the tag doesn't match (wrong key or changed data)."""
    if len(key) not in (16, 24, 32) or len(data) < 16:
        return None
    if _AESGCM is not None:
        try:
            return _AESGCM(key).decrypt(nonce, data, aad or None)
        except Exception:
            return None
    ct, tag = data[:-16], data[-16:]
    pt, j0, h = _gcm(key, nonce, ct, aad)
    expected = bytes(a ^ b for a, b in zip(_encrypt_block(_expand_key(key), j0), _ghash(h, aad, ct)))
    return pt if hmac.compare_digest(expected, tag) else None


# ---- helpers ----


def _trim(s: Any) -> Optional[str]:
    if s is None:
        return None
    t = str(s).strip()
    return t or None


def decode_base64(s: str) -> bytes:
    """Base64 in any flavour the server may send: url-safe or standard, with or without padding."""
    t = str(s).strip().replace("-", "+").replace("_", "/").rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9+/]*", t) or len(t) % 4 == 1:
        raise ValueError("not base64")
    return base64.b64decode(t + "=" * (-len(t) % 4))


def digest(data: Union[bytes, str]) -> str:
    """Lowercase hex SHA-256."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def normalise_digest(d: str) -> str:
    """A digest as compared: lowercase, without a "sha256:" prefix."""
    t = str(d).strip().lower()
    return t[7:] if t.startswith("sha256:") else t


def mask(key: Optional[str]) -> str:
    """"AX8P-XXXX-XXXX-XXXX": the first group, the rest as X."""
    k = _trim(key)
    if not k:
        return "(none)"
    groups = k.split("-")
    if len(groups) == 1:
        return k[:4] + "X" * max(0, len(k) - 4)
    return "-".join([groups[0]] + ["X" * len(g) for g in groups[1:]])


def detail(changed: List[str]) -> str:
    """"N changed: a, b, +3 more", at most 200 characters (sent as integrityDetail)."""
    b = "%d changed: " % len(changed)
    shown = 0
    for c in changed:
        nxt = ("" if shown == 0 else ", ") + c
        reserve = 16 if shown + 1 < len(changed) else 0
        if len(b) + len(nxt) + reserve > _MAX_DETAIL:
            break
        b += nxt
        shown += 1
    if shown < len(changed):
        b += ("" if shown == 0 else ", ") + "+%d more" % (len(changed) - shown)
    return b[:_MAX_DETAIL]


def open_sealed(sealed: str, key: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Opens an ``SLS1.`` blob: ``'SLS1.' + base64url(nonce 12 || AES-256-GCM ciphertext || tag 16)``, AAD ``SLS1``,
    plaintext JSON ``{"v":1,"digests":{path: sha256hex},"data":"<base64>"}``. Raises Locked on a wrong key or
    changed data."""
    s = _trim(sealed)
    if not s or not s.startswith(SEALED_PREFIX):
        raise Locked("Not sealed data: expected text starting with " + SEALED_PREFIX)
    try:
        raw = decode_base64(s[len(SEALED_PREFIX):])
    except ValueError:
        raise Locked("Not sealed data: not base64url")
    if len(raw) < 12 + 16:
        raise Locked("Not sealed data: too short")
    plain = gcm_decrypt(key, raw[:12], raw[12:], _SEALED_AAD)
    if plain is None:
        raise Locked("This data wasn't sealed for this product's unlock (sealed for another product, or re-sealed since).")
    try:
        m = json.loads(plain.decode("utf-8"))
    except ValueError:
        raise Locked("Not sealed data: sealed content isn't readable")
    if not isinstance(m, dict) or not isinstance(m.get("data"), str):
        raise Locked("Not sealed data: sealed content has no data")
    digests = {}
    if isinstance(m.get("digests"), dict):
        for p in sorted(m["digests"]):
            if isinstance(m["digests"][p], str):
                digests[str(p)] = m["digests"][p].lower()
    return decode_base64(m["data"]), digests


def machine_id() -> str:
    """SHA-256 of the OS, architecture, host name and hardware address: what makes a copied cache file useless
    elsewhere."""
    raw = "%s|%s" % (platform.system(), platform.machine())
    try:
        raw += "|" + socket.gethostname()
    except Exception:
        raw += "|?"
    try:
        node = uuid.getnode()
        raw += "|" + ("" if (node >> 40) & 1 else "%012x" % node)  # a random node id isn't hardware
    except Exception:
        raw += "|?"
    return digest(raw)


def _valid_key(k: bytes) -> bool:
    return len(k) in (16, 24, 32)


Reader = Callable[[str], Optional[Union[bytes, str]]]


class SunLicenseProtection:
    """Core unlock, tamper reports, the ownership notice and protected files (see the module docs)."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        api_key: Optional[str] = None,
        license_key: Optional[str] = None,
        fingerprint: Optional[str] = None,
        product_code: Optional[str] = None,
        product: Optional[str] = None,
        owner: Optional[str] = None,
        terms: Optional[str] = None,
        cache_directory: Any = "~",
        timeout: float = 15.0,
        user_agent: Optional[str] = None,
        _now: Optional[Callable[[], float]] = None,
        _machine: Optional[Callable[[], str]] = None,
        _get: Optional[Callable[[str, Dict[str, str]], Tuple[int, bytes]]] = None,
    ) -> None:
        """
        Args:
            base_url: Default https://api.sunlicense.com.
            api_key: Your API key (protected files).
            license_key: The license key this install checks with.
            fingerprint: The machine id it checks with.
            product_code: The product's code in SunLicense (protected files).
            product: Product name for :meth:`notice`.
            owner: Owner (seller) name for :meth:`notice`.
            terms: Terms link :meth:`notice` ends with.
            cache_directory: Where the unlock cache is kept; None = memory only. Default ``~/.sunlicense``.
        """
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = _trim(api_key)
        self.license_key = _trim(license_key)
        self.fingerprint = _trim(fingerprint)
        self.product_code = _trim(product_code)
        self.product_name = _trim(product)
        self.owner = _trim(owner)
        self.terms = _trim(terms)
        if cache_directory == "~":
            cache_directory = os.path.join(os.path.expanduser("~"), ".sunlicense")
        self.cache_directory = cache_directory
        self.timeout = timeout
        self._user_agent = user_agent or "sunlicense-python"
        self._now = _now or time.time
        self._machine = _machine or machine_id
        self._get = _get
        self._unlock: Optional[bytes] = None
        self._digests: Dict[str, str] = {}
        self._integrity: Optional[str] = None
        self._integrity_detail: Optional[str] = None

    # ---- license and answers ----

    def license(self, license_key: Optional[str], fingerprint: Optional[str] = None) -> None:
        """The license key and machine id this install checks with; a different key drops the unlock held in
        memory."""
        key = _trim(license_key)
        if key is None or key != self.license_key:
            self._unlock = None
        self.license_key = key
        self.fingerprint = _trim(fingerprint)

    def accept(self, body: Any) -> None:
        """Reads a license check's answer (the JSON body, as text or parsed, of ``/api/v2/license/validate`` or
        ``/api/v1/validate``). A valid answer with ``unlock`` keeps and caches it; a definite "no" (``valid: false``)
        forgets it. Anything unreadable is ignored (treat that like no answer). Never raises."""
        parsed = body
        if isinstance(body, (bytes, str)):
            try:
                parsed = json.loads(body)
            except ValueError:
                return
        if not isinstance(parsed, dict):
            return
        if parsed.get("valid") is True:
            u = parsed.get("unlock")
            self.accept_answer(True, u if isinstance(u, str) else None)
        elif parsed.get("valid") is False:
            self.accept_answer(False)

    def accept_answer(self, valid: bool, unlock_base64: Optional[str] = None) -> None:
        """Same as :meth:`accept` for an answer already read: valid with its unlock (or None), or rejected."""
        if not valid:
            self.rejected()
            return
        if not _trim(unlock_base64):
            return  # valid, but the product has nothing sealed: keep what we have
        try:
            key = base64.b64decode(str(unlock_base64).strip(), validate=True)
        except ValueError:
            return
        if not _valid_key(key):
            return
        self._unlock = key
        self._write_cache(key)

    def rejected(self) -> None:
        """SunLicense said no: the unlock (in memory and on disk) is gone until the next valid check."""
        self._unlock = None
        f = self._cache_file()
        if f:
            try:
                os.remove(f)
            except OSError:
                pass

    def accept_offline(self, file: str, public_key_base64: str) -> bool:
        """Takes the unlock from an offline license file (``.lic``): checks its Ed25519 signature with the
        organization's public key (base64 X.509), that it is for this license key and not expired or past its refresh
        window. Returns False (and changes nothing) when the file isn't usable, carries no unlock, or ``cryptography``
        isn't installed."""
        payload = _verified_offline(file, public_key_base64)
        if payload is None:
            return False
        lk = payload.get("licenseKey")
        if self.license_key and isinstance(lk, str) and self.license_key.lower() != lk.strip().lower():
            return False
        now = self._now()
        issued = _instant(payload.get("issuedAt"))
        if issued is not None and issued > now + _SKEW:
            return False
        policy = payload.get("policy")
        expires = _instant(policy.get("expiresAt")) if isinstance(policy, dict) else None
        if expires is not None and now >= expires:
            return False
        refresh = _instant(payload.get("refreshAfter"))
        if refresh is not None and now >= refresh:
            return False
        u = payload.get("unlock")
        if not isinstance(u, str):
            return False
        try:
            k = base64.b64decode(u.strip(), validate=True)
        except ValueError:
            return False
        if not _valid_key(k):
            return False
        self._unlock = k  # the file is its own cache: nothing written to disk
        return True

    def unlocked(self) -> bool:
        """True when an unlock is available: from this run's valid check, the offline file, or the cache (≤ 7 days)."""
        return self._key() is not None

    # ---- core unlock ----

    def unseal(self, sealed: Union[str, bytes]) -> bytes:
        """Decrypts data sealed with ``sunlicense seal`` (an ``SLS1.`` string). Raises :class:`Locked` without an
        unlock, or when the data was sealed for another product. Remembers the digests for :meth:`integrity`."""
        key = self._key()
        if key is None:
            raise Locked("No valid license check yet: the protected part of this product stays locked.")
        data, digests = open_sealed(sealed.decode("utf-8") if isinstance(sealed, bytes) else sealed, key)
        self._digests = digests
        return data

    def digests(self) -> Dict[str, str]:
        """The digests sealed with the last data :meth:`unseal` opened (path -> lowercase hex SHA-256)."""
        return dict(self._digests)

    def integrity(self, source: Union[str, Reader, None] = None, digests: Optional[Mapping[str, str]] = None) -> Optional[str]:
        """Compares the sealed digests with the product's files: ``source`` is a directory (paths resolve inside it;
        default the working directory) or a function(path) -> bytes or None. ``digests`` defaults to the ones sealed
        with the last :meth:`unseal`. Returns ``"OK"`` or ``"MODIFIED"``, or None when nothing was sealed with
        digests; the result goes with the next license check."""
        digests = self._digests if digests is None else digests
        if not digests:
            return None
        reader = source if callable(source) else _directory_reader(source or os.getcwd())
        changed = []
        for p in sorted(digests):
            try:
                data = reader(p)
            except Exception:
                data = None
            if data is None:
                changed.append(p + " (missing)")
            elif digest(data) != normalise_digest(digests[p]):
                changed.append(p)
        if changed:
            self._integrity, self._integrity_detail = "MODIFIED", detail(changed)
        else:
            self._integrity, self._integrity_detail = "OK", None
        return self._integrity

    def integrity_result(self) -> Optional[str]:
        """The latest :meth:`integrity` result, or None before any."""
        return self._integrity

    def validate_fields(self) -> Dict[str, str]:
        """Fields to add to the next license check's JSON body: ``integrity`` and, when modified, ``integrityDetail``.
        Works as ``**context`` for :meth:`SunLicense.validate` too."""
        fields: Dict[str, str] = {}
        if self._integrity:
            fields["integrity"] = self._integrity
            if self._integrity_detail:
                fields["integrityDetail"] = self._integrity_detail
        return fields

    # ---- ownership notice ----

    def notice(self) -> str:
        """One line for the start-up log: product, owner, masked license key and terms link, e.g. "My Bot is licensed
        software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://…". Never the full key or the buyer's
        name."""
        b = (self.product_name or "This product") + " is licensed software"
        if self.owner:
            b += " by " + self.owner
        b += ". License " + mask(self.license_key) + "."
        if self.terms:
            b += " Terms: " + self.terms
        return b

    # ---- protected files ----

    def protected_file(self, name: str) -> bytes:
        """Downloads a protected file uploaded to the product (Standard plan). SunLicense sends it only while the
        license is valid. Raises :class:`Refused` when it says no, ``IOError`` when it can't be reached."""
        if not self.product_code:
            raise ValueError("SunLicense: set product_code to download protected files")
        if not self.license_key:
            raise Refused(401, "No license key")
        url = "%s/api/v2/protected-files/%s/%s" % (
            self.base_url, urllib.parse.quote(self.product_code, safe=""), urllib.parse.quote(name, safe=""))
        headers = {"license": self.license_key, "User-Agent": self._user_agent}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        if self.fingerprint:
            headers["fingerprint"] = self.fingerprint
        status, body = (self._get or self._http_get)(url, headers)
        if status == 200:
            return body
        if status >= 500 or status == 429 or status <= 0:
            raise IOError("SunLicense returned HTTP %d for protected file %s" % (status, name))
        code = None
        try:
            j = json.loads(body.decode("utf-8"))
            code = j.get("code") if isinstance(j.get("code"), str) else j.get("detail") if isinstance(j.get("detail"), str) else None
        except Exception:
            pass
        raise Refused(status, "SunLicense refused protected file %s (HTTP %d%s)" % (name, status, ", " + code if code else ""))

    def _http_get(self, url: str, headers: Dict[str, str]) -> Tuple[int, bytes]:
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
        except (urllib.error.URLError, OSError) as error:
            raise IOError("Cannot reach SunLicense at %s: %s" % (self.base_url, error))

    # ---- the unlock cache: one file per license key, AES-GCM under a key bound to the key, the machine id and this machine ----

    def _key(self) -> Optional[bytes]:
        if self._unlock is not None:
            return self._unlock
        k = self._read_cache()
        if k is not None:
            self._unlock = k
        return k

    def _cache_file(self) -> Optional[str]:
        if self.cache_directory is None or not self.license_key:
            return None
        fid = digest("sunlicense-unlock-file\0" + self.license_key)[:16]
        return os.path.join(str(self.cache_directory), _CACHE_FILE + fid)

    def _cache_key(self) -> bytes:
        binding = "sunlicense-unlock-cache\0%s\0%s\0%s" % (self.license_key, self.fingerprint or "", self._machine())
        return hashlib.sha256(binding.encode("utf-8")).digest()

    def _write_cache(self, key: bytes) -> None:
        f = self._cache_file()
        if not f:
            return
        try:
            plain = ("%d\n%s" % (int(self._now() * 1000), base64.b64encode(key).decode())).encode("utf-8")
            nonce = os.urandom(12)
            blob = nonce + gcm_encrypt(self._cache_key(), nonce, plain)
            os.makedirs(os.path.dirname(f), exist_ok=True)
            tmp = f + ".tmp"
            with open(tmp, "w") as out:
                out.write(_CACHE_PREFIX + base64.urlsafe_b64encode(blob).decode().rstrip("="))
            os.replace(tmp, f)
        except Exception:
            pass  # memory only

    def _read_cache(self) -> Optional[bytes]:
        f = self._cache_file()
        if not f or not os.path.isfile(f):
            return None
        try:
            with open(f) as fh:
                text = fh.read().strip()
            if not text.startswith(_CACHE_PREFIX):
                return None
            raw = decode_base64(text[len(_CACHE_PREFIX):])
            plain = gcm_decrypt(self._cache_key(), raw[:12], raw[12:])
            if plain is None:
                return None  # another machine, another license key, or a damaged file
            millis, b64 = plain.decode("utf-8").split("\n", 1)
            saved, now = int(millis) / 1000.0, self._now()
            if saved > now + _SKEW or now >= saved + CACHE_TTL:
                return None  # older than 7 days, or the clock was turned back
            k = base64.b64decode(b64, validate=True)
            return k if _valid_key(k) else None
        except Exception:
            return None


def _directory_reader(directory: str) -> Reader:
    root = os.path.realpath(directory)

    def read(name: str) -> Optional[bytes]:
        p = os.path.realpath(os.path.join(root, name))
        if p != root and not p.startswith(root + os.sep):
            return None
        if not os.path.isfile(p):
            return None
        with open(p, "rb") as fh:
            return fh.read()

    return read


def _instant(s: Any) -> Optional[float]:
    if not isinstance(s, str):
        return None
    from datetime import datetime, timezone

    t = s.strip().replace("Z", "+00:00")
    t = re.sub(r"(\.\d{6})\d+", r"\1", t)  # Python 3.8 parses at most microseconds
    try:
        d = datetime.fromisoformat(t)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.timestamp()


def _verified_offline(file: str, public_key_base64: str) -> Optional[Dict[str, Any]]:
    if not file or not _trim(public_key_base64):
        return None
    parts = str(file).strip().split(".")
    if len(parts) != 2:
        return None
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
    except Exception:
        return None
    try:
        payload = decode_base64(parts[0])
        key = load_der_public_key(base64.b64decode(public_key_base64.strip()))
        key.verify(decode_base64(parts[1]), payload)  # Ed25519: raises on a bad signature
        parsed = json.loads(payload.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None
