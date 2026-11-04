"""Tests for core unlock, integrity, the notice and protected files (standard library only; the offline .lic test
and the cryptography backend run when ``cryptography`` is installed).

Run: python -m unittest discover -s tests
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sunlicense import Locked, Refused, SunLicense, SunLicenseProtection, mask  # noqa: E402
from sunlicense import protection as P  # noqa: E402

# SunLicense's protection test vectors (cloud/docs/specs/protection-test-vectors.json): copy the file again when it changes.
with open(os.path.join(os.path.dirname(__file__), "fixtures", "protection-test-vectors.json")) as fh:
    V = json.load(fh)

KEY = "AX8P-QW3E-RT5Y-ZZ12"
UNLOCK = V["wire"]["compatResponseV2"]["unlock"]
T0 = 1762000000.0


def hkdf(ikm, salt, info, length):
    prk = __import__("hmac").new(salt, ikm, hashlib.sha256).digest()
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = __import__("hmac").new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


class Clock:
    def __init__(self, t=T0):
        self.t = t

    def __call__(self):
        return self.t


class ProtectionTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sunlicense-protection-")
        self.clock = Clock()

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, **o):
        args = dict(license_key=KEY, fingerprint="machine-1", base_url="https://api.example.test",
                    cache_directory=self.dir, _now=self.clock, _machine=lambda: "host-a")
        args.update(o)
        return SunLicenseProtection(**args)

    def backends(self):
        """Runs the block with cryptography (when installed) and with the pure-Python AES-GCM."""
        yield "default"
        with mock.patch.object(P, "_AESGCM", None):
            yield "pure-python"

    def test_hkdf_and_product_keys(self):
        t = V["rfc5869TestCase1"]
        self.assertEqual(hkdf(bytes.fromhex(t["ikmHex"]), bytes.fromhex(t["saltHex"]), bytes.fromhex(t["infoHex"]),
                              t["length"]).hex(), t["okmHex"])
        for k in V["productKeys"]:
            key = hkdf(bytes.fromhex(k["orgSecretHex"]), k["saltAscii"].encode(), k["infoAscii"].encode(), 32)
            self.assertEqual(base64.b64encode(key).decode(), k["productKeyBase64"], k["name"])

    def test_sealed_vectors_open_and_seal_the_same_bytes(self):
        for backend in self.backends():
            for v in V["sealed"]:
                key = base64.b64decode(v["productKeyBase64"])
                data, digests = P.open_sealed(v["sealed"], key)
                self.assertEqual(data, base64.b64decode(v["dataBase64"]), backend + " " + v["name"])
                self.assertEqual(digests, v["digests"], v["name"])
                nonce = bytes.fromhex(v["nonceHex"])
                blob = nonce + P.gcm_encrypt(key, nonce, v["plaintextUtf8"].encode("utf-8"), b"SLS1")
                self.assertEqual("SLS1." + base64.urlsafe_b64encode(blob).decode().rstrip("="), v["sealed"], backend)

    def test_must_fail_vectors(self):
        for backend in self.backends():
            for v in V["mustFail"]:
                with self.assertRaises(Locked, msg=backend + " " + v["name"]):
                    P.open_sealed(v["sealed"], base64.b64decode(v["productKeyBase64"]))

    def test_digests_and_base64(self):
        for d in V["digests"]:
            if "inputUtf8" in d:
                self.assertEqual(P.digest(d["inputUtf8"]), d["sha256Hex"])
            if "inputBase64" in d:
                self.assertEqual(P.digest(base64.b64decode(d["inputBase64"])), d["sha256Hex"])
            if "input" in d:
                self.assertEqual(P.normalise_digest(d["input"]), d["normalised"])
        s = V["sealed"][0]["sealed"]
        padded = s + "=" * (-(len(s) - 5) % 4)
        self.assertTrue(P.open_sealed(padded, base64.b64decode(V["sealed"][0]["productKeyBase64"])))
        with self.assertRaises(ValueError):
            P.decode_base64("a$b")

    def test_locked_until_a_valid_answer_with_unlock(self):
        p = self.make()
        self.assertFalse(p.unlocked())
        with self.assertRaises(Locked):
            p.unseal(V["sealed"][0]["sealed"])
        p.accept(json.dumps(V["wire"]["compatResponseV2"]))
        self.assertTrue(p.unlocked())
        self.assertEqual(p.unseal(V["sealed"][0]["sealed"]), base64.b64decode(V["sealed"][0]["dataBase64"]))
        self.assertEqual(p.digests(), V["sealed"][0]["digests"])

    def test_v1_answers_and_answers_that_change_nothing(self):
        p = self.make()
        p.accept(V["wire"]["validateResponseV1"])
        self.assertTrue(p.unlocked())
        for body in ('{"valid":true,"code":"VALID"}', "<html>502</html>", {"status": 401}, None, "error code: 1010"):
            p.accept(body)
        self.assertTrue(p.unlocked())

    def test_a_refused_check_forgets_the_unlock_in_memory_and_on_disk(self):
        p = self.make()
        p.accept(V["wire"]["compatResponseV2"])
        self.assertEqual(len(os.listdir(self.dir)), 1)
        p.accept({"valid": False, "status": 403, "code": "SUSPENDED"})
        self.assertFalse(p.unlocked())
        self.assertEqual(os.listdir(self.dir), [])

    def test_cache_7_days_this_machine_this_key_only(self):
        for backend in self.backends():
            shutil.rmtree(self.dir)
            os.makedirs(self.dir)
            self.clock.t = T0
            self.make().accept(V["wire"]["compatResponseV2"])
            (name,) = os.listdir(self.dir)
            self.assertRegex(name, r"^\.sunlicense-unlock-[0-9a-f]{16}$")
            self.assertEqual(name, ".sunlicense-unlock-" + P.digest("sunlicense-unlock-file\0" + KEY)[:16])
            with open(os.path.join(self.dir, name)) as fh:
                text = fh.read()
            self.assertTrue(text.startswith("SLC1.") and UNLOCK not in text)
            self.assertTrue(self.make().unlocked(), backend)
            self.assertFalse(self.make(_machine=lambda: "host-b").unlocked())
            self.assertFalse(self.make(fingerprint="machine-2").unlocked())
            self.assertFalse(self.make(license_key="OTHR-XXXX").unlocked())
            self.clock.t = T0 + 7 * 86400 - 60
            self.assertTrue(self.make().unlocked())
            self.clock.t = T0 + 7 * 86400
            self.assertFalse(self.make().unlocked())
            self.clock.t = T0 - 3600
            self.assertFalse(self.make().unlocked(), "clock turned back")

    def test_cache_file_format_matches_the_other_sdks(self):
        self.make().accept(V["wire"]["compatResponseV2"])
        (name,) = os.listdir(self.dir)
        with open(os.path.join(self.dir, name)) as fh:
            raw = P.decode_base64(fh.read()[5:])
        key = hashlib.sha256(("sunlicense-unlock-cache\0%s\0machine-1\0host-a" % KEY).encode()).digest()
        with mock.patch.object(P, "_AESGCM", None):
            plain = P.gcm_decrypt(key, raw[:12], raw[12:])
        self.assertEqual(plain.decode(), "%d\n%s" % (T0 * 1000, UNLOCK))

    def test_memory_only_and_a_new_key(self):
        p = self.make(cache_directory=None)
        p.accept(V["wire"]["compatResponseV2"])
        self.assertTrue(p.unlocked())
        p.license("NEWK-XXXX-XXXX-XXXX", "machine-1")
        self.assertFalse(p.unlocked())

    def test_integrity(self):
        p = self.make()
        p.accept(V["wire"]["compatResponseV2"])
        self.assertIsNone(p.integrity(lambda f: b"x"), "nothing unsealed yet")
        p.unseal(V["sealed"][2]["sealed"])
        files = {"Main.class": b"main", "assets/rules.dat": b"rules", "lib/util.jar": b"util"}
        self.assertEqual(p.integrity(files.get), "OK")
        self.assertEqual(p.validate_fields(), {"integrity": "OK"})
        files["lib/util.jar"] = b"patched"
        del files["Main.class"]
        self.assertEqual(p.integrity(files.get), "MODIFIED")
        self.assertEqual(p.integrity_result(), "MODIFIED")
        self.assertEqual(p.validate_fields(), {"integrity": "MODIFIED",
                                               "integrityDetail": "2 changed: Main.class (missing), lib/util.jar"})
        root = os.path.join(self.dir, "app")
        os.makedirs(os.path.join(root, "lib"))
        for path, data in (("Main.class", b"main"), ("lib/util.jar", b"util")):
            with open(os.path.join(root, path), "wb") as fh:
                fh.write(data)
        digests = {"Main.class": P.digest(b"main"), "lib/util.jar": "SHA256:" + P.digest(b"util").upper(), "../escape": "x"}
        self.assertEqual(p.integrity(root, digests), "MODIFIED")
        self.assertEqual(p.validate_fields()["integrityDetail"], "1 changed: ../escape (missing)")
        del digests["../escape"]
        self.assertEqual(p.integrity(root, digests), "OK")

    def test_detail_stays_within_200_characters(self):
        d = P.detail(["lib/some-long-library-name-%02d.jar" % i for i in range(40)])
        self.assertLessEqual(len(d), 200)
        self.assertRegex(d, r"^40 changed: .*, \+\d+ more$")

    def test_notice_and_mask(self):
        p = self.make(product="My Bot", owner="Example Studio", terms="https://example.com/terms")
        self.assertEqual(p.notice(), "My Bot is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. "
                                     "Terms: https://example.com/terms")
        self.assertNotIn(KEY, p.notice())
        self.assertEqual(self.make().notice(), "This product is licensed software. License AX8P-XXXX-XXXX-XXXX.")
        self.assertEqual(mask(None), "(none)")
        self.assertEqual(mask("ABCDEFGHIJ"), "ABCDXXXXXX")

    def test_protected_files(self):
        seen = {}
        answer = {"status": 200, "body": b"RULES"}

        def get(url, headers):
            seen.update(url=url, headers=headers)
            return answer["status"], answer["body"]

        p = self.make(product_code="my bot", api_key="sk_test", _get=get)
        self.assertEqual(p.protected_file("rules.dat"), b"RULES")
        self.assertEqual(seen["url"], "https://api.example.test/api/v2/protected-files/my%20bot/rules.dat")
        self.assertEqual(seen["headers"]["Authorization"], "Bearer sk_test")
        self.assertEqual(seen["headers"]["X-License-Key"], KEY)
        self.assertEqual(seen["headers"]["X-Fingerprint"], "machine-1")
        answer.update(status=403, body=b'{"code":"SUSPENDED"}')
        with self.assertRaises(Refused) as e:
            p.protected_file("rules.dat")
        self.assertEqual(e.exception.status, 403)
        self.assertIn("SUSPENDED", str(e.exception))
        answer.update(status=503, body=b"")
        with self.assertRaises(IOError) as e:
            p.protected_file("rules.dat")
        self.assertNotIsInstance(e.exception, Refused)
        with self.assertRaises(ValueError):
            self.make(_get=get).protected_file("x")

    @unittest.skipIf(P._AESGCM is None, "cryptography isn't installed")
    def test_offline_license_file(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        priv = Ed25519PrivateKey.generate()
        pub = base64.b64encode(priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)).decode()

        def lic(payload, key=priv):
            data = json.dumps(payload).encode()
            b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
            return b64(data) + "." + b64(key.sign(data))

        base = {"format": "sunlicense-offline/1", "licenseKey": KEY, "issuedAt": "2025-11-01T00:00:00Z",
                "refreshAfter": "2025-11-20T00:00:00Z", "policy": {"expiresAt": "2026-01-01T00:00:00.123456789Z"},
                "unlock": UNLOCK}
        self.clock.t = 1762732800.0  # 2025-11-10
        p = self.make(cache_directory=None)
        self.assertTrue(p.accept_offline(lic(base), pub))
        self.assertTrue(p.unlocked())
        at = lambda: self.make(cache_directory=None)  # noqa: E731
        self.assertFalse(at().accept_offline(lic(base, Ed25519PrivateKey.generate()), pub))
        self.assertFalse(at().accept_offline(lic(dict(base, licenseKey="OTHR-XXXX")), pub))
        self.assertFalse(at().accept_offline(lic(dict(base, policy={"expiresAt": "2025-11-05T00:00:00Z"})), pub))
        self.assertFalse(at().accept_offline(lic(dict(base, refreshAfter="2025-11-09T00:00:00Z")), pub))
        self.assertFalse(at().accept_offline(lic({k: v for k, v in base.items() if k != "unlock"}), pub))
        self.assertFalse(at().accept_offline("garbage", pub))


class ClientProtectionTest(unittest.TestCase):
    def test_validate_sends_integrity_and_keeps_or_forgets_the_unlock(self):
        import io
        import urllib.error

        sent, answers = [], []

        class Response(io.BytesIO):
            def __init__(self, status, body):
                super().__init__(json.dumps(body).encode())
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def urlopen(request, timeout=None):
            sent.append(json.loads(request.data))
            status, body = answers.pop(0)
            if status >= 400:
                raise urllib.error.HTTPError(request.full_url, status, "x", {}, io.BytesIO(json.dumps(body).encode()))
            return Response(status, body)

        d = tempfile.mkdtemp()
        try:
            client = SunLicense(base_url="https://api.example.test", token="sk_test")
            p = client.protection(cache_directory=d, _machine=lambda: "host-a")
            self.assertEqual(p.api_key, "sk_test")
            with mock.patch("urllib.request.urlopen", urlopen):
                answers.append((200, V["wire"]["compatResponseV2"]))
                self.assertTrue(client.validate(KEY, fingerprint="machine-1").valid)
                self.assertTrue(p.unlocked())
                self.assertEqual(p.license_key, KEY)
                self.assertNotIn("integrity", sent[0])
                p.unseal(V["sealed"][0]["sealed"])
                self.assertEqual(p.integrity(lambda f: b"not the jar"), "MODIFIED")
                answers.append((403, {"valid": False, "status": 403, "code": "SUSPENDED"}))
                self.assertFalse(client.validate(KEY, fingerprint="machine-1").valid)
                self.assertEqual(sent[1]["integrity"], "MODIFIED")
                self.assertEqual(sent[1]["integrityDetail"], "1 changed: plugin.jar")
                self.assertFalse(p.unlocked())
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
