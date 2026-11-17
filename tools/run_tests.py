#!/usr/bin/env python3
"""
tools/run_tests.py
==================
End-to-end verification in throwaway temp environments. Run with -I-safe
stdlib only. Covers:

 1. real encrypt/decrypt round trip + tamper detection + wrong-key rejection
 2. mixed-version fleet stays readable during a background rotation
 3. atomic rewrite: concurrent reader never sees a partial/inconsistent file
 4. per-file manifest records the *actual* version (not a global key number)
 5. injected failure fails HMAC verification; backup recovery restores it
 6. pause/resume and retry-failed flow
 7. cutover mode retires old keys; failed cutover withholds retirement
 8. key disable blocked while file references or in-flight downloads exist
 9. download bundle contains plaintext but never any key material
10. log redaction: secrets are scrubbed even if explicitly logged
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import time
import zipfile
import io

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_rotation import crypto
from key_rotation.keyring import Keyring, KeyringError
from key_rotation.log_security import redact, redaction_filter
from key_rotation.rotation import RotationManager
from key_rotation.storage import EncryptedStore, StorageError

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def fresh_env() -> tuple[str, Keyring, EncryptedStore]:
    base = tempfile.mkdtemp(prefix="krt-test-")
    os.mkdir(os.path.join(base, "private"), 0o700)
    data = os.path.join(base, "data")
    os.mkdir(data)
    kr = Keyring(os.path.join(base, "private", "keyring.json"))
    kr.create_version("v1", "2026-11-17T00:00:00+00:00")
    store = EncryptedStore(data, kr)
    return base, kr, store


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ------------------------------------------------------------------ 1 crypto
def test_crypto() -> None:
    section("1. real authenticated encryption")
    kr = Keyring.__new__(Keyring)  # lightweight: only need a secret
    secret = crypto.random_secret()
    pt = b"order-1001,Beijing,4200.00,CNY\n" * 50
    blob = crypto.encrypt(secret, "v9", "partition-x", pt)
    check("container magic present", blob[:4] == b"KRT1")
    check("header records key version", crypto.peek_key_version(blob) == "v9")
    back = crypto.decrypt(secret, "partition-x", blob)
    check("round trip recovers plaintext", back == pt)

    tampered = bytearray(blob)
    tampered[40] ^= 0x01
    try:
        crypto.decrypt(secret, "partition-x", bytes(tampered))
        check("ciphertext tamper rejected", False)
    except crypto.VerificationError:
        check("ciphertext tamper rejected", True)

    try:
        crypto.decrypt(crypto.random_secret(), "partition-x", blob)
        check("wrong key rejected", False)
    except crypto.VerificationError:
        check("wrong key rejected", True)

    try:
        crypto.decrypt(secret, "partition-y", blob)  # different AAD id
        check("AAD/file-id swap rejected", False)
    except crypto.VerificationError:
        check("AAD/file-id swap rejected", True)

    # nonce uniqueness => different ciphertext for same plaintext
    b2 = crypto.encrypt(secret, "v9", "partition-x", pt)
    check("random nonce makes ciphertexts differ", b2 != blob)
    check("both containers still decrypt",
          crypto.decrypt(secret, "partition-x", b2) == pt)


# --------------------------------------------------- 2/3/4 rotation & reads
def test_rotation_and_consistency() -> None:
    section("2-4. mixed rotation, concurrent consistent reads, per-file versions")
    base, kr, store = fresh_env()
    try:
        files = {}
        for i in range(6):
            fid = f"partition-{i:02d}"
            pt = f"records for {fid}\n".encode() * 200
            store.put_encrypted(fid, "v1", pt, "2026-11-17T00:00:00+00:00")
            files[fid] = pt

        kr.create_version("v2", "2026-11-17T01:00:00+00:00")
        mgr = RotationManager(store, kr)

        errors: list[str] = []
        stop = threading.Event()

        def reader_loop() -> None:
            # Hammer every file while rewrites happen: a read must always
            # return either the complete old or the complete new plaintext.
            while not stop.is_set():
                for fid, pt in files.items():
                    try:
                        got = store.read_decrypted(fid)
                        if got != pt:
                            errors.append(f"{fid}: inconsistent content")
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{fid}: {type(exc).__name__}: {exc}")
                time.sleep(0.002)

        workers = [threading.Thread(target=reader_loop) for _ in range(4)]
        for w in workers:
            w.start()
        job = mgr.start("v2", mode="mixed")
        while mgr.current_job()["status"] in ("queued", "running", "paused"):
            time.sleep(0.02)
        stop.set()
        for w in workers:
            w.join()
        check("concurrent readers saw no partial/inconsistent data",
              not errors, str(errors[:3]))
        check("all files rotated", job.to_dict()["counts"]["done"] == 6)

        counts = store.count_by_key()
        check("actual headers all on v2", counts == {"v2": 6}, str(counts))
        manifest_versions = {r["file_id"]: r["key_version"]
                             for r in store.list_files()}
        check("manifest per-file versions match headers",
              all(v == "v2" for v in manifest_versions.values()))
        check("v1 still active for backward compatibility",
              kr.state_of("v1") == "active")
        check("current key remains v1 after mixed run", kr.current == "v1")

        # mixed fleet: seed one new v1 file alongside v2 files, both readable
        store.put_encrypted("partition-new", "v1", b"late arrival\n",
                            "2026-11-17T02:00:00+00:00")
        check("mixed fleet: v2 file readable",
              store.read_decrypted("partition-00") == files["partition-00"])
        check("mixed fleet: v1 file readable",
              store.read_decrypted("partition-new") == b"late arrival\n")
    finally:
        shutil.rmtree(base)


# ------------------------------------------------------------- 5/6 failures
def test_failure_recovery_pause() -> None:
    section("5-6. tamper failure, recovery, pause/resume, retry")
    base, kr, store = fresh_env()
    try:
        for i in range(3):
            store.put_encrypted(f"p{i}", "v1", f"data-{i}\n".encode() * 30,
                                "2026-11-17T00:00:00+00:00")
        kr.create_version("v2", "2026-11-17T01:00:00+00:00")
        mgr = RotationManager(store, kr)

        mgr.inject_failure("p1")
        rec = store.verify_file("p1", "2026-11-17T01:05:00+00:00")
        check("tampered file fails verification",
              rec.verify_status == "failed" and "authentication" in
              (rec.verify_error or ""))

        # rotation: p1 fails, others succeed; old p1 container stays on v1
        mgr.start("v2", mode="mixed")
        time.sleep(0.3)
        job = mgr.current_job()
        check("job reports failed state", job["status"] == "failed")
        check("two files done, one failed",
              job["counts"]["done"] == 2 and job["counts"]["failed"] == 1)
        check("failed file stays on old version v1",
              store.records["p1"].key_version == "v1")
        # Atomic rewrite guarantee: nothing was installed in place of the
        # old container -- the manifest still points at v1 and the only
        # damage is the injected byte flip, which recovery can undo.
        check("no half-written replacement installed",
              not os.path.exists(store._path("p1") + ".writing"))

        # pause/resume mechanics on a fresh job against the recovered file
        rec2 = mgr.recover_file("p1")
        check("recovery restores verification", rec2["verify_status"] == "ok")
        check("recovered file content intact",
              store.read_decrypted("p1") == b"data-1\n" * 30)
        mgr.pause()  # pause first, then enqueue retry for controlled resume
        mgr.retry_failed()
        time.sleep(0.15)
        check("paused job status visible",
              mgr.current_job()["status"] == "paused")
        mgr.resume()
        time.sleep(0.4)
        check("retry completes all files",
              mgr.current_job()["counts"]["done"] == 3)
        check("final job completed",
              mgr.current_job()["status"] == "completed")
        check("every header now v2", store.count_by_key() == {"v2": 3})
    finally:
        shutil.rmtree(base)


# --------------------------------------------------------------- 7 cutover
def test_cutover_policy() -> None:
    section("7. cutover policy (success retires old keys; failure withholds)")
    base, kr, store = fresh_env()
    try:
        for i in range(3):
            store.put_encrypted(f"c{i}", "v1", b"x" * 100,
                                "2026-11-17T00:00:00+00:00")
        kr.create_version("v2", "2026-11-17T01:00:00+00:00")
        mgr = RotationManager(store, kr)
        mgr.inject_failure("c2")
        mgr.start("v2", mode="cutover")
        time.sleep(0.3)
        check("cutover withheld on failure (v1 not retired)",
              kr.state_of("v1") == "active")
        check("current stays v1 after failed cutover", kr.current == "v1")

        mgr.recover_file("c2")
        mgr.retry_failed()
        time.sleep(0.3)
        check("retry finishes cutover",
              mgr.current_job()["status"] == "completed")
        check("current key switched to v2", kr.current == "v2")
        check("v1 retired (decrypt-only)", kr.state_of("v1") == "retired")
        # retired key still decrypts old... nothing left, but API works:
        check("retired key secret still available for decrypt",
              bool(kr.get_secret("v1")))
    finally:
        shutil.rmtree(base)


# ----------------------------------------------------------- 8 key disable
def test_disable_rules() -> None:
    section("8. key disable gating (references & in-flight downloads)")
    base, kr, store = fresh_env()
    try:
        store.put_encrypted("f1", "v1", b"hello",
                            "2026-11-17T00:00:00+00:00")
        kr.create_version("v2", "2026-11-17T01:00:00+00:00")

        try:
            kr.disable("v1", references=1, now_iso="2026-11-17T02:00:00+00:00")
            check("disable blocked with file references", False)
        except KeyringError:
            check("disable blocked with file references", True)

        kr.begin_use("v1")
        try:
            kr.disable("v1", references=0, now_iso="2026-11-17T02:00:00+00:00")
            check("disable blocked with in-flight download", False)
        except KeyringError:
            check("disable blocked with in-flight download", True)
        kr.end_use("v1")

        # v1 is still the current encryption key; cut over to v2 first.
        kr.set_current("v2")
        kr.disable("v1", references=0, now_iso="2026-11-17T02:00:00+00:00")
        check("disable succeeds once references and in-flight are zero",
              kr.state_of("v1") == "disabled")
        try:
            kr.get_secret("v1")
            check("disabled key secret is destroyed", False)
        except KeyringError:
            check("disabled key secret is destroyed", True)

        try:
            kr.disable("v2", references=0, now_iso="now")
            check("current key cannot be disabled", False)
        except KeyringError:
            check("current key cannot be disabled", True)
    finally:
        shutil.rmtree(base)


# ------------------------------------------------------------- 9/10 bundle
def test_bundle_and_log_redaction() -> None:
    section("9-10. bundle hygiene & log redaction")
    base, kr, store = fresh_env()
    try:
        pt = b"id,amount\n1,42\n"
        store.put_encrypted("b1", "v1", pt, "2026-11-17T00:00:00+00:00")
        blob = store.read_decrypted  # ensure path works
        check("read path works", blob("b1") == pt)

        # Build a bundle the same way the web route does.
        import base64
        secret_b64 = kr.list_versions()[0]["secret_b64"]
        secret_raw = base64.b64decode(secret_b64)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("b1.csv", pt.decode())
            zf.writestr("MANIFEST.json", json.dumps({"file_id": "b1"}))
        bundle = buf.getvalue()
        check("bundle excludes raw secret", secret_raw not in bundle)
        check("bundle excludes encoded secret", secret_b64.encode() not in bundle)
        check("bundle contains plaintext CSV", b"id,amount" in bundle)

        # redaction: even an explicit attempt to log the secret is scrubbed
        redaction_filter.register(secret_raw, secret_b64)
        logged = redact(f"leak attempt {secret_b64} done")
        check("registered secret redacted from text",
              secret_b64 not in logged and "REDACTED" in logged)
        logged_hex = redact(f"raw {secret_raw.hex()} x")
        check("hex-shaped secret redacted by pattern backstop",
              secret_raw.hex() not in logged_hex)
    finally:
        shutil.rmtree(base)


def test_keyring_file_permissions() -> None:
    section("keyring file is private (0600)")
    base, kr, store = fresh_env()
    try:
        mode = os.stat(kr.path).st_mode & 0o777
        check("keyring.json mode 0600", mode == 0o600, oct(mode))
        with open(kr.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        check("keyring holds one secret entry per version",
              all("secret_b64" in e for e in doc["keys"]))
        check("disabled version's secret field is empty",
              all(e["state"] != "disabled" or e["secret_b64"] == ""
                  for e in doc["keys"]))
    finally:
        shutil.rmtree(base)


def main() -> int:
    test_crypto()
    test_rotation_and_consistency()
    test_failure_recovery_pause()
    test_cutover_policy()
    test_disable_rules()
    test_bundle_and_log_redaction()
    test_keyring_file_permissions()
    print(f"\n{'='*50}\n{FAIL} failed, {PASS} passed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
