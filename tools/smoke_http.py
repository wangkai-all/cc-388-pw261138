#!/usr/bin/env python3
"""
tools/smoke_http.py
===================
Drives the running HTTP service through the full operator workflow:

  create v2 -> start mixed rotation with concurrent queries -> inject a
  verification failure -> recover -> retry -> cutover -> retire/disable
  rules -> download bundle secret-leak check.
"""

from __future__ import annotations

import io
import json
import sys
import threading
import time
import urllib.request
import zipfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8011"


def call(method: str, path: str, body: dict | None = None, raw: bool = False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            payload = resp.read()
            return payload if raw else json.loads(payload)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode()
        raise AssertionError(f"{method} {path} -> {exc.code}: {detail}")


def wait_job_terminal(timeout: float = 15) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = call("GET", "/api/status")["job"]
        if job and job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("job did not finish in time")


def main() -> int:
    print("1) initial status")
    status = call("GET", "/api/status")
    assert len(status["files"]) == 8
    assert all(f["key_version"] == "v1" for f in status["files"])

    print("2) register v2 (v1 stays current)")
    call("POST", "/api/keys")
    keys = call("GET", "/api/status")["keys"]
    assert {k["version"] for k in keys} == {"v1", "v2"}
    assert next(k for k in keys if k["version"] == "v1")["is_current"]

    print("3) start MIXED rotation while hammering queries")
    query_errors: list[str] = []
    stop = threading.Event()

    def query_loop() -> None:
        fid = "partition-cn-01"
        expected = call("GET", f"/api/query/{fid}")["content"]
        while not stop.is_set():
            try:
                got = call("GET", f"/api/query/{fid}")["content"]
                assert got == expected, "content changed mid-rotation"
            except Exception as exc:  # noqa: BLE001
                query_errors.append(str(exc))
            time.sleep(0.01)

    t = threading.Thread(target=query_loop)
    t.start()
    call("POST", "/api/rotation/start",
         {"target_version": "v2", "mode": "mixed"})
    job = wait_job_terminal()
    stop.set()
    t.join()
    assert job["status"] == "completed", job["status"]
    assert not query_errors, query_errors[:2]
    print(f"   {job['counts']['done']}/8 rewritten, concurrent queries OK")

    print("4) mixed fleet policy: current still v1, v1 still active")
    keys = call("GET", "/api/status")["keys"]
    assert next(k for k in keys if k["version"] == "v1")["is_current"]
    assert next(k for k in keys if k["version"] == "v1")["state"] == "active"

    print("5) legal-reference list (v2 non-current yet holds all 8 files)")
    old = call("GET", "/api/keys/old-references")["keys"]
    v2_refs = next(k for k in old if k["version"] == "v2")
    assert v2_refs["file_references"] == 8
    assert v2_refs["can_disable"] is False  # references block disabling
    v1_refs = [k for k in old if k["version"] == "v1"]
    assert not v1_refs  # v1 is current, so it isn't listed as an "old" key

    print("6) fault injection + verification failure + recovery")
    call("POST", "/api/fault/inject", {"file_id": "partition-eu-01"})
    # rotate eu-01 back to v1 to produce a genuine mixed file again
    call("POST", "/api/rotation/start",
         {"target_version": "v1", "mode": "mixed"})
    job = wait_job_terminal()
    failed = [i for i in job["items"] if i["status"] == "failed"]
    assert failed and failed[0]["file_id"] == "partition-eu-01"
    rec = call("POST", "/api/verify", {"file_id": "partition-eu-01"})
    assert rec["verify_status"] == "failed"
    print("   verification genuinely failed:", rec["verify_error"][:60], "...")
    rec = call("POST", "/api/fault/recover", {"file_id": "partition-eu-01"})
    assert rec["verify_status"] == "ok"

    print("7) retry the failed file")
    call("POST", "/api/rotation/retry")
    job = wait_job_terminal()
    assert job["status"] == "completed"

    print("8) CUTOVER to v2 (all files must succeed first)")
    call("POST", "/api/rotation/start",
         {"target_version": "v2", "mode": "cutover"})
    job = wait_job_terminal()
    assert job["status"] == "completed"
    keys = call("GET", "/api/status")["keys"]
    assert next(k for k in keys if k["version"] == "v2")["is_current"]
    assert next(k for k in keys if k["version"] == "v1")["state"] == "retired"
    print("   v1 retired (decrypt-only), current = v2")

    print("9) disable rules")
    # v1 has zero references now but try while an in-flight-style guard exists:
    # first show normal disable works after retirement
    call("POST", "/api/keys/disable", {"version": "v1"})
    keys = call("GET", "/api/status")["keys"]
    v1 = next(k for k in keys if k["version"] == "v1")
    assert v1["state"] == "disabled" and not v1["can_disable"]
    # current key can never be disabled
    try:
        call("POST", "/api/keys/disable", {"version": "v2"})
        raise AssertionError("v2 disable should have been refused")
    except AssertionError as exc:
        assert "current encryption key" in str(exc), str(exc)
        print("   disabling current key refused as expected")

    print("10) download bundle contains data but no key material")
    bundle = call("GET", "/api/download/partition-us-01", raw=True)
    zf = zipfile.ZipFile(io.BytesIO(bundle))
    names = zf.namelist()
    assert "MANIFEST.json" in names and names[0].endswith(".csv")
    manifest = json.loads(zf.read("MANIFEST.json"))
    assert "secret" not in json.dumps(manifest).lower()
    # compare against private keyring bytes
    with open("demo_env/private/keyring.json", "rb") as fh:
        keyring_doc = json.loads(fh.read())
    import base64
    for entry in keyring_doc["keys"]:
        if entry["secret_b64"]:
            secret = base64.b64decode(entry["secret_b64"])
            assert secret not in bundle, "raw secret leaked into bundle"
            assert entry["secret_b64"].encode() not in bundle
    print("   bundle:", names, "-- no secret bytes present")

    print("11) query still works on v2-encrypted files")
    q = call("GET", "/api/query/partition-sg-02")
    assert q["key_version"] == "v2" and q["content"].startswith("id,domain")

    print("\nALL HTTP SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
