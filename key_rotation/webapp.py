"""
key_rotation.webapp
===================
Stdlib HTTP service tying the three collaborators together:

  * file processor (storage.EncryptedStore)
  * key-version registry (keyring.Keyring, private local config)
  * query/download service (this module's /query and /download routes)

Security properties enforced here:
  * responses only ever expose key *versions and states*, never secrets;
  * a download bundle is plaintext data plus a manifest -- no key bytes, no
    nonce/container internals, and a runtime assertion refuses the response
    if any registered secret is found inside it;
  * root logging goes through SecretRedactionFilter;
  * disabling a key requires zero file references AND zero in-flight reads.
"""

from __future__ import annotations

import io
import json
import logging
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .keyring import Keyring, KeyringError, new_version_id
from .log_security import redact, redaction_filter
from .rotation import RotationManager
from .storage import EncryptedStore, StorageError

logger = logging.getLogger("key_rotation")


def build_logger(log_path: str | None) -> logging.Logger:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler()
    handler.addFilter(redaction_filter)
    root.addHandler(handler)
    if log_path:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.addFilter(redaction_filter)
        root.addHandler(file_handler)
    root.setLevel(logging.INFO)
    return logging.getLogger("key_rotation")


class AppState:
    """Shared services container (constructed once at process start)."""

    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        self.private_dir = os.path.join(self.base_dir, "private")
        self.data_dir = os.path.join(self.base_dir, "data")
        self.download_dir = os.path.join(self.base_dir, "downloads")
        os.makedirs(self.private_dir, mode=0o700, exist_ok=True)
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.download_dir, exist_ok=True)
        self.keyring = Keyring(os.path.join(self.private_dir, "keyring.json"))
        self.store = EncryptedStore(self.data_dir, self.keyring)
        self.manager = RotationManager(self.store, self.keyring)
        self._lock = threading.RLock()

    # ----------------------------------------------------------- key views
    def key_overview(self) -> list[dict]:
        """Per-key view with actual file references (the legal-reference list)."""
        counts = self.store.count_by_key()
        out = []
        for entry in self.keyring.list_versions():
            out.append({
                "version": entry["version"],
                "state": entry["state"],
                "is_current": entry["is_current"],
                "file_references": counts.get(entry["version"], 0),
                "in_flight_downloads": entry["in_flight"],
                "can_disable": (
                    entry["state"] != "disabled"
                    and not entry["is_current"]
                    and counts.get(entry["version"], 0) == 0
                    and entry["in_flight"] == 0
                ),
                "created_at": entry["created_at"],
                "disabled_at": entry["disabled_at"],
            })
        return out

    def old_keys_with_references(self) -> list[dict]:
        """Old (non-current) keys that still have legitimate references."""
        return [
            k for k in self.key_overview()
            if not k["is_current"] and (k["file_references"] > 0
                                        or k["in_flight_downloads"] > 0)
        ]

    def create_key(self) -> dict:
        from datetime import datetime, timezone

        with self._lock:
            existing = {e["version"] for e in self.keyring.list_versions()}
            version = new_version_id(existing)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            entry = self.keyring.create_version(version, now)
            logger.info("created new key version %s (state=%s)",
                        entry.version, entry.state)
            return {"version": version, "state": entry.state}

    def disable_key(self, version: str) -> dict:
        from datetime import datetime, timezone

        with self._lock:
            refs = self.store.references_for(version)
            now = datetime.now(timezone.utc).isoformat(timespec="seconds")
            self.keyring.disable(version, refs, now)
            logger.info("key %s disabled (references were %d)", version, refs)
            return {"version": version, "state": "disabled"}

    def retire_key(self, version: str) -> dict:
        with self._lock:
            self.keyring.retire(version)
            logger.info("key %s retired (decrypt-only)", version)
            return {"version": version, "state": "retired"}

    # ------------------------------------------------------------ bundles
    def download_bundle(self, file_id: str) -> tuple[bytes, str]:
        """
        Produce a ZIP containing ONLY plaintext data + a data manifest.
        No key material, no encrypted container, no nonces.
        """
        plaintext = self.store.read_decrypted(file_id)  # pins key while in use
        record = self.store.records[file_id]
        manifest = {
            "file_id": file_id,
            "key_version_used_for_decryption": record.key_version,
            "plaintext_sha256": record.plaintext_sha256,
            "size": record.size,
            "note": "key material is never included in download bundles",
        }
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{file_id}.csv", plaintext.decode("utf-8"))
            zf.writestr("MANIFEST.json",
                        json.dumps(manifest, indent=2, ensure_ascii=False))
        blob = buffer.getvalue()
        # Runtime guard: refuse if any secret leaked into the package.
        for entry in self.keyring.list_versions():
            if entry["state"] == "disabled":
                continue
            secret = self.keyring.get_secret(entry["version"])
            if secret in blob:
                raise RuntimeError("internal error: secret found in bundle")
        return blob, f"{file_id}-bundle.zip"


class WebHandler(BaseHTTPRequestHandler):
    server_version = "KeyRotationDemo/1.0"

    # ------------------------------------------------------------ plumbing
    @property
    def state(self) -> AppState:
        return self.server.app_state  # type: ignore[attr-defined]

    def _json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, message: str, status: int = 400) -> None:
        self._json({"error": redact(str(message))}, status)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def log_message(self, fmt, *args) -> None:
        # Route access logs through the redacting logger as well.
        logger.info("%s %s", self.address_string(), redact(fmt % args))

    # --------------------------------------------------------------- GET
    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path in ("/", "/index.html"):
                return self._serve_index()
            if path == "/api/status":
                repairs = self.state.store.reconcile_manifest()
                return self._json({
                    "keys": self.state.key_overview(),
                    "files": self.state.store.list_files(),
                    "job": self.state.manager.current_job(),
                    "reconciled": repairs,
                })
            if path == "/api/keys/old-references":
                return self._json({"keys": self.state.old_keys_with_references()})
            if path.startswith("/api/query/"):
                file_id = path.rsplit("/", 1)[-1]
                plaintext = self.state.store.read_decrypted(file_id)
                record = self.state.store.records[file_id]
                return self._json({
                    "file_id": file_id,
                    "key_version": record.key_version,
                    "plaintext_sha256": record.plaintext_sha256,
                    "content": plaintext.decode("utf-8"),
                })
            if path.startswith("/api/download/"):
                file_id = path.rsplit("/", 1)[-1]
                blob, name = self.state.download_bundle(file_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/zip")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)
                logger.info("served download bundle for %s", file_id)
                return
            self._error("not found", 404)
        except (StorageError, KeyringError, FileNotFoundError) as exc:
            self._error(exc, 404)
        except Exception as exc:  # last-resort, message scrubbed
            logger.exception("request failed")
            self._error(exc, 500)

    # -------------------------------------------------------------- POST
    def do_POST(self) -> None:
        try:
            path = urlparse(self.path).path
            body = self._read_json() if self.headers.get("Content-Length") else {}

            if path == "/api/keys":
                return self._json(self.state.create_key(), 201)
            if path == "/api/rotation/start":
                target = body.get("target_version")
                mode = body.get("mode", "mixed")
                if not target:
                    return self._error("target_version required")
                job = self.state.manager.start(target, mode)
                return self._json(job.to_dict(), 202)
            if path == "/api/rotation/pause":
                self.state.manager.pause()
                return self._json(self.state.manager.current_job())
            if path == "/api/rotation/resume":
                self.state.manager.resume()
                return self._json(self.state.manager.current_job())
            if path == "/api/rotation/retry":
                self.state.manager.retry_failed()
                return self._json(self.state.manager.current_job(), 202)
            if path == "/api/fault/inject":
                file_id = body.get("file_id")
                self.state.manager.inject_failure(file_id)
                return self._json({"file_id": file_id, "injected": True})
            if path == "/api/fault/recover":
                file_id = body.get("file_id")
                return self._json(self.state.manager.recover_file(file_id))
            if path == "/api/verify":
                file_id = body.get("file_id")
                return self._json(self.state.manager.verify_one(file_id))
            if path == "/api/keys/retire":
                return self._json(self.state.retire_key(body["version"]))
            if path == "/api/keys/disable":
                return self._json(self.state.disable_key(body["version"]))
            self._error("not found", 404)
        except (KeyringError, StorageError, RuntimeError, ValueError) as exc:
            self._error(exc, 400)
        except Exception as exc:
            logger.exception("request failed")
            self._error(exc, 500)

    def _serve_index(self) -> None:
        here = os.path.dirname(os.path.abspath(__file__))
        page = os.path.join(here, "static", "index.html")
        with open(page, "rb") as fh:
            body = fh.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(base_dir: str, host: str = "127.0.0.1", port: int = 8000,
          log_path: str | None = None) -> None:
    build_logger(log_path)
    state = AppState(base_dir)
    httpd = ThreadingHTTPServer((host, port), WebHandler)
    httpd.app_state = state  # type: ignore[attr-defined]
    logger.info("key rotation service listening on http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
