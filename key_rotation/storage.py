"""
key_rotation.storage
====================
Encrypted partition-file store with a per-file manifest.

Consistency model
-----------------
* Every partition file is an authenticated KRT1 container (see crypto.py).
  The key version actually used is embedded in the file header AND recorded
  per file in the manifest -- never a single global "current key" number.
* Rewrites are atomic: the new container is written to a temp file and fully
  authenticated there; only then is it os.replace()-d over the old one.
  A concurrent query therefore always sees either the complete old version
  or the complete new version, never a half-written file.
* The manifest is replaced atomically as well, under the same store lock as
  the data swap, so manifest and on-disk header cannot diverge.
* Readers look up the key version from the file header (the cryptographic
  truth), then resolve the secret through the keyring. A mixed fleet (some
  files on v1, some on v2) is therefore fully readable at all times.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from typing import Optional

from . import crypto
from .keyring import Keyring, KeyringError

MANIFEST_NAME = "manifest.json"


class StorageError(Exception):
    pass


@dataclass
class FileRecord:
    file_id: str
    key_version: str          # version recorded in manifest (mirrors header)
    plaintext_sha256: str     # checksum of the *plaintext*, verified on read
    size: int                 # plaintext size
    updated_at: str
    last_verified_at: Optional[str] = None
    verify_status: str = "ok"  # ok | failed | pending
    verify_error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "key_version": self.key_version,
            "plaintext_sha256": self.plaintext_sha256,
            "size": self.size,
            "updated_at": self.updated_at,
            "last_verified_at": self.last_verified_at,
            "verify_status": self.verify_status,
            "verify_error": self.verify_error,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FileRecord":
        return cls(
            file_id=d["file_id"],
            key_version=d["key_version"],
            plaintext_sha256=d["plaintext_sha256"],
            size=d["size"],
            updated_at=d["updated_at"],
            last_verified_at=d.get("last_verified_at"),
            verify_status=d.get("verify_status", "ok"),
            verify_error=d.get("verify_error"),
        )


class EncryptedStore:
    def __init__(self, data_dir: str, keyring: Keyring):
        self.data_dir = data_dir
        self.keyring = keyring
        self.manifest_path = os.path.join(data_dir, MANIFEST_NAME)
        os.makedirs(data_dir, exist_ok=True)
        self._lock = threading.RLock()
        self.records: dict[str, FileRecord] = {}
        if os.path.exists(self.manifest_path):
            self._load_manifest()

    # ------------------------------------------------------------ manifest
    def _load_manifest(self) -> None:
        with open(self.manifest_path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        self.records = {
            r["file_id"]: FileRecord.from_dict(r) for r in doc["files"]
        }

    def _save_manifest(self) -> None:
        doc = {"files": [r.to_dict() for r in self.records.values()]}
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, self.manifest_path)

    def _path(self, file_id: str) -> str:
        return os.path.join(self.data_dir, file_id + ".enc")

    # -------------------------------------------------------------- writes
    def put_encrypted(self, file_id: str, key_version: str,
                      plaintext: bytes, now_iso: str) -> FileRecord:
        """Encrypt plaintext under key_version and atomically install it."""
        with self._lock:
            secret = self.keyring.get_secret(key_version)
            blob = crypto.encrypt(secret, key_version, file_id, plaintext)
            tmp = self._path(file_id) + ".writing"
            with open(tmp, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path(file_id))
            record = FileRecord(
                file_id=file_id,
                key_version=key_version,
                plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
                size=len(plaintext),
                updated_at=now_iso,
                verify_status="ok",
                verify_error=None,
            )
            self.records[file_id] = record
            self._save_manifest()
            return record

    def rewrite_with_key(self, file_id: str, target_version: str,
                         now_iso: str) -> FileRecord:
        """
        Re-encrypt one file under target_version.

        Decrypts the current container with its *current* key (header-driven,
        so mixed-version fleets work), verifies the plaintext checksum, then
        installs the new container atomically. The manifest update and the
        file swap happen under one lock -> readers never see inconsistency.
        """
        with self._lock:
            old = self.records.get(file_id)
            if old is None:
                raise StorageError(f"unknown file {file_id}")
            with open(self._path(file_id), "rb") as fh:
                raw = fh.read()
            actual_version = crypto.peek_key_version(raw)
            secret = self.keyring.get_secret(actual_version)
            plaintext = crypto.decrypt(secret, file_id, raw)
            digest = hashlib.sha256(plaintext).hexdigest()
            if digest != old.plaintext_sha256:
                raise StorageError(
                    f"plaintext checksum mismatch for {file_id}: data corrupt"
                )
            return self.put_encrypted(file_id, target_version, plaintext, now_iso)

    # --------------------------------------------------------------- reads
    def read_decrypted(self, file_id: str) -> bytes:
        """
        Decrypt for query/download. The key version comes from the file
        header, and the keyring pins the version (begin_use/end_use) so it
        cannot be disabled while this read is in flight.
        """
        with self._lock:
            if file_id not in self.records:
                raise StorageError(f"unknown file {file_id}")
            with open(self._path(file_id), "rb") as fh:
                raw = fh.read()
        # Pin outside the data lock: a long download must not block rewrites
        # of *other* files, and the pin only guards key material destruction.
        version = crypto.peek_key_version(raw)
        self.keyring.begin_use(version)
        try:
            secret = self.keyring.get_secret(version)
            plaintext = crypto.decrypt(secret, file_id, raw)
            record = self.records[file_id]
            if hashlib.sha256(plaintext).hexdigest() != record.plaintext_sha256:
                raise StorageError(
                    f"post-decrypt checksum mismatch for {file_id}"
                )
            return plaintext
        finally:
            self.keyring.end_use(version)

    # ------------------------------------------------------------ verify /
    def verify_file(self, file_id: str, now_iso: str) -> FileRecord:
        """Full authentication + checksum verification of one file."""
        with self._lock:
            record = self.records.get(file_id)
            if record is None:
                raise StorageError(f"unknown file {file_id}")
            try:
                with open(self._path(file_id), "rb") as fh:
                    raw = fh.read()
                version = crypto.peek_key_version(raw)
                secret = self.keyring.get_secret(version)
                plaintext = crypto.decrypt(secret, file_id, raw)
                if hashlib.sha256(plaintext).hexdigest() != record.plaintext_sha256:
                    raise crypto.VerificationError("plaintext checksum mismatch")
                record.verify_status = "ok"
                record.verify_error = None
            except (crypto.CryptoError, StorageError, KeyringError) as exc:
                record.verify_status = "failed"
                record.verify_error = str(exc)
            record.last_verified_at = now_iso
            self._save_manifest()
            return record

    def tamper_file(self, file_id: str) -> None:
        """
        Fault injection: flip one ciphertext byte on disk so the next
        verification genuinely fails at the HMAC authentication step.
        The manifest is untouched -- recovery means restoring the bytes.
        """
        with self._lock:
            path = self._path(file_id)
            with open(path, "r+b") as fh:
                fh.seek(-crypto.TAG_SIZE - 1, os.SEEK_END)
                b = fh.read(1)
                fh.seek(-1, os.SEEK_CUR)
                fh.write(bytes([b[0] ^ 0xFF]))

    def mark_failed(self, file_id: str, message: str, now_iso: str) -> None:
        with self._lock:
            record = self.records[file_id]
            record.verify_status = "failed"
            record.verify_error = message
            record.last_verified_at = now_iso
            self._save_manifest()

    # ------------------------------------------------------------- queries
    def list_files(self) -> list[dict]:
        with self._lock:
            return [r.to_dict() for r in self.records.values()]

    def count_by_key(self) -> dict[str, int]:
        """Reference count per key version according to actual file headers."""
        counts: dict[str, int] = {}
        with self._lock:
            for file_id in self.records:
                try:
                    with open(self._path(file_id), "rb") as fh:
                        ver = crypto.peek_key_version(fh.read())
                except crypto.InvalidFileFormat:
                    ver = self.records[file_id].key_version + "(unparseable)"
                counts[ver] = counts.get(ver, 0) + 1
        return counts

    def references_for(self, version: str) -> int:
        return self.count_by_key().get(version, 0)

    def reconcile_manifest(self) -> list[str]:
        """
        Compare manifest versions against actual on-disk headers and repair
        the manifest if they ever diverge (e.g. process crashed between the
        data swap and manifest write). Returns the list of repairs made.
        """
        repairs = []
        with self._lock:
            for file_id, record in self.records.items():
                with open(self._path(file_id), "rb") as fh:
                    header_version = crypto.peek_key_version(fh.read())
                if header_version != record.key_version:
                    repairs.append(
                        f"{file_id}: manifest {record.key_version} -> "
                        f"header {header_version}"
                    )
                    record.key_version = header_version
            if repairs:
                self._save_manifest()
        return repairs
