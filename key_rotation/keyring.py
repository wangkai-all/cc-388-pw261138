"""
key_rotation.keyring
====================
Local *private* key-version registry.

The keyring JSON file is the only place master secrets live. It is written
with mode 0600, never embedded in download packages, and a log filter
(see webapp) guarantees secret bytes never reach the logs.

Key lifecycle
-------------
    active    -- usable for both encryption (current key only) and decryption
    retired   -- decryption-only; kept because files or in-flight downloads
                 still reference it. Rotation targets cannot be retired.
    disabled  -- secret material destroyed. Only reachable when BOTH:
                   1. zero partition files reference the version, and
                   2. zero in-flight downloads are using it.
                 A disabled key can never decrypt anything again.

State transitions:  active -> retired -> disabled
(an `active` key with no references may also be disabled directly.)
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import threading
from dataclasses import dataclass
from typing import Optional

from . import crypto
from .log_security import redaction_filter

VALID_STATES = ("active", "retired", "disabled")


class KeyringError(Exception):
    pass


@dataclass
class KeyEntry:
    version: str
    state: str
    secret_b64: str  # base64 of the 32-byte master secret; "" once disabled
    created_at: str
    disabled_at: Optional[str] = None

    def secret_bytes(self) -> bytes:
        if self.state == "disabled" or not self.secret_b64:
            raise KeyringError(f"key {self.version} is disabled: secret destroyed")
        return base64.b64decode(self.secret_b64)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "state": self.state,
            "secret_b64": self.secret_b64,
            "created_at": self.created_at,
            "disabled_at": self.disabled_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "KeyEntry":
        return cls(
            version=d["version"],
            state=d["state"],
            secret_b64=d.get("secret_b64", ""),
            created_at=d["created_at"],
            disabled_at=d.get("disabled_at"),
        )


class Keyring:
    """Thread-safe key registry backed by a 0600 JSON file."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        self._entries: dict[str, KeyEntry] = {}
        self.current: Optional[str] = None
        # version -> count of downloads currently decrypting with this key
        self.in_flight: dict[str, int] = {}
        if os.path.exists(path):
            self._load()

    # ------------------------------------------------------------------ I/O
    def _load(self) -> None:
        with open(self.path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        self._entries = {
            e["version"]: KeyEntry.from_dict(e) for e in doc["keys"]
        }
        self.current = doc.get("current")
        self.in_flight = {k: 0 for k in self._entries}

    def _save(self) -> None:
        doc = {"current": self.current, "keys": [e.to_dict() for e in self._entries.values()]}
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2, ensure_ascii=False)
        # Private: owner read/write only, never group/world readable.
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(tmp, self.path)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)

    # ------------------------------------------------------------- mutation
    def create_version(self, version: str, now_iso: str,
                       make_current: bool = False) -> KeyEntry:
        with self._lock:
            if version in self._entries:
                raise KeyringError(f"key version {version} already exists")
            secret = crypto.random_secret()
            secret_b64 = base64.b64encode(secret).decode("ascii")
            # Make sure the secret can never appear in a log line verbatim.
            redaction_filter.register(secret, secret_b64)
            entry = KeyEntry(
                version=version,
                state="active",
                secret_b64=secret_b64,
                created_at=now_iso,
            )
            self._entries[version] = entry
            self.in_flight[version] = 0
            # A freshly registered key does NOT become the encryption key
            # automatically; cutover (or an explicit set_current) does that.
            if make_current or self.current is None:
                self.current = version
            self._save()
            return entry

    def set_current(self, version: str) -> None:
        with self._lock:
            entry = self._require(version)
            if entry.state != "active":
                raise KeyringError(
                    f"only active keys can be current; {version} is {entry.state}"
                )
            self.current = version
            self._save()

    def retire(self, version: str) -> None:
        """active -> retired (decrypt only). Current key cannot be retired."""
        with self._lock:
            entry = self._require(version)
            if self.current == version:
                raise KeyringError(
                    f"cannot retire {version}: it is the current encryption key"
                )
            if entry.state != "active":
                raise KeyringError(f"key {version} is already {entry.state}")
            entry.state = "retired"
            self._save()

    def disable(self, version: str, references: int, now_iso: str) -> None:
        """
        Destroy the secret. Allowed only with zero file references AND zero
        in-flight downloads. `references` is supplied by the manifest service
        so the keyring never decides this on its own.
        """
        with self._lock:
            entry = self._require(version)
            if self.current == version:
                raise KeyringError(
                    f"cannot disable {version}: it is the current encryption key"
                )
            if references > 0:
                raise KeyringError(
                    f"cannot disable {version}: {references} file(s) still reference it"
                )
            if self.in_flight.get(version, 0) > 0:
                raise KeyringError(
                    f"cannot disable {version}: "
                    f"{self.in_flight[version]} download(s) in flight"
                )
            if entry.state == "disabled":
                raise KeyringError(f"key {version} already disabled")
            entry.state = "disabled"
            entry.secret_b64 = ""
            entry.disabled_at = now_iso
            self._save()

    # -------------------------------------------------------------- lookups
    def _require(self, version: str) -> KeyEntry:
        if version not in self._entries:
            raise KeyringError(f"unknown key version {version}")
        return self._entries[version]

    def get_secret(self, version: str) -> bytes:
        with self._lock:
            return self._require(version).secret_bytes()

    def state_of(self, version: str) -> str:
        with self._lock:
            return self._require(version).state

    def list_versions(self) -> list[dict]:
        with self._lock:
            return [
                {
                    **e.to_dict(),
                    "is_current": e.version == self.current,
                    "in_flight": self.in_flight.get(e.version, 0),
                }
                for e in self._entries.values()
            ]

    # ----------------------------------------------------- download tracking
    def begin_use(self, version: str) -> None:
        """Pin a key version while a download is decrypting with it."""
        with self._lock:
            self._require(version)  # disabled key raises immediately
            self.in_flight[version] = self.in_flight.get(version, 0) + 1

    def end_use(self, version: str) -> None:
        with self._lock:
            if self.in_flight.get(version, 0) > 0:
                self.in_flight[version] -= 1


def new_version_id(existing: set[str]) -> str:
    """Pick v1, v2, ... avoiding collisions (human-friendly demo ids)."""
    i = 1
    while f"v{i}" in existing:
        i += 1
    return f"v{i}"


def random_token() -> str:
    return secrets.token_hex(8)
