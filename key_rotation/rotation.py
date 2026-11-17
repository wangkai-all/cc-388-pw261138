"""
key_rotation.rotation
=====================
Background per-file re-encryption worker and its policy choices.

Two strategies (the human decision called out in the brief):

* mixed  -- files are rewritten to the target key one by one; old key
            versions stay active and the fleet is legitimately mixed during
            and after the run. Every query keeps working because readers
            resolve the key from each file header.
* cutover -- same per-file rewrite, but once EVERY file has succeeded the
            target becomes the current encryption key and the previous
            versions are retired (decrypt-only) automatically. If any file
            fails, the cutover is withheld: nothing is retired and the fleet
            stays mixed until the failures are recovered and retried.

Failure semantics: rewrites are atomic, so a failed/tampered file keeps its
complete old container and its old key version. One bad file never blocks
the others; the job ends in state "failed" and the failed files can be
recovered (backup restore) and retried.
"""

from __future__ import annotations

import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import crypto
from .keyring import Keyring
from .storage import EncryptedStore, StorageError


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class FileItem:
    file_id: str
    from_version: str
    status: str = "pending"  # pending | processing | done | failed
    error: Optional[str] = None
    finished_at: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "file_id": self.file_id,
            "from_version": self.from_version,
            "status": self.status,
            "error": self.error,
            "finished_at": self.finished_at,
        }


@dataclass
class RotationJob:
    job_id: str
    target_version: str
    mode: str
    status: str = "queued"  # queued | running | paused | completed | failed
    items: list[FileItem] = field(default_factory=list)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    log: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id,
            "target_version": self.target_version,
            "mode": self.mode,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "items": [i.to_dict() for i in self.items],
            "log": list(self.log),
            "counts": {
                "total": len(self.items),
                "done": sum(1 for i in self.items if i.status == "done"),
                "failed": sum(1 for i in self.items if i.status == "failed"),
                "pending": sum(1 for i in self.items if i.status == "pending"),
                "processing": sum(1 for i in self.items if i.status == "processing"),
            },
        }


class RotationManager:
    def __init__(self, store: EncryptedStore, keyring: Keyring):
        self.store = store
        self.keyring = keyring
        self._lock = threading.RLock()
        self._pause = threading.Event()      # set = running, clear = paused
        self._pause.set()
        self._thread: Optional[threading.Thread] = None
        self.job: Optional[RotationJob] = None
        # fault-injection backups: file_id -> original container bytes
        self._tamper_backups: dict[str, bytes] = {}

    # ------------------------------------------------------------- helpers
    def _append_log(self, message: str) -> None:
        line = f"[{_now()}] {message}"
        self.job.log.append(line)

    def current_job(self) -> Optional[dict]:
        with self._lock:
            return self.job.to_dict() if self.job else None

    # -------------------------------------------------------- lifecycle /
    def start(self, target_version: str, mode: str) -> RotationJob:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("a rotation job is already running")
            if mode not in ("mixed", "cutover"):
                raise ValueError("mode must be 'mixed' or 'cutover'")
            if self.keyring.state_of(target_version) != "active":
                raise RuntimeError(
                    f"target key {target_version} is not active"
                )
            files = self.store.list_files()
            if not files:
                raise RuntimeError("no partition files to rotate")
            job = RotationJob(
                job_id=uuid.uuid4().hex[:12],
                target_version=target_version,
                mode=mode,
                status="queued",
                items=[
                    FileItem(file_id=r["file_id"], from_version=r["key_version"])
                    for r in files
                ],
                started_at=_now(),
            )
            self.job = job
            self._pause.set()
            self._append_log(
                f"job {job.job_id} started: {len(job.items)} file(s) -> "
                f"{target_version}, mode={mode}"
            )
            self._thread = threading.Thread(
                target=self._worker, args=(job,), daemon=True,
                name=f"rotation-{job.job_id}",
            )
            self._thread.start()
            return job

    def pause(self) -> None:
        with self._lock:
            if not self.job:
                raise RuntimeError("no job to pause")
            if self.job.status == "completed":
                raise RuntimeError("job already completed")
            self._pause.clear()
            if self.job.status in ("running", "queued"):
                self.job.status = "paused"
            self._append_log("paused by operator; in-flight file finishes first")

    def resume(self) -> None:
        with self._lock:
            if not self.job or self.job.status != "paused":
                raise RuntimeError("job is not paused")
            self._pause.set()
            self.job.status = "running"
            self._append_log("resumed by operator")

    def retry_failed(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError("job still running")
            if not self.job:
                raise RuntimeError("no job present")
            requeued = 0
            for item in self.job.items:
                if item.status in ("failed", "pending"):
                    item.status = "pending"
                    item.error = None
                    item.finished_at = None
                    requeued += 1
            if requeued == 0:
                raise RuntimeError("no failed items to retry")
            self.job.status = "queued"
            self.job.finished_at = None
            # Do not force the pause gate open: a caller may pause first,
            # then enqueue the retry for a controlled step-through.
            self._append_log(f"retry requested for {requeued} failed file(s)")
            self._thread = threading.Thread(
                target=self._worker, args=(self.job,), daemon=True,
                name=f"rotation-retry-{self.job.job_id}",
            )
            self._thread.start()

    # ------------------------------------------------------------ worker /
    def _worker(self, job: RotationJob) -> None:
        if job.status == "queued":
            # Respect a pause requested before the worker started.
            job.status = "paused" if not self._pause.is_set() else "running"
        for item in job.items:
            if item.status != "pending":
                continue
            # Pause gate: block here while suspended, without holding locks.
            self._pause.wait()
            with self._lock:
                if job.status == "paused":
                    job.status = "running"
            item.status = "processing"
            self._append_log(f"rewriting {item.file_id} "
                             f"({item.from_version} -> {job.target_version})")
            try:
                record = self.store.rewrite_with_key(
                    item.file_id, job.target_version, _now()
                )
                item.from_version = record.key_version
                item.status = "done"
                item.finished_at = _now()
                self._append_log(f"done {item.file_id} -> {record.key_version}")
            except Exception as exc:
                # Atomic rewrite failed: the old container is untouched, so
                # the file stays on its previous, still-readable version.
                item.status = "failed"
                item.error = str(exc)
                item.finished_at = _now()
                self.store.mark_failed(item.file_id, str(exc), _now())
                self._append_log(f"FAILED {item.file_id}: {exc}")

        failures = [i for i in job.items if i.status == "failed"]
        job.finished_at = _now()
        if failures:
            job.status = "failed"
            self._append_log(
                f"job finished with {len(failures)} failure(s); "
                "cutover withheld, fleet remains mixed"
            )
            return

        job.status = "completed"
        self._append_log("all files rewritten and verified")
        if job.mode == "cutover":
            try:
                if self.keyring.current != job.target_version:
                    self.keyring.set_current(job.target_version)
                # Retire every other still-active version: decrypt-only now.
                for entry in self.keyring.list_versions():
                    if (entry["version"] != job.target_version
                            and entry["state"] == "active"):
                        self.keyring.retire(entry["version"])
                        self._append_log(
                            f"cutover: key {entry['version']} retired "
                            "(decrypt-only)"
                        )
                self._append_log(
                    f"cutover complete: current key is {job.target_version}"
                )
            except Exception as exc:  # policy failure shouldn't lose data
                job.status = "failed"
                self._append_log(f"cutover policy error: {exc}")

    # ------------------------------------------------ fault injection /
    def inject_failure(self, file_id: str) -> None:
        """
        Corrupt one file's on-disk ciphertext (with a backup for recovery).
        The next verification or rewrite of that file fails authentication.
        """
        with self._lock:
            if file_id not in self.store.records:
                raise StorageError(f"unknown file {file_id}")
            path = self.store._path(file_id)
            with open(path, "rb") as fh:
                original = fh.read()
            self._tamper_backups[file_id] = original
            self.store.tamper_file(file_id)
            self.store.mark_failed(
                file_id,
                "fault injected: ciphertext byte flipped on disk",
                _now(),
            )
            if self.job:
                self._append_log(f"fault injected into {file_id}")

    def recover_file(self, file_id: str) -> dict:
        """
        Recovery path: restore the pre-tamper container from the local
        backup, re-authenticate it, and clear the failure marker. The file
        returns to its pre-failure key version and can be retried.
        """
        with self._lock:
            if file_id not in self._tamper_backups:
                raise RuntimeError(
                    f"no fault backup for {file_id}; nothing to recover"
                )
            backup = self._tamper_backups.pop(file_id)
            path = self.store._path(file_id)
            tmp = path + ".restoring"
            with open(tmp, "wb") as fh:
                fh.write(backup)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            record = self.store.verify_file(file_id, _now())
            if self.job:
                for item in self.job.items:
                    if item.file_id == file_id and item.status == "failed":
                        item.status = "pending"
                        item.error = None
                self._append_log(
                    f"{file_id} restored from backup; verification "
                    f"{record.verify_status}"
                )
            return record.to_dict()

    def verify_one(self, file_id: str) -> dict:
        with self._lock:
            return self.store.verify_file(file_id, _now()).to_dict()
