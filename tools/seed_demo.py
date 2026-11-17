#!/usr/bin/env python3
"""
tools/seed_demo.py
==================
Create a fresh demo environment:

  private/keyring.json  -- 0600 registry containing key v1's master secret
  data/partition-*.enc  -- fictional partition files, really encrypted
  downloads/            -- output dir for query bundles

All plaintext is synthetic. Run repeatedly only against an empty target.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from key_rotation.keyring import Keyring
from key_rotation.storage import EncryptedStore

PARTITIONS = [
    ("partition-cn-01", "orders",   120),
    ("partition-cn-02", "orders",   135),
    ("partition-eu-01", "orders",    98),
    ("partition-eu-02", "invoices", 110),
    ("partition-us-01", "invoices", 142),
    ("partition-us-02", "users",     76),
    ("partition-sg-01", "users",     88),
    ("partition-sg-02", "events",   210),
]

FIRST_NAMES = ["Ava", "Li", "Noah", "Mia", "Omar", "Yuki", "Ines", "Sam"]
CITIES = ["Beijing", "Berlin", "Austin", "Lisbon", "Singapore", "Osaka"]


def synth_rows(domain: str, n: int) -> bytes:
    lines = ["id,domain,customer,city,amount,currency,ts"]
    for i in range(1, n + 1):
        name = FIRST_NAMES[(i * 7) % len(FIRST_NAMES)]
        city = CITIES[(i * 3) % len(CITIES)]
        amount = 100 + (i * 37) % 9000
        currency = ["CNY", "EUR", "USD"][i % 3]
        ts = 1_700_000_000 + i * 913
        lines.append(f"{i:05d},{domain},{name},{city},{amount}.00,{currency},{ts}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Seed the key-rotation demo")
    parser.add_argument("--base-dir", default="demo_env",
                        help="environment directory (default: demo_env)")
    args = parser.parse_args()

    base = os.path.abspath(args.base_dir)
    private = os.path.join(base, "private")
    data = os.path.join(base, "data")
    os.makedirs(private, mode=0o700, exist_ok=True)
    os.makedirs(data, exist_ok=True)
    os.makedirs(os.path.join(base, "downloads"), exist_ok=True)

    keyring_path = os.path.join(private, "keyring.json")
    if os.path.exists(keyring_path) or os.listdir(data):
        print(f"refusing to seed: {base} already contains data", file=sys.stderr)
        return 2

    # Logging with redaction, before any secret is generated.
    try:
        from key_rotation.log_security import redaction_filter  # noqa: F401
        import logging
        h = logging.StreamHandler()
        h.addFilter(redaction_filter)
        logging.getLogger().addHandler(h)
        logging.getLogger().setLevel(logging.INFO)
    except Exception:
        pass

    keyring = Keyring(keyring_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    keyring.create_version("v1", now, make_current=True)

    store = EncryptedStore(data, keyring)
    total_bytes = 0
    for file_id, domain, rows in PARTITIONS:
        plaintext = synth_rows(domain, rows)
        store.put_encrypted(file_id, "v1", plaintext, now)
        total_bytes += len(plaintext)
        print(f"  encrypted {file_id:16s} {len(plaintext):6d} bytes under v1")

    mode = oct(os.stat(keyring_path).st_mode & 0o777)
    print(f"\nseeded {len(PARTITIONS)} partition files ({total_bytes} plaintext bytes)")
    print(f"keyring: {keyring_path} (permissions {mode})")
    print(f"data:    {data}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
