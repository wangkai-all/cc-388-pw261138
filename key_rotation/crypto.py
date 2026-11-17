"""
key_rotation.crypto
===================
Real authenticated encryption built only from the Python standard library.

Construction (per encrypted file):
  * Every key version holds one 32-byte master secret (never leaves the local
    private keyring file).
  * A random 16-byte nonce is generated per encryption and stored *inside* the
    encrypted file header -- it is not a secret.
  * A per-file key is derived with HKDF-SHA256(master, salt=nonce,
    info=b"keyrotation/v1/data").
  * The keystream is HMAC-SHA256(per_file_key, counter || block_index)
    streamed over the plaintext in fixed blocks (HMAC-SHA256 counter mode).
  * Authentication is Encrypt-then-MAC: HMAC-SHA256(auth_key, header || AAD
    || ciphertext), where AAD binds the logical file id and key version.
  * The 32-byte MAC tag is appended to the file. Any tampering (ciphertext,
    header, nonce, version field) makes verification fail.

On-disk file format (all multi-byte integers big-endian):

    magic (4B, b"KRT1")
    version (1B, format version = 1)
    key_version_len (2B) | key_version (UTF-8, e.g. "v2")
    nonce_len (2B)       | nonce (16B random)
    plaintext_len (8B)
    ciphertext (plaintext_len bytes)
    tag (32B, HMAC-SHA256 over header || AAD || ciphertext)
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass

MAGIC = b"KRT1"
FORMAT_VERSION = 1
NONCE_SIZE = 16
TAG_SIZE = 32
BLOCK_SIZE = 32  # one HMAC-SHA256 output per keystream block
_HKDF_INFO_KEY = b"keyrotation/v1/data"
_HKDF_INFO_AUTH = b"keyrotation/v1/auth"


class CryptoError(Exception):
    """Base class for crypto failures."""


class InvalidFileFormat(CryptoError):
    """The blob does not parse as a KRT1 container."""


class VerificationError(CryptoError):
    """Authentication failed: wrong key, wrong AAD, or tampered data."""


def random_secret(size: int = 32) -> bytes:
    """Generate a fresh cryptographically secure master secret."""
    return os.urandom(size)


def random_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 expand; we only ever need 32 bytes so a single block suffices,
    # but the loop is written generically.
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def hkdf(master_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = _hkdf_extract(salt, master_secret)
    return _hkdf_expand(prk, info, length)


def _keystream_block(key: bytes, nonce: bytes, block_index: int) -> bytes:
    # 8-byte counter prefix keeps each keystream block globally unique within
    # a file (nonce already makes it unique across files).
    msg = nonce + struct.pack(">Q", block_index)
    return hmac.new(key, msg, hashlib.sha256).digest()


def _xor_stream(data_key: bytes, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    block_index = 0
    for start in range(0, len(data), BLOCK_SIZE):
        chunk = data[start : start + BLOCK_SIZE]
        ks = _keystream_block(data_key, nonce, block_index)[: len(chunk)]
        out.extend(a ^ b for a, b in zip(chunk, ks))
        block_index += 1
    return bytes(out)


@dataclass(frozen=True)
class EncryptedBlob:
    key_version: str
    nonce: bytes
    plaintext_len: int
    ciphertext: bytes
    tag: bytes

    def header(self) -> bytes:
        kv = self.key_version.encode("utf-8")
        return (
            MAGIC
            + struct.pack(">B", FORMAT_VERSION)
            + struct.pack(">H", len(kv))
            + kv
            + struct.pack(">H", len(self.nonce))
            + self.nonce
            + struct.pack(">Q", self.plaintext_len)
        )

    def to_bytes(self) -> bytes:
        return self.header() + self.ciphertext + self.tag


def _aad(file_id: str, key_version: str) -> bytes:
    # Bind the logical file identity so an encrypted blob cannot be moved
    # between partition files and still authenticate.
    return (
        b"keyrotation/v1/aad"
        + struct.pack(">H", len(file_id))
        + file_id.encode("utf-8")
        + struct.pack(">H", len(key_version))
        + key_version.encode("utf-8")
    )


def encrypt(master_secret: bytes, key_version: str, file_id: str,
            plaintext: bytes) -> bytes:
    """Encrypt plaintext and return the full authenticated container."""
    nonce = random_nonce()
    data_key = hkdf(master_secret, nonce, _HKDF_INFO_KEY)
    auth_key = hkdf(master_secret, nonce, _HKDF_INFO_AUTH)
    ciphertext = _xor_stream(data_key, nonce, plaintext)
    blob = EncryptedBlob(key_version, nonce, len(plaintext), ciphertext, b"")
    tag = hmac.new(
        auth_key, blob.header() + _aad(file_id, key_version) + ciphertext,
        hashlib.sha256,
    ).digest()
    object.__setattr__(blob, "tag", tag)
    return blob.to_bytes()


def parse_container(raw: bytes) -> EncryptedBlob:
    """Parse and structurally validate a KRT1 container (no crypto checks)."""
    # Fixed prefix: magic(4) + format(1) + kv_len(2); fields after are variable.
    if len(raw) < 7 or raw[:4] != MAGIC:
        raise InvalidFileFormat("not a KRT1 container (bad magic or truncated)")
    off = 4
    (fmt,) = struct.unpack(">B", raw[off : off + 1])
    off += 1
    if fmt != FORMAT_VERSION:
        raise InvalidFileFormat(f"unsupported format version {fmt}")
    (kv_len,) = struct.unpack(">H", raw[off : off + 2])
    off += 2
    if len(raw) < off + kv_len + 2:
        raise InvalidFileFormat("truncated at key version field")
    key_version = raw[off : off + kv_len].decode("utf-8")
    off += kv_len
    (n_len,) = struct.unpack(">H", raw[off : off + 2])
    off += 2
    if len(raw) < off + n_len + 8:
        raise InvalidFileFormat("truncated at nonce field")
    nonce = raw[off : off + n_len]
    off += n_len
    (plaintext_len,) = struct.unpack(">Q", raw[off : off + 8])
    off += 8
    if len(raw) < off + plaintext_len + TAG_SIZE:
        raise InvalidFileFormat("declared length exceeds actual file size")
    ciphertext = raw[off : off + plaintext_len]
    tag = raw[off + plaintext_len : off + plaintext_len + TAG_SIZE]
    return EncryptedBlob(key_version, nonce, plaintext_len, ciphertext, tag)


def decrypt(master_secret: bytes, file_id: str, raw: bytes) -> bytes:
    """Authenticate and decrypt a container. Raises VerificationError on tamper."""
    blob = parse_container(raw)
    data_key = hkdf(master_secret, blob.nonce, _HKDF_INFO_KEY)
    auth_key = hkdf(master_secret, blob.nonce, _HKDF_INFO_AUTH)
    expected = hmac.new(
        auth_key,
        blob.header() + _aad(file_id, blob.key_version) + blob.ciphertext,
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected, blob.tag):
        raise VerificationError(
            f"authentication failed for {file_id} "
            f"(key {blob.key_version}): data tampered or wrong key"
        )
    plaintext = _xor_stream(data_key, blob.nonce, blob.ciphertext)
    return plaintext


def peek_key_version(raw: bytes) -> str:
    """Return the key version recorded inside the container header."""
    return parse_container(raw).key_version
