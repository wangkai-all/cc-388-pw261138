"""
key_rotation.log_security
=========================
Defense in depth so master secrets never reach the logs.

* SecretRedactionFilter holds the set of every secret value ever created by
  the keyring (raw bytes and base64 form). Any log record containing one is
  scrubbed before emission.
* As a pattern-based backstop, long base64/hex runs (the shape of an encoded
  key) are replaced even if the value wasn't registered.
* The filter is attached to the root logger and also exposed as a standalone
  function `redact(text)` used when serializing API payloads.
"""

from __future__ import annotations

import logging
import re

# >=24 chars of base64 or >=32 hex chars: the shape key material takes.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RUN = re.compile(r"(?<![A-Fa-f0-9])[a-f0-9]{32,}(?![A-Fa-f0-9])")
_REPLACEMENT = "<REDACTED-KEY-MATERIAL>"


class SecretRedactionFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()

    def register(self, *values: bytes | str) -> None:
        for value in values:
            if not value:
                continue
            if isinstance(value, bytes):
                import base64

                self._secrets.add(value.hex())
                self._secrets.add(base64.b64encode(value).decode("ascii"))
            else:
                self._secrets.add(value)

    def redact(self, text: str) -> str:
        for secret in self._secrets:
            if secret and secret in text:
                text = text.replace(secret, _REPLACEMENT)
        text = _B64_RUN.sub(_REPLACEMENT, text)
        text = _HEX_RUN.sub(_REPLACEMENT, text)
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        scrubbed = self.redact(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        return True


# Process-wide singleton; webapp attaches it to the root logger.
redaction_filter = SecretRedactionFilter()


def redact(text: str) -> str:
    return redaction_filter.redact(text)
