"""Exit codes and error hierarchy, per 03_SECURITY_AND_ACCESS.md section 7.

The full table was defined from M1 even though M1 only ever emitted a
subset of these codes (0, 2, 20, 21, 40, 41, 43, 70). M2 now emits 30
(stale timestamp), 31 (rollback), and 44 (timestamp equivocation). The
transparency log itself, and codes 42/45, remain M3.
"""

from __future__ import annotations

from enum import IntEnum
from pathlib import Path


class ExitCode(IntEnum):
    OK = 0
    USAGE = 2
    NETWORK = 20
    REFERENCE_NOT_FOUND = 21
    STALE = 30  # M2: no unexpired timestamp obtainable
    ROLLBACK = 31  # M2: seq or root version below high-water mark
    DIGEST_MISMATCH = 40
    SIGNATURE_INVALID = 41
    KEY_REVOKED = 42  # M3
    PIN_MISMATCH = 43
    LOG_FAILURE = 44  # M3: transparency log inclusion/consistency/equivocation
    PROVENANCE_INVALID = 45  # M3
    INTERNAL = 70


class TesseraError(Exception):
    """Base class for all errors that terminate a command with a specific exit code."""

    exit_code: ExitCode = ExitCode.INTERNAL

    def __init__(self, message: str, *, evidence: Path | None = None, **detail):
        super().__init__(message)
        self.message = message
        self.evidence = evidence
        self.detail = detail


class UsageError(TesseraError):
    exit_code = ExitCode.USAGE


class NetworkError(TesseraError):
    exit_code = ExitCode.NETWORK


class ReferenceNotFoundError(TesseraError):
    exit_code = ExitCode.REFERENCE_NOT_FOUND


class StaleError(TesseraError):
    exit_code = ExitCode.STALE


class RollbackError(TesseraError):
    exit_code = ExitCode.ROLLBACK


class DigestMismatchError(TesseraError):
    exit_code = ExitCode.DIGEST_MISMATCH


class SignatureError(TesseraError):
    exit_code = ExitCode.SIGNATURE_INVALID


class PinMismatchError(TesseraError):
    exit_code = ExitCode.PIN_MISMATCH


class LogFailureError(TesseraError):
    exit_code = ExitCode.LOG_FAILURE


class InternalError(TesseraError):
    exit_code = ExitCode.INTERNAL
