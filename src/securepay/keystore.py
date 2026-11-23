from __future__ import annotations

import base64
import json
import logging
import os
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from nacl import bindings as sodium
from nacl.exceptions import CryptoError
from nacl.pwhash import argon2id as _argon2id

from securepay import config
from securepay.errors import (
    AADMismatchError,
    BadPassphraseError,
    CorruptVaultError,
    KeystoreError,
    RateLimitError,
)
from securepay.ratelimit import AttemptTracker

logger = logging.getLogger(__name__)

__all__ = [
    "VAULT_CIPHER",
    "load_vault",
    "save_vault",
    "unlock_vault",
    "zeroise",
]

VAULT_CIPHER = "ChaCha20-Poly1305"


def _derive_key(passphrase: str, salt: bytes, opslimit: int, memlimit: int) -> bytearray:
    key = _argon2id.kdf(
        config.KDF_OUTPUT_BYTES,
        passphrase.encode("utf-8"),
        salt,
        opslimit=opslimit,
        memlimit=memlimit,
    )
    if not isinstance(key, bytes) or len(key) != config.KDF_OUTPUT_BYTES:
        raise KeystoreError("KDF returned unexpected output")
    return bytearray(key)


def _check_writable_secure(path: Path) -> None:
    if path.exists():
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise KeystoreError(
                f"vault {path.name} has group/other permission bits set "
                f"({oct(mode)}); refusing to use it"
            )


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def save_vault(path: Path, passphrase: str, payload: dict[str, Any], aad: dict[str, Any]) -> None:
    if not passphrase:
        raise KeystoreError("passphrase must not be empty")
    salt = os.urandom(config.KDF_SALT_BYTES)
    nonce = os.urandom(config.NONCE_BYTES)
    kdf_params = {
        "opslimit": int(config.ARGON2ID_OPSLIMIT),
        "memlimit": int(config.ARGON2ID_MEMLIMIT),
    }
    key = _derive_key(passphrase, salt, **kdf_params)
    try:
        aad_bytes = json.dumps(aad, sort_keys=True, separators=(",", ":")).encode()
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
            payload_bytes,
            aad_bytes,
            nonce,
            bytes(key),
        )
    finally:
        zeroise(key)
    record = {
        "format": config.VAULT_FORMAT,
        "version": config.VAULT_VERSION,
        "kdf": "argon2id",
        "kdf_params": kdf_params,
        "cipher": VAULT_CIPHER,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "aad": aad,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    body = json.dumps(record, sort_keys=True, indent=2).encode("utf-8")
    _atomic_write(path, body)
    logger.info("event=vault_saved path=%s aad=%s", path.name, aad)


def load_vault(
    path: Path,
    passphrase: str,
    expected_aad: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _check_writable_secure(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CorruptVaultError(f"cannot read vault file: {path.name}") from exc
    try:
        record = json.loads(raw)
        if record["format"] != config.VAULT_FORMAT:
            raise CorruptVaultError("unknown vault format")
        if int(record["version"]) != config.VAULT_VERSION:
            raise CorruptVaultError("unsupported vault version")
        if record["kdf"] != "argon2id" or record["cipher"] != VAULT_CIPHER:
            raise CorruptVaultError("unexpected KDF or cipher")
        params = record["kdf_params"]
        if (
            int(params["opslimit"]) != config.ARGON2ID_OPSLIMIT
            or int(params["memlimit"]) != config.ARGON2ID_MEMLIMIT
        ):
            raise CorruptVaultError("vault KDF parameters do not match configuration")
        salt = base64.b64decode(record["salt"], validate=True)
        nonce = base64.b64decode(record["nonce"], validate=True)
        ciphertext = base64.b64decode(record["ciphertext"], validate=True)
        if len(salt) != config.KDF_SALT_BYTES or len(nonce) != config.NONCE_BYTES:
            raise CorruptVaultError("bad salt/nonce length")
    except (KeyError, ValueError, TypeError) as exc:
        raise CorruptVaultError("vault file is malformed") from exc

    key = _derive_key(
        passphrase,
        salt,
        int(params["opslimit"]),
        int(params["memlimit"]),
    )
    try:
        aad_bytes = json.dumps(record["aad"], sort_keys=True, separators=(",", ":")).encode()
        plaintext = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            ciphertext, aad_bytes, nonce, bytes(key)
        )
    except CryptoError as exc:
        raise BadPassphraseError(
            "vault authentication failed (wrong passphrase or tampered file)"
        ) from exc
    finally:
        zeroise(key)

    if expected_aad is not None and record["aad"] != expected_aad:
        raise AADMismatchError(f"vault metadata mismatch (stored={record['aad']!r})")
    try:
        payload = json.loads(plaintext)
        if not isinstance(payload, dict):
            raise ValueError("payload is not an object")
    except ValueError as exc:
        raise CorruptVaultError("vault payload is malformed") from exc
    logger.info("event=vault_opened path=%s", path.name)
    return payload


def unlock_vault(
    path: Path,
    passphrase: str,
    expected_aad: dict[str, Any],
    tracker: AttemptTracker,
    *,
    sleep_on_failure: Callable[[], None] | None = None,
) -> dict[str, Any]:
    try:
        tracker.ensure_unlocked()
    except RateLimitError:
        logger.warning("event=vault_locked_out path=%s", path.name)
        raise
    try:
        payload = load_vault(path, passphrase, expected_aad)
    except BadPassphraseError:
        logger.warning("event=vault_unlock_failed path=%s", path.name)
        if sleep_on_failure is not None:
            sleep_on_failure()
        tracker.record_failure()
        raise
    tracker.record_success()
    return payload


def zeroise(buffer: bytes | bytearray, label: str = "key material") -> None:
    if isinstance(buffer, bytearray):
        for i in range(len(buffer)):
            buffer[i] = 0
    logger.debug("event=zeroised label=%s", label)
