from __future__ import annotations

import json
import logging
import stat
from pathlib import Path

import pytest

from securepay import config
from securepay.attacks.simulator import LogCapture
from securepay.errors import (
    AADMismatchError,
    BadPassphraseError,
    CorruptVaultError,
    KeystoreError,
    RateLimitError,
)
from securepay.keystore import load_vault, save_vault, unlock_vault, zeroise
from securepay.ratelimit import AttemptTracker

AAD = {"kind": "student", "id": "902101"}


@pytest.fixture(autouse=True)
def _fast_kdf(fast_kdf_ctx: None) -> None:
    pass


def _save(tmp_path: Path, payload: dict | None = None, aad: dict | None = None) -> Path:
    path = tmp_path / "vault.keys"
    save_vault(path, "correct horse battery staple", payload or {"seed": "ab" * 32}, aad or AAD)
    return path


def test_roundtrip(tmp_path: Path) -> None:
    path = _save(tmp_path, {"seed": "cd" * 32, "next_nonce": 7})
    loaded = load_vault(path, "correct horse battery staple", AAD)
    assert loaded["seed"] == "cd" * 32
    assert loaded["next_nonce"] == 7


def test_wrong_passphrase_rejected(tmp_path: Path) -> None:
    path = _save(tmp_path)
    with pytest.raises(BadPassphraseError):
        load_vault(path, "wrong passphrase", AAD)


def test_aad_mismatch_rejected(tmp_path: Path) -> None:
    path = _save(tmp_path)
    with pytest.raises(AADMismatchError):
        load_vault(path, "correct horse battery staple", {"kind": "student", "id": "902102"})


def test_tampered_ciphertext_rejected(tmp_path: Path) -> None:
    path = _save(tmp_path)
    record = json.loads(path.read_text(encoding="utf-8"))
    import base64

    raw = bytearray(base64.b64decode(record["ciphertext"]))
    raw[0] ^= 0x01
    record["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(BadPassphraseError):
        load_vault(path, "correct horse battery staple", AAD)


def test_kdf_parameter_downgrade_rejected(tmp_path: Path) -> None:
    path = _save(tmp_path)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["kdf_params"]["opslimit"] = 2
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(CorruptVaultError):
        load_vault(path, "correct horse battery staple", AAD)


def test_unknown_format_rejected(tmp_path: Path) -> None:
    path = _save(tmp_path)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["format"] = "evil-vault"
    path.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(CorruptVaultError):
        load_vault(path, "correct horse battery staple", AAD)


def test_garbage_file_rejected(tmp_path: Path) -> None:
    path = tmp_path / "vault.keys"
    path.write_bytes(b"\x00\x01not json at all")
    path.chmod(0o600)
    with pytest.raises(CorruptVaultError):
        load_vault(path, "whatever", AAD)


def test_file_permissions_are_0600(tmp_path: Path) -> None:
    path = _save(tmp_path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_refuses_world_readable_existing_vault(tmp_path: Path) -> None:
    path = _save(tmp_path)
    path.chmod(0o644)
    with pytest.raises(KeystoreError):
        load_vault(path, "correct horse battery staple", AAD)


def test_resave_changes_ciphertext(tmp_path: Path) -> None:
    path = _save(tmp_path)
    first = json.loads(path.read_text(encoding="utf-8"))["ciphertext"]
    save_vault(path, "correct horse battery staple", {"seed": "ab" * 32}, AAD)
    second = json.loads(path.read_text(encoding="utf-8"))["ciphertext"]
    assert first != second


def test_unlock_vault_lockout(tmp_path: Path) -> None:
    path = _save(tmp_path)
    tracker = AttemptTracker(tmp_path / "vault.attempts")
    for _ in range(config.UNLOCK_MAX_FAILURES):
        with pytest.raises(BadPassphraseError):
            unlock_vault(path, "nope", AAD, tracker)
    with pytest.raises(RateLimitError):
        unlock_vault(path, "correct horse battery staple", AAD, tracker)


def test_failed_unlocks_and_lockout_are_logged(tmp_path: Path) -> None:
    path = _save(tmp_path)
    tracker = AttemptTracker(tmp_path / "vault.attempts")
    capture = LogCapture()
    log = logging.getLogger("securepay.keystore")
    log.addHandler(capture)
    try:
        for _ in range(config.UNLOCK_MAX_FAILURES):
            with pytest.raises(BadPassphraseError):
                unlock_vault(path, "nope", AAD, tracker)
        with pytest.raises(RateLimitError):
            unlock_vault(path, "correct horse battery staple", AAD, tracker)
    finally:
        log.removeHandler(capture)
    levels = {lv for lv, _msg in capture.records}
    assert levels == {"WARNING"}
    assert capture.expect("event=vault_unlock_failed", count=config.UNLOCK_MAX_FAILURES) == ""
    assert capture.expect("event=vault_locked_out") == ""
    assert not any("nope" in msg or "correct horse" in msg for _lv, msg in capture.records)


def test_zeroise_scrubs_bytearrays() -> None:
    buf = bytearray(b"\xff" * 32)
    zeroise(buf)
    assert bytes(buf) == b"\x00" * 32
