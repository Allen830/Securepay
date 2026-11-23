from __future__ import annotations

import pytest

from securepay import config


def test_production_kdf_parameters_are_moderate() -> None:
    assert config.ARGON2ID_OPSLIMIT == 3
    assert config.ARGON2ID_MEMLIMIT == 64 * 1024 * 1024


def test_security_constants_are_sane() -> None:
    assert config.MAX_FRAME_BYTES <= 1 << 20
    assert config.KEY_BYTES == 32
    assert config.NONCE_BYTES == 12
    assert config.NONCE_PREFIX_BYTES + config.NONCE_COUNTER_BYTES == 12
    assert config.MAX_COUNTER >= 1 << 48
    assert config.MAX_CLOCK_SKEW_SECONDS <= 300
    assert config.REKEY_AFTER_MESSAGES < config.MAX_COUNTER
    assert config.UNLOCK_MAX_FAILURES <= 10


def test_temporary_overrides_and_restores() -> None:
    original = config.REKEY_AFTER_MESSAGES
    with config.temporary(REKEY_AFTER_MESSAGES=5, MAX_CLOCK_SKEW_SECONDS=2):
        assert config.REKEY_AFTER_MESSAGES == 5
        assert config.MAX_CLOCK_SKEW_SECONDS == 2
    assert original == config.REKEY_AFTER_MESSAGES


def test_temporary_restores_on_exception() -> None:
    original = config.PENDING_TTL_SECONDS
    with pytest.raises(RuntimeError), config.temporary(PENDING_TTL_SECONDS=1):
        assert config.PENDING_TTL_SECONDS == 1
        raise RuntimeError("boom")
    assert original == config.PENDING_TTL_SECONDS


def test_temporary_rejects_unknown_parameters() -> None:
    with pytest.raises(ValueError, match="not overridable"), \
            config.temporary(MAX_FRAME_BYTES=10):
        pass


def test_network_paths_layout(tmp_path: object) -> None:
    paths = config.NetworkPaths(root=tmp_path)
    assert paths.ca_cert == tmp_path / "ca" / "ca.crt"
    assert paths.switch_vault == tmp_path / "switch" / "switch.keys"
    assert paths.wallet_vault("902101") == tmp_path / "wallets" / "902101.keys"
    assert paths.terminal_cert("coffee_shop") == tmp_path / "terminals" / "coffee_shop.crt"
    assert paths.ledger == tmp_path / "ledger.db"
    paths.ensure()
    assert paths.wallets_dir.is_dir()
    assert paths.receipts_dir.is_dir()
