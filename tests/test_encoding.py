from __future__ import annotations

import pytest

from securepay import config
from securepay.encoding import (
    ValidationError,
    b64_decode,
    b64_encode,
    canonical_bytes,
    domain_tag,
    format_amount,
    fresh_timestamp,
    mask_pan,
    new_txn_id,
    now_ts,
    parse_amount_minor,
    u32be,
    validate_amount_minor,
    validate_currency,
    validate_id,
    validate_timestamp,
    validate_txn_id,
)


def test_canonical_bytes_is_deterministic() -> None:
    a = {"b": 2, "a": 1, "c": [3, {"d": "e"}]}
    b = {"c": [3, {"d": "e"}], "a": 1, "b": 2}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_bytes_rejects_floats() -> None:
    with pytest.raises(ValidationError):
        canonical_bytes({"amount": 1.5})


def test_canonical_bytes_rejects_non_string_keys() -> None:
    with pytest.raises(ValidationError):
        canonical_bytes({1: "x"})


def test_canonical_bytes_rejects_sets() -> None:
    with pytest.raises(ValidationError):
        canonical_bytes({"s": {1, 2}})


def test_b64_roundtrip_and_strict_decode() -> None:
    data = b"\x00\xffhello"
    assert b64_decode(b64_encode(data)) == data
    with pytest.raises(ValidationError):
        b64_decode("not valid base64!!")


def test_u32be_roundtrip() -> None:
    assert int.from_bytes(u32be(0xDEADBEEF), "big") == 0xDEADBEEF
    with pytest.raises(ValidationError):
        u32be(1 << 32)


def test_domain_tag_is_stable_and_validated() -> None:
    assert domain_tag("SP1", "CV", "server") == b"SP1/CV/server"
    with pytest.raises(ValidationError):
        domain_tag("bad tag with spaces")


def test_mask_pan() -> None:
    assert mask_pan("4012 8821 9021 3341") == "****-****-****-3341"
    with pytest.raises(ValidationError):
        mask_pan("123")


def test_amount_parsing_and_formatting() -> None:
    assert parse_amount_minor("12.50") == 1250
    assert parse_amount_minor("0.01") == 1
    assert parse_amount_minor("1000") == 100000
    assert format_amount(1250) == "12.50"
    assert format_amount(1) == "0.01"
    assert format_amount(100000) == "1000.00"
    for bad in ("", "-5", "1.234", "abc", "NaN", "Infinity", "1e3", " 12.50 "):
        with pytest.raises(ValidationError):
            parse_amount_minor(bad)


def test_validate_amount_minor_bounds() -> None:
    assert validate_amount_minor(1) == 1
    assert validate_amount_minor(config.MAX_AMOUNT_MINOR) == config.MAX_AMOUNT_MINOR
    for bad in (0, -1, config.MAX_AMOUNT_MINOR + 1, 1.5, "5", True):
        with pytest.raises(ValidationError):
            validate_amount_minor(bad)


def test_validate_id_rules() -> None:
    assert validate_id("coffee_shop") == "coffee_shop"
    assert validate_id("902101") == "902101"
    for bad in ("", "UPPER", "with space", "a" * 33, "-leading", "ok!char"):
        with pytest.raises(ValidationError):
            validate_id(bad)


def test_validate_currency() -> None:
    assert validate_currency("AED") == "AED"
    for bad in ("aed", "AE", "AEDX", 5, ""):
        with pytest.raises(ValidationError):
            validate_currency(bad)


def test_txn_id_format() -> None:
    txn = new_txn_id()
    assert validate_txn_id(txn) == txn
    assert new_txn_id() != new_txn_id()
    for bad in ("TXN-1-X", "not-a-txn", "", "TXN-1234567890-ABCDEF123456 extra"):
        with pytest.raises(ValidationError):
            validate_txn_id(bad)


def test_timestamp_validation() -> None:
    assert validate_timestamp(now_ts()) == now_ts()
    with pytest.raises(ValidationError):
        validate_timestamp("123")
    with pytest.raises(ValidationError):
        validate_timestamp(-1)
    with pytest.raises(ValidationError):
        validate_timestamp(0)
    assert fresh_timestamp(now_ts())
    assert not fresh_timestamp(now_ts() - 10 * 365 * 24 * 3600)
