from __future__ import annotations

import base64
import hashlib
import json
import re
import time
import uuid
from typing import Any

from securepay import config
from securepay.errors import ValidationError

__all__ = [
    "b64_decode",
    "b64_encode",
    "canonical_bytes",
    "domain_tag",
    "format_amount",
    "fresh_timestamp",
    "mask_pan",
    "new_txn_id",
    "now_ts",
    "parse_amount_minor",
    "parse_u32be",
    "sha256",
    "sha256_hex",
    "u32be",
    "validate_amount_minor",
    "validate_b64",
    "validate_currency",
    "validate_fresh_timestamp",
    "validate_id",
    "validate_str",
    "validate_timestamp",
    "validate_txn_id",
]


_ALLOWED_SCALARS = (bool, int, str, type(None))


def _check_canonical_types(value: Any, path: str = "$") -> None:
    if isinstance(value, _ALLOWED_SCALARS):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_canonical_types(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValidationError(f"non-string object key at {path}", detail=path)
        for field_name, field_value in value.items():
            _check_canonical_types(field_value, f"{path}.{field_name}")
        return
    raise ValidationError(
        f"value of type {type(value).__name__} at {path} is not canonicalisable",
        detail=path,
    )


def canonical_bytes(obj: Any) -> bytes:
    _check_canonical_types(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64_decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValidationError("malformed base64 value") from exc


def u32be(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise ValidationError(f"value out of u32 range: {value}")
    return value.to_bytes(4, "big")


def parse_u32be(data: bytes) -> int:
    if len(data) != 4:
        raise ValidationError("length prefix must be exactly 4 bytes")
    return int.from_bytes(data, "big")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def now_ts() -> int:
    return int(time.time())


def fresh_timestamp(ts: int, *, max_skew: float | None = None) -> bool:
    skew = config.MAX_CLOCK_SKEW_SECONDS if max_skew is None else max_skew
    return abs(now_ts() - ts) <= skew


def domain_tag(*parts: str) -> bytes:
    for part in parts:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", part):
            raise ValidationError(f"invalid domain tag component: {part!r}")
    return ("/".join(parts)).encode("ascii")


def mask_pan(pan_digits: str) -> str:
    digits = "".join(ch for ch in pan_digits if ch.isdigit())
    if not 12 <= len(digits) <= 19:
        raise ValidationError("PAN must contain 12-19 digits", detail="pan")
    return f"****-****-****-{digits[-4:]}"


def format_amount(amount_minor: int) -> str:
    validate_amount_minor(amount_minor)
    sign = "-" if amount_minor < 0 else ""
    major, minor = divmod(abs(amount_minor), config.MINOR_UNITS_PER_UNIT)
    return f"{sign}{major:d}.{minor:02d}"


def parse_amount_minor(text: str) -> int:
    if not isinstance(text, str) or not re.fullmatch(r"\d+(\.\d{1,2})?", text):
        raise ValidationError(f"amount must look like '12.50', got {text!r}", field="amount")
    whole, _, frac = text.partition(".")
    minor = int(whole) * config.MINOR_UNITS_PER_UNIT + int(frac.ljust(2, "0") or 0)
    validate_amount_minor(minor)
    return minor


_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_TXN_RE = re.compile(r"TXN-[0-9]{10}-[0-9A-F]{12}")
_CURRENCY_RE = re.compile(r"[A-Z]{3}")


def validate_id(value: Any, *, field: str = "id") -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValidationError(f"invalid {field}: {value!r}", field=field)
    return value


def validate_txn_id(value: Any) -> str:
    if not isinstance(value, str) or not _TXN_RE.fullmatch(value):
        raise ValidationError("invalid txn_id", field="txn_id")
    return value


def new_txn_id() -> str:
    return f"TXN-{now_ts():010d}-{uuid.uuid4().hex[:12].upper()}"


def validate_currency(value: Any) -> str:
    if not isinstance(value, str) or not _CURRENCY_RE.fullmatch(value):
        raise ValidationError("invalid currency code", field="currency")
    return value


def validate_amount_minor(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("amount must be an integer of minor units", field="amount")
    if not 0 < value <= config.MAX_AMOUNT_MINOR:
        raise ValidationError(
            f"amount out of range (1..{config.MAX_AMOUNT_MINOR} minor units)",
            field="amount",
        )
    return value


def validate_timestamp(value: Any, *, field: str = "ts") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer timestamp", field=field)
    if not 0 < value < 4_102_444_800:
        raise ValidationError(f"{field} outside plausible range", field=field)
    return value


def validate_fresh_timestamp(value: Any, *, field: str = "ts") -> int:
    ts = validate_timestamp(value, field=field)
    if not fresh_timestamp(ts):
        raise ValidationError(f"{field} outside freshness window", field=field)
    return ts


def validate_b64(value: Any, *, field: str, max_bytes: int) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= ((max_bytes + 2) // 3) * 4 + 4:
        raise ValidationError(f"invalid {field} length", field=field)
    try:
        raw = b64_decode(value)
    except ValidationError as exc:
        raise ValidationError(f"invalid {field}: not base64", field=field) from exc
    if len(raw) > max_bytes:
        raise ValidationError(f"{field} too large", field=field)
    return value


def validate_str(
    value: Any,
    *,
    field: str,
    min_len: int = 1,
    max_len: int = 128,
    pattern: str | None = None,
) -> str:
    if not isinstance(value, str) or not min_len <= len(value) <= max_len:
        raise ValidationError(
            f"invalid {field}: length {len(value) if isinstance(value, str) else 'n/a'}"
            f" (want {min_len}..{max_len})",
            field=field,
        )
    if pattern is not None and not re.fullmatch(pattern, value):
        raise ValidationError(f"invalid {field}: bad characters", field=field)
    return value
