from __future__ import annotations

from typing import TypedDict

from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.encoding import (
    b64_decode,
    b64_encode,
    canonical_bytes,
    domain_tag,
    validate_amount_minor,
    validate_currency,
    validate_fresh_timestamp,
    validate_id,
    validate_str,
    validate_timestamp,
    validate_txn_id,
)
from securepay.errors import ValidationError
from securepay.pki import sign_bytes, verify_bytes

__all__ = [
    "MSG_AUTHORISATION_REQUEST",
    "MSG_AUTH_REJECTED",
    "MSG_BALANCE_QUERY",
    "MSG_BALANCE_REPORT",
    "MSG_ERROR",
    "MSG_GET_PENDING",
    "MSG_PAYMENT_AUTHORISATION",
    "MSG_PAYMENT_DECLINE",
    "MSG_PAYMENT_REQUEST",
    "MSG_PAYMENT_REQUEST_ACK",
    "MSG_PAYMENT_RESULT",
    "MSG_PENDING_LIST",
    "MSG_RECEIPT",
    "RECEIPT_STATUS_SETTLED",
    "PaymentAuthorisation",
    "PaymentDecline",
    "PaymentRequest",
    "Receipt",
    "payment_authorisation_sig_payload",
    "payment_decline_sig_payload",
    "payment_request_sig_payload",
    "receipt_sig_payload",
    "sign_payment_authorisation",
    "sign_payment_decline",
    "sign_payment_request",
    "sign_receipt",
    "validate_message",
    "verify_payment_authorisation_sig",
    "verify_payment_decline_sig",
    "verify_payment_request_sig",
    "verify_receipt_sig",
]

MSG_PAYMENT_REQUEST = "payment_request"
MSG_PAYMENT_REQUEST_ACK = "payment_request_ack"
MSG_AUTHORISATION_REQUEST = "authorisation_request"
MSG_PAYMENT_AUTHORISATION = "payment_authorisation"
MSG_PAYMENT_DECLINE = "payment_decline"
MSG_PAYMENT_RESULT = "payment_result"
MSG_RECEIPT = "receipt"
MSG_AUTH_REJECTED = "auth_rejected"
MSG_BALANCE_QUERY = "balance_query"
MSG_BALANCE_REPORT = "balance_report"
MSG_GET_PENDING = "get_pending"
MSG_PENDING_LIST = "pending_list"
MSG_ERROR = "error"

RECEIPT_STATUS_SETTLED = "SETTLED"

_SIG_BYTES = 64
_TAG_REQUEST = domain_tag("SP1", "PAYMENT-REQUEST", "v1")
_TAG_AUTHORISATION = domain_tag("SP1", "PAYMENT-AUTH", "v1")
_TAG_DECLINE = domain_tag("SP1", "PAYMENT-DECLINE", "v1")
_TAG_RECEIPT = domain_tag("SP1", "RECEIPT", "v1")


class PaymentRequest(TypedDict):

    type: str
    v: int
    txn_id: str
    merchant_id: str
    payer_id: str
    amount_minor: int
    currency: str
    ts: int
    merchant_sig: str


class PaymentAuthorisation(TypedDict):

    type: str
    v: int
    txn_id: str
    payer_id: str
    merchant_id: str
    amount_minor: int
    currency: str
    ts: int
    client_nonce: int
    payer_sig: str


class PaymentDecline(TypedDict):

    type: str
    v: int
    txn_id: str
    payer_id: str
    merchant_id: str
    amount_minor: int
    currency: str
    ts: int
    payer_sig: str


class Receipt(TypedDict):

    type: str
    v: int
    txn_id: str
    payer_id: str
    merchant_id: str
    amount_minor: int
    currency: str
    ts: int
    session_id: str
    status: str
    ledger_seq: int
    pan_masked: str
    card_token: str
    switch_sig: str


def payment_request_sig_payload(
    *,
    txn_id: str,
    merchant_id: str,
    payer_id: str,
    amount_minor: int,
    currency: str,
    ts: int,
    channel_binding: str,
) -> bytes:
    return _TAG_REQUEST + canonical_bytes(
        {
            "v": config.PROTOCOL_VERSION,
            "txn_id": txn_id,
            "merchant_id": merchant_id,
            "payer_id": payer_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ts": ts,
            "channel_binding": channel_binding,
        }
    )


def payment_authorisation_sig_payload(
    *,
    txn_id: str,
    payer_id: str,
    merchant_id: str,
    amount_minor: int,
    currency: str,
    ts: int,
    client_nonce: int,
    channel_binding: str,
) -> bytes:
    return _TAG_AUTHORISATION + canonical_bytes(
        {
            "v": config.PROTOCOL_VERSION,
            "txn_id": txn_id,
            "payer_id": payer_id,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ts": ts,
            "client_nonce": client_nonce,
            "channel_binding": channel_binding,
        }
    )


def payment_decline_sig_payload(
    *,
    txn_id: str,
    payer_id: str,
    merchant_id: str,
    amount_minor: int,
    currency: str,
    ts: int,
    channel_binding: str,
) -> bytes:
    return _TAG_DECLINE + canonical_bytes(
        {
            "v": config.PROTOCOL_VERSION,
            "txn_id": txn_id,
            "payer_id": payer_id,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ts": ts,
            "channel_binding": channel_binding,
        }
    )


def receipt_sig_payload(receipt: Receipt) -> bytes:
    body = {k: v for k, v in receipt.items() if k != "switch_sig"}
    return _TAG_RECEIPT + canonical_bytes(body)


def sign_payment_request(key: SigningKey, payload: bytes) -> str:
    return b64_encode(sign_bytes(key, payload))


def sign_payment_authorisation(key: SigningKey, payload: bytes) -> str:
    return b64_encode(sign_bytes(key, payload))


def sign_payment_decline(key: SigningKey, payload: bytes) -> str:
    return b64_encode(sign_bytes(key, payload))


def sign_receipt(key: SigningKey, payload: bytes) -> str:
    return b64_encode(sign_bytes(key, payload))


def _decode_sig(signature_b64: str) -> bytes:
    raw = b64_decode(signature_b64)
    if len(raw) != _SIG_BYTES:
        raise ValidationError("signature must be 64 bytes", field="signature")
    return raw


def verify_payment_request_sig(public_key: VerifyKey, payload: bytes, signature_b64: str) -> None:
    verify_bytes(public_key, payload, _decode_sig(signature_b64))


def verify_payment_authorisation_sig(
    public_key: VerifyKey, payload: bytes, signature_b64: str
) -> None:
    verify_bytes(public_key, payload, _decode_sig(signature_b64))


def verify_payment_decline_sig(public_key: VerifyKey, payload: bytes, signature_b64: str) -> None:
    verify_bytes(public_key, payload, _decode_sig(signature_b64))


def verify_receipt_sig(public_key: VerifyKey, payload: bytes, signature_b64: str) -> None:
    verify_bytes(public_key, payload, _decode_sig(signature_b64))


def _base(message: dict[str, object], expected_type: str) -> None:
    if message.get("type") != expected_type:
        raise ValidationError(f"expected message type {expected_type}", field="type")
    if message.get("v") != config.PROTOCOL_VERSION:
        raise ValidationError("unsupported message version", field="v")


def _validate_signed_payment_fields(message: dict[str, object]) -> None:
    validate_txn_id(message.get("txn_id"))
    validate_id(message.get("merchant_id"), field="merchant_id")
    validate_id(message.get("payer_id"), field="payer_id")
    validate_amount_minor(message.get("amount_minor"))
    validate_currency(message.get("currency"))
    validate_timestamp(message.get("ts"))
    sig = validate_str(message.get("merchant_sig"), field="merchant_sig", max_len=120)
    _decode_sig(sig)


def validate_payment_request(message: dict[str, object]) -> PaymentRequest:
    _base(message, MSG_PAYMENT_REQUEST)
    validate_fresh_timestamp(message.get("ts"), field="ts")
    _validate_signed_payment_fields(message)
    return message


def validate_payment_authorisation(message: dict[str, object]) -> PaymentAuthorisation:
    _base(message, MSG_PAYMENT_AUTHORISATION)
    validate_fresh_timestamp(message.get("ts"), field="ts")
    validate_txn_id(message.get("txn_id"))
    validate_id(message.get("merchant_id"), field="merchant_id")
    validate_id(message.get("payer_id"), field="payer_id")
    validate_amount_minor(message.get("amount_minor"))
    validate_currency(message.get("currency"))
    nonce = message.get("client_nonce")
    if isinstance(nonce, bool) or not isinstance(nonce, int) or not 0 < nonce < (1 << 63):
        raise ValidationError("client_nonce must be a positive int64", field="client_nonce")
    sig = validate_str(message.get("payer_sig"), field="payer_sig", max_len=120)
    _decode_sig(sig)
    return message


def validate_payment_decline(message: dict[str, object]) -> PaymentDecline:
    _base(message, MSG_PAYMENT_DECLINE)
    validate_fresh_timestamp(message.get("ts"), field="ts")
    validate_txn_id(message.get("txn_id"))
    validate_id(message.get("merchant_id"), field="merchant_id")
    validate_id(message.get("payer_id"), field="payer_id")
    validate_amount_minor(message.get("amount_minor"))
    validate_currency(message.get("currency"))
    sig = validate_str(message.get("payer_sig"), field="payer_sig", max_len=120)
    _decode_sig(sig)
    return message


def validate_receipt(receipt: dict[str, object]) -> Receipt:
    if receipt.get("v") != config.PROTOCOL_VERSION:
        raise ValidationError("unsupported receipt version", field="v")
    validate_txn_id(receipt.get("txn_id"))
    validate_id(receipt.get("payer_id"), field="payer_id")
    validate_id(receipt.get("merchant_id"), field="merchant_id")
    validate_amount_minor(receipt.get("amount_minor"))
    validate_currency(receipt.get("currency"))
    validate_timestamp(receipt.get("ts"), field="ts")
    if receipt.get("status") != RECEIPT_STATUS_SETTLED:
        raise ValidationError("receipt status must be SETTLED", field="status")
    seq = receipt.get("ledger_seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise ValidationError("ledger_seq must be a positive integer", field="ledger_seq")
    validate_str(
        receipt.get("session_id"), field="session_id", min_len=16, max_len=64, pattern="[0-9a-f]+"
    )
    validate_str(receipt.get("pan_masked"), field="pan_masked", pattern=r"\*{4}-\*{4}-\*{4}-\d{4}")
    validate_str(
        receipt.get("card_token"), field="card_token", min_len=16, max_len=64, pattern="[0-9a-f]+"
    )
    validate_str(receipt.get("switch_sig"), field="switch_sig", max_len=120)
    return receipt


def validate_authorisation_request(message: dict[str, object]) -> None:
    _base(message, MSG_AUTHORISATION_REQUEST)
    validate_txn_id(message.get("txn_id"))
    validate_id(message.get("merchant_id"), field="merchant_id")
    validate_id(message.get("payer_id"), field="payer_id")
    validate_amount_minor(message.get("amount_minor"))
    validate_currency(message.get("currency"))
    validate_timestamp(message.get("ts"), field="ts")
    validate_str(message.get("merchant_name"), field="merchant_name")
    validate_str(
        message.get("merchant_session"),
        field="merchant_session",
        min_len=16,
        max_len=64,
        pattern="[0-9a-f]+",
    )
    pem = validate_str(
        message.get("merchant_cert_pem"),
        field="merchant_cert_pem",
        min_len=100,
        max_len=2000,
        pattern=r"[A-Za-z0-9+/=\s.-]+",
    )
    if "BEGIN CERTIFICATE" not in pem:
        raise ValidationError(
            "merchant_cert_pem is not a PEM certificate", field="merchant_cert_pem"
        )
    sig = validate_str(message.get("merchant_sig"), field="merchant_sig", max_len=120)
    _decode_sig(sig)


def validate_message(message: dict[str, object]) -> str:
    msg_type = message.get("type")
    if not isinstance(msg_type, str):
        raise ValidationError("message has no type", field="type")
    if msg_type == MSG_PAYMENT_REQUEST:
        validate_payment_request(message)
    elif msg_type == MSG_PAYMENT_AUTHORISATION:
        validate_payment_authorisation(message)
    elif msg_type == MSG_PAYMENT_DECLINE:
        validate_payment_decline(message)
    elif msg_type == MSG_AUTHORISATION_REQUEST:
        validate_authorisation_request(message)
    elif msg_type == MSG_RECEIPT:
        _base(message, MSG_RECEIPT)
        receipt = message.get("receipt")
        if not isinstance(receipt, dict):
            raise ValidationError("receipt must be an object", field="receipt")
        validate_receipt(receipt)
    elif msg_type in (MSG_PAYMENT_REQUEST_ACK, MSG_PAYMENT_RESULT, MSG_AUTH_REJECTED):
        _base(message, msg_type)
        validate_txn_id(message.get("txn_id"))
        if msg_type == MSG_PAYMENT_RESULT:
            if message.get("status") not in ("SETTLED", "REJECTED"):
                raise ValidationError("invalid payment result status", field="status")
            receipt = message.get("receipt")
            if receipt is not None:
                if not isinstance(receipt, dict):
                    raise ValidationError("receipt must be an object", field="receipt")
                validate_receipt(receipt)
    elif msg_type == MSG_BALANCE_QUERY:
        _base(message, MSG_BALANCE_QUERY)
    elif msg_type == MSG_BALANCE_REPORT:
        _base(message, MSG_BALANCE_REPORT)
        validate_id(message.get("account_id"), field="account_id")
        balance = message.get("balance_minor")
        if isinstance(balance, bool) or not isinstance(balance, int) or balance < 0:
            raise ValidationError(
                "balance_minor must be a non-negative integer", field="balance_minor"
            )
        validate_currency(message.get("currency"))
    elif msg_type == MSG_GET_PENDING:
        _base(message, MSG_GET_PENDING)
    elif msg_type == MSG_PENDING_LIST:
        _base(message, MSG_PENDING_LIST)
        requests = message.get("requests")
        if not isinstance(requests, list):
            raise ValidationError("requests must be a list", field="requests")
        for entry in requests:
            if not isinstance(entry, dict):
                raise ValidationError("pending entry must be an object", field="requests")
            validate_authorisation_request(entry)
    elif msg_type == MSG_ERROR:
        _base(message, MSG_ERROR)
        validate_str(message.get("code"), field="code", min_len=3, max_len=48, pattern="[a-z_]+")
        validate_str(message.get("message"), field="message", min_len=1, max_len=200)
    else:
        raise ValidationError(f"unknown message type {msg_type!r}", field="type")
    return msg_type
