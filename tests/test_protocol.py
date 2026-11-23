from __future__ import annotations

import base64

import pytest

from securepay.encoding import now_ts
from securepay.errors import BadSignatureError, ValidationError
from securepay.pki import generate_signing_key
from securepay.protocol import (
    MSG_PAYMENT_AUTHORISATION,
    MSG_PAYMENT_DECLINE,
    MSG_PAYMENT_REQUEST,
    payment_authorisation_sig_payload,
    payment_decline_sig_payload,
    payment_request_sig_payload,
    receipt_sig_payload,
    sign_payment_decline,
    sign_payment_request,
    validate_message,
    validate_receipt,
    verify_payment_decline_sig,
    verify_payment_request_sig,
    verify_receipt_sig,
)


def _good_request() -> dict[str, object]:
    return {
        "type": MSG_PAYMENT_REQUEST,
        "v": 1,
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "merchant_id": "coffee_shop",
        "payer_id": "902101",
        "amount_minor": 1250,
        "currency": "AED",
        "ts": now_ts(),
        "merchant_sig": base64.b64encode(b"S" * 64).decode("ascii"),
    }


def _good_authorisation() -> dict[str, object]:
    return {
        "type": MSG_PAYMENT_AUTHORISATION,
        "v": 1,
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": 1250,
        "currency": "AED",
        "ts": now_ts(),
        "client_nonce": 1,
        "payer_sig": base64.b64encode(b"S" * 64).decode("ascii"),
    }


def _good_receipt() -> dict[str, object]:
    return {
        "type": "receipt",
        "v": 1,
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": 1250,
        "currency": "AED",
        "ts": now_ts(),
        "session_id": "ab" * 16,
        "status": "SETTLED",
        "ledger_seq": 3,
        "pan_masked": "****-****-****-3341",
        "card_token": "cd" * 16,
        "switch_sig": base64.b64encode(b"S" * 64).decode("ascii"),
    }


def test_valid_messages_pass() -> None:
    assert validate_message(_good_request()) == MSG_PAYMENT_REQUEST
    assert validate_message(_good_authorisation()) == MSG_PAYMENT_AUTHORISATION
    assert validate_message({"type": "receipt", "v": 1, "receipt": _good_receipt()}) == "receipt"
    assert validate_message({"type": "balance_query", "v": 1}) == "balance_query"


def test_bad_fields_rejected() -> None:
    bad_requests = [
        {**_good_request(), "amount_minor": 0},
        {**_good_request(), "amount_minor": "1250"},
        {**_good_request(), "currency": "aed"},
        {**_good_request(), "merchant_id": "EVIL MERCHANT"},
        {**_good_request(), "txn_id": "nope"},
        {**_good_request(), "ts": 1},
        {**_good_request(), "merchant_sig": "short"},
        {**_good_request(), "v": 99},
    ]
    for message in bad_requests:
        with pytest.raises(ValidationError):
            validate_message(message)


def test_unknown_type_rejected() -> None:
    with pytest.raises(ValidationError):
        validate_message({"type": "give_me_money", "v": 1})


def test_authorisation_nonce_bounds() -> None:
    for bad in (0, -1, 1 << 63, "5", True):
        with pytest.raises(ValidationError):
            validate_message({**_good_authorisation(), "client_nonce": bad})


def test_receipt_validation() -> None:
    receipt = _good_receipt()
    assert validate_receipt(receipt) is not None
    for field, value in [
        ("status", "PENDING"),
        ("ledger_seq", 0),
        ("amount_minor", -5),
        ("pan_masked", "1234"),
        ("session_id", "xyz"),
        ("switch_sig", ""),
    ]:
        with pytest.raises(ValidationError):
            validate_receipt({**receipt, field: value})


def test_signature_payloads_are_domain_separated() -> None:
    fields = {
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "merchant_id": "coffee_shop",
        "payer_id": "902101",
        "amount_minor": 1250,
        "currency": "AED",
        "ts": 1700000000,
    }
    request_payload = payment_request_sig_payload(channel_binding="ab" * 16, **fields)
    auth_payload = payment_authorisation_sig_payload(
        channel_binding="ab" * 16, client_nonce=1, **fields
    )
    assert request_payload != auth_payload
    assert request_payload.startswith(b"SP1/PAYMENT-REQUEST/v1")
    assert auth_payload.startswith(b"SP1/PAYMENT-AUTH/v1")


def test_channel_binding_changes_payload() -> None:
    a = payment_request_sig_payload(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        merchant_id="coffee_shop",
        payer_id="902101",
        amount_minor=1250,
        currency="AED",
        ts=1700000000,
        channel_binding="aa" * 16,
    )
    b = payment_request_sig_payload(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        merchant_id="coffee_shop",
        payer_id="902101",
        amount_minor=1250,
        currency="AED",
        ts=1700000000,
        channel_binding="bb" * 16,
    )
    assert a != b


def test_sign_and_verify_roundtrip() -> None:
    merchant = generate_signing_key()
    payload = payment_request_sig_payload(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        merchant_id="coffee_shop",
        payer_id="902101",
        amount_minor=1250,
        currency="AED",
        ts=1700000000,
        channel_binding="ab" * 16,
    )
    signature = sign_payment_request(merchant, payload)
    verify_payment_request_sig(merchant.verify_key, payload, signature)
    with pytest.raises(BadSignatureError):
        verify_payment_request_sig(generate_signing_key().verify_key, payload, signature)
    with pytest.raises(BadSignatureError):
        verify_payment_request_sig(merchant.verify_key, payload + b"x", signature)


def test_receipt_sign_verify() -> None:
    switch = generate_signing_key()
    receipt = _good_receipt()
    receipt["switch_sig"] = base64.b64encode(
        switch.sign(receipt_sig_payload(receipt)).signature
    ).decode("ascii")
    verify_receipt_sig(switch.verify_key, receipt_sig_payload(receipt), str(receipt["switch_sig"]))
    tampered = {**receipt, "amount_minor": 1}
    with pytest.raises(BadSignatureError):
        verify_receipt_sig(
            switch.verify_key, receipt_sig_payload(tampered), str(receipt["switch_sig"])
        )


def _decline_fields() -> dict[str, object]:
    return {
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "merchant_id": "coffee_shop",
        "payer_id": "902101",
        "amount_minor": 1250,
        "currency": "AED",
        "ts": 1700000000,
    }


def _decline_payload(binding: str) -> bytes:
    return payment_decline_sig_payload(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        merchant_id="coffee_shop",
        payer_id="902101",
        amount_minor=1250,
        currency="AED",
        ts=1700000000,
        channel_binding=binding,
    )


def test_decline_payload_is_domain_separated_from_authorisation() -> None:
    decline = _decline_payload("ab" * 16)
    auth = payment_authorisation_sig_payload(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        merchant_id="coffee_shop",
        payer_id="902101",
        amount_minor=1250,
        currency="AED",
        ts=1700000000,
        client_nonce=1,
        channel_binding="ab" * 16,
    )
    assert decline.startswith(b"SP1/PAYMENT-DECLINE/v1")
    assert decline != auth


def test_decline_sign_verify_and_binding() -> None:
    student = generate_signing_key()
    payload = _decline_payload("aa" * 16)
    signature = sign_payment_decline(student, payload)
    verify_payment_decline_sig(student.verify_key, payload, signature)
    other_session = _decline_payload("bb" * 16)
    with pytest.raises(BadSignatureError):
        verify_payment_decline_sig(student.verify_key, other_session, signature)
    with pytest.raises(BadSignatureError):
        verify_payment_decline_sig(generate_signing_key().verify_key, payload, signature)


def test_payment_decline_message_validation() -> None:
    good = {
        "type": MSG_PAYMENT_DECLINE,
        "v": 1,
        **_decline_fields(),
        "ts": now_ts(),
        "payer_sig": base64.b64encode(b"S" * 64).decode("ascii"),
    }
    assert validate_message(dict(good)) == MSG_PAYMENT_DECLINE
    for field, value in (
        ("txn_id", "bad"),
        ("amount_minor", 0),
        ("currency", "aed"),
        ("ts", 1),
        ("payer_sig", "short"),
    ):
        with pytest.raises(ValidationError):
            validate_message({**good, field: value})
