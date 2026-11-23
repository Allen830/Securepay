from __future__ import annotations

import base64
import time

import pytest

from securepay import config
from securepay.attacks.simulator import Lab
from securepay.audit import AuditLog
from securepay.errors import SecurePayError


def _decline_message(request: dict[str, object], payer: str, sig: bytes) -> dict[str, object]:
    return {
        "type": "payment_decline",
        "v": config.PROTOCOL_VERSION,
        "txn_id": request["txn_id"],
        "payer_id": payer,
        "merchant_id": request["merchant_id"],
        "amount_minor": request["amount_minor"],
        "currency": request["currency"],
        "ts": int(time.time()),
        "payer_sig": base64.b64encode(sig).decode("ascii"),
    }


def test_decline_is_recorded_and_merchant_is_told_at_once(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", 500)
        request = wallet.pending_requests()[0]
        reply = wallet.decline(request)
        assert reply["type"] == "auth_rejected"
        assert reply["reason_code"] == "declined_by_payer"

        started = time.monotonic()
        result = terminal.await_result(txn, wait_seconds=5.0)
        assert time.monotonic() - started < 3.0
        assert result["status"] == "REJECTED"
        assert result["reason_code"] == "declined_by_payer"
    finally:
        terminal.close()
        wallet.close()

    assert lab.balance("902101") == 45000
    assert lab.balance("coffee_shop") == 220000
    record = lab.core.ledger.get_txn(txn)
    assert record is not None and record.status == "REJECTED"
    assert not lab.paths.receipt(txn).exists()

    entries = AuditLog.read_file(lab.paths.ledger, frozenset({"payment_declined"}))
    assert [e.payload["txn_id"] for e in entries] == [txn]
    assert entries[0].payload["reason_code"] == "declined_by_payer"
    assert entries[0].payload["payer_id"] == "902101"
    assert lab.core.ledger.verify_audit(lab.core.verify_key).ok


def test_declined_request_is_gone_and_cannot_be_authorised_later(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        terminal.request_payment("902101", 500)
        request = wallet.pending_requests()[0]
        wallet.decline(request)
        assert wallet.pending_requests() == []
        with pytest.raises(SecurePayError):
            wallet.authorise(request)
    finally:
        terminal.close()
        wallet.close()
    assert lab.balance("902101") == 45000


def test_settled_payment_cannot_be_declined_afterwards(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", 700)
        request = wallet.pending_requests()[0]
        wallet.authorise(request)
        terminal.await_result(txn, wait_seconds=5.0)
        with pytest.raises(SecurePayError):
            wallet.decline(request)
    finally:
        terminal.close()
        wallet.close()
    record = lab.core.ledger.get_txn(txn)
    assert record is not None and record.status == "SETTLED"
    assert not AuditLog.read_file(lab.paths.ledger, frozenset({"payment_declined"}))


def test_forged_decline_is_refused_and_not_logged(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", 500)
        request = wallet.pending_requests()[0]
        wallet.channel.send(_decline_message(request, "902101", b"F" * 64))
        reply = wallet.channel.recv(timeout=5.0)
        assert reply["type"] == "error"
    finally:
        terminal.close()
        wallet.close()
    record = lab.core.ledger.get_txn(txn)
    assert record is not None and record.status == "PENDING"
    assert not AuditLog.read_file(lab.paths.ledger, frozenset({"payment_declined"}))


def test_wallet_cannot_decline_for_another_student(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    sarah = lab.wallet("902101")
    alex = lab.wallet("902102")
    try:
        txn = terminal.request_payment("902101", 500)
        request = sarah.pending_requests()[0]
        alex.channel.send(_decline_message(request, "902101", b"F" * 64))
        reply = alex.channel.recv(timeout=5.0)
        assert reply["type"] == "error"
        assert reply["code"] == "protocol_error"
    finally:
        terminal.close()
        sarah.close()
        alex.close()
    record = lab.core.ledger.get_txn(txn)
    assert record is not None and record.status == "PENDING"
