from __future__ import annotations

import base64
import time

import pytest

from securepay import config
from securepay.attacks.simulator import Lab
from securepay.errors import SecurePayError


def _settle(lab: Lab, amount: int = 1250) -> tuple[str, dict[str, object]]:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", amount)
        request = wallet.pending_requests()[0]
        receipt = wallet.authorise(request)
        terminal.await_result(txn, wait_seconds=5.0)
    finally:
        terminal.close()
        wallet.close()
    return txn, receipt


def test_full_payment_over_real_sockets(lab: Lab) -> None:
    txn, receipt = _settle(lab, 1250)
    assert receipt["status"] == "SETTLED"
    assert receipt["txn_id"] == txn
    assert receipt["payer_id"] == "902101"
    assert receipt["merchant_id"] == "coffee_shop"
    assert lab.balance("902101") == 45000 - 1250
    assert lab.balance("coffee_shop") == 220000 + 1250
    receipt_file = lab.paths.receipt(txn)
    assert receipt_file.exists()
    from securepay.client import load_receipt_file, verify_receipt_artefact

    ok, detail = verify_receipt_artefact(
        load_receipt_file(receipt_file),
        lab.core.verify_key,
        ledger_path=lab.paths.ledger,
    )
    assert ok, detail


def test_merchant_cannot_charge_for_another_merchant(lab: Lab) -> None:
    terminal = lab.terminal("canteen")
    try:
        request = {
            "type": "payment_request",
            "v": 1,
            "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
            "merchant_id": "coffee_shop",
            "payer_id": "902101",
            "amount_minor": 100,
            "currency": "AED",
            "ts": int(time.time()),
            "merchant_sig": base64.b64encode(b"S" * 64).decode("ascii"),
        }
        terminal.channel.send(request)
        reply = terminal.channel.recv(timeout=5.0)
        assert reply["type"] == "error"
        assert reply["code"] == "protocol_error"
    finally:
        terminal.close()


def test_wallet_cannot_authorise_for_another_payer(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        terminal.request_payment("902102", 500)
        request = wallet.pending_requests()
        assert request == []
    finally:
        terminal.close()
        wallet.close()


def test_insufficient_funds_declined(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902105")
    try:
        txn = terminal.request_payment("902105", 100000)
        request = wallet.pending_requests()[0]
        with pytest.raises(SecurePayError, match="insufficient_funds"):
            wallet.authorise(request)
        result = terminal.await_result(txn, wait_seconds=5.0)
        assert result["status"] == "REJECTED"
        assert result["reason_code"] == "insufficient_funds"
        assert lab.balance("902105") == 19000
        assert lab.balance("coffee_shop") == 220000
    finally:
        terminal.close()
        wallet.close()


def test_pending_request_expires(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", 100)
        with config.temporary(PENDING_TTL_SECONDS=1):
            time.sleep(3.0)
            request = wallet.pending_requests()
            assert request == []
            from securepay.protocol import (
                payment_authorisation_sig_payload,
                sign_payment_authorisation,
            )

            payload = payment_authorisation_sig_payload(
                txn_id=txn,
                payer_id="902101",
                merchant_id="coffee_shop",
                amount_minor=100,
                currency="AED",
                ts=int(time.time()),
                client_nonce=1,
                channel_binding=wallet.session_id,
            )
            wallet.channel.send(
                {
                    "type": "payment_authorisation",
                    "v": 1,
                    "txn_id": txn,
                    "payer_id": "902101",
                    "merchant_id": "coffee_shop",
                    "amount_minor": 100,
                    "currency": "AED",
                    "ts": int(time.time()),
                    "client_nonce": 1,
                    "payer_sig": sign_payment_authorisation(wallet.signing_key, payload),
                }
            )
            reply = wallet.channel.recv(timeout=5.0)
            assert reply["type"] == "error"
            assert reply["code"] == "pending_request_error"
        assert lab.balance("902101") == 45000
    finally:
        terminal.close()
        wallet.close()


def test_two_wallet_sessions_same_student(lab: Lab) -> None:
    wallet_a = lab.wallet("902101")
    wallet_b = lab.wallet("902101")
    try:
        assert wallet_a.session_id != wallet_b.session_id
        assert lab.wallet("902101").balance()["balance_minor"] == 45000
    finally:
        wallet_a.close()
        wallet_b.close()


def test_rate_limit_closes_flooding_session(lab: Lab) -> None:
    wallet = lab.wallet("902101")
    try:
        for _ in range(config.SESSION_MESSAGE_BURST + 10):
            wallet.channel.send({"type": "balance_query", "v": 1})
        with pytest.raises((SecurePayError, OSError)):
            for _ in range(config.SESSION_MESSAGE_BURST + 10):
                wallet.channel.recv(timeout=5.0)
        other = lab.wallet("902102")
        other.close()
    finally:
        wallet.close()


def test_terminal_balance_query(lab: Lab) -> None:
    terminal = lab.terminal("canteen")
    try:
        report = terminal.balance()
        assert report["account_id"] == "canteen"
        assert report["balance_minor"] == 150000
    finally:
        terminal.close()


def test_merchant_receives_result_only_for_its_own_txn(lab: Lab) -> None:
    terminal = lab.terminal("coffee_shop")
    wallet = lab.wallet("902101")
    try:
        txn = terminal.request_payment("902101", 300)
        request = wallet.pending_requests()[0]
        wallet.authorise(request)
        result = terminal.await_result(txn, wait_seconds=5.0)
        assert result["status"] == "SETTLED"
        assert isinstance(result.get("receipt"), dict)
    finally:
        terminal.close()
        wallet.close()
