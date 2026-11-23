from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from securepay.errors import (
    DuplicateTxnError,
    InsufficientFundsError,
    LedgerError,
    PendingRequestError,
    StaleNonceError,
    UnknownAccountError,
)
from securepay.ledger import STATUS_PENDING, STATUS_SETTLED, Ledger
from securepay.pki import generate_signing_key


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    ledger = Ledger(tmp_path / "ledger.db", generate_signing_key())
    ledger.create_account("902101", "student", "Sarah Ahmed", 45000)
    ledger.create_account("coffee_shop", "merchant", "UOWD Espresso Bar", 220000)
    return ledger


def _request(txn_id: str = "TXN-0000000001-AAAAAAAAAAAA", amount: int = 1250) -> dict:
    return {
        "txn_id": txn_id,
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": amount,
        "currency": "AED",
        "session_id": "ab" * 16,
        "merchant_sig": "b64sig",
    }


def _factory(seq: int) -> dict:
    return {"txn_id": "TXN-0000000001-AAAAAAAAAAAA", "ledger_seq": seq}


def test_register_and_settle(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    receipt, seq = ledger.settle_payment(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        payer_id="902101",
        merchant_id="coffee_shop",
        amount_minor=1250,
        currency="AED",
        client_nonce=1,
        payer_sig="sig1",
        receipt_factory=_factory,
    )
    assert receipt["ledger_seq"] == seq >= 1
    assert ledger.balance("902101") == 45000 - 1250
    assert ledger.balance("coffee_shop") == 220000 + 1250
    record = ledger.get_txn("TXN-0000000001-AAAAAAAAAAAA")
    assert record is not None and record.status == STATUS_SETTLED


def test_duplicate_txn_id_rejected(ledger: Ledger) -> None:
    request = _request()
    ledger.register_payment_request(**request)
    with pytest.raises(DuplicateTxnError):
        ledger.register_payment_request(**request)


def test_settled_txn_cannot_settle_again(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    args = {
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": 1250,
        "currency": "AED",
        "payer_sig": "sig1",
        "receipt_factory": _factory,
    }
    ledger.settle_payment(**args, client_nonce=1)
    with pytest.raises(DuplicateTxnError):
        ledger.settle_payment(**args, client_nonce=2)


def test_nonce_must_be_strictly_monotonic(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    args = {
        "txn_id": "TXN-0000000001-AAAAAAAAAAAA",
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": 1250,
        "currency": "AED",
        "payer_sig": "sig1",
        "receipt_factory": _factory,
    }
    ledger.settle_payment(**args, client_nonce=5)
    ledger.register_payment_request(**_request("TXN-0000000002-BBBBBBBBBBBB"))
    for stale in (1, 4, 5):
        with pytest.raises(StaleNonceError):
            ledger.settle_payment(
                **{**args, "txn_id": "TXN-0000000002-BBBBBBBBBBBB"}, client_nonce=stale
            )
    ledger.settle_payment(**{**args, "txn_id": "TXN-0000000002-BBBBBBBBBBBB"}, client_nonce=6)


def test_insufficient_funds_rolls_back(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request(amount=99999999))
    with pytest.raises(InsufficientFundsError):
        ledger.settle_payment(
            txn_id="TXN-0000000001-AAAAAAAAAAAA",
            payer_id="902101",
            merchant_id="coffee_shop",
            amount_minor=99999999,
            currency="AED",
            client_nonce=1,
            payer_sig="sig",
            receipt_factory=_factory,
        )
    assert ledger.balance("902101") == 45000
    assert ledger.balance("coffee_shop") == 220000
    record = ledger.get_txn("TXN-0000000001-AAAAAAAAAAAA")
    assert record is not None and record.status == STATUS_PENDING


def test_authorisation_mismatch_rejected(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request(amount=1250))
    with pytest.raises(PendingRequestError):
        ledger.settle_payment(
            txn_id="TXN-0000000001-AAAAAAAAAAAA",
            payer_id="902101",
            merchant_id="coffee_shop",
            amount_minor=999,
            currency="AED",
            client_nonce=1,
            payer_sig="sig",
            receipt_factory=_factory,
        )


def test_unknown_account_rejected(ledger: Ledger) -> None:
    with pytest.raises(UnknownAccountError):
        ledger.balance("nobody")
    with pytest.raises(UnknownAccountError):
        ledger.register_payment_request(**{**_request(), "payer_id": "999999"})


def test_negative_balance_blocked_by_schema(ledger: Ledger) -> None:
    with pytest.raises(sqlite3.IntegrityError):
        ledger._conn.execute(
            "UPDATE accounts SET balance_minor = -1 WHERE account_id = ?",
            ("902101",),
        )


def test_reject_payment_marks_rejected(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    ledger.reject_payment("TXN-0000000001-AAAAAAAAAAAA", "insufficient_funds")
    record = ledger.get_txn("TXN-0000000001-AAAAAAAAAAAA")
    assert record is not None and record.status == "REJECTED"
    with pytest.raises(PendingRequestError):
        ledger.settle_payment(
            txn_id="TXN-0000000001-AAAAAAAAAAAA",
            payer_id="902101",
            merchant_id="coffee_shop",
            amount_minor=1250,
            currency="AED",
            client_nonce=1,
            payer_sig="sig",
            receipt_factory=_factory,
        )


def test_persistence_across_reopen(ledger: Ledger, tmp_path: Path) -> None:
    ledger.register_payment_request(**_request())
    ledger.settle_payment(
        txn_id="TXN-0000000001-AAAAAAAAAAAA",
        payer_id="902101",
        merchant_id="coffee_shop",
        amount_minor=1250,
        currency="AED",
        client_nonce=1,
        payer_sig="sig",
        receipt_factory=_factory,
    )
    ledger.close()
    reopened = Ledger(tmp_path / "ledger.db", generate_signing_key())
    try:
        assert reopened.balance("902101") == 45000 - 1250
        record = reopened.get_txn("TXN-0000000001-AAAAAAAAAAAA")
        assert record is not None and record.status == STATUS_SETTLED
        with pytest.raises(DuplicateTxnError):
            reopened.register_payment_request(**_request())
    finally:
        reopened.close()


def test_pending_requests_scoped_to_payer(ledger: Ledger) -> None:
    ledger.create_account("902102", "student", "Alex Chen", 1000)
    ledger.register_payment_request(**_request("TXN-0000000003-CCCCCCCCCCCC"))
    ledger.register_payment_request(
        **{
            **_request("TXN-0000000004-DDDDDDDDDDDD"),
            "payer_id": "902102",
        }
    )
    mine = ledger.pending_requests_for("902101")
    assert [r.txn_id for r in mine] == ["TXN-0000000003-CCCCCCCCCCCC"]


def _audit_rows(db_path: Path) -> list[tuple[int, str, str]]:
    conn = sqlite3.connect(db_path)
    try:
        return [
            (int(seq), event, payload)
            for seq, event, payload in conn.execute(
                "SELECT seq, event, payload FROM audit_log ORDER BY seq"
            )
        ]
    finally:
        conn.close()


def test_credit_updates_balance_and_audits(ledger: Ledger, tmp_path: Path) -> None:
    old, new = ledger.credit("902101", 5000)
    assert (old, new) == (45000, 50000)
    assert ledger.balance("902101") == 50000
    topups = [
        payload for _seq, event, payload in _audit_rows(tmp_path / "ledger.db") if event == "TOPUP"
    ]
    assert len(topups) == 1
    assert '"account_id":"902101"' in topups[0]
    assert '"amount_minor":5000' in topups[0]
    assert '"old_balance_minor":45000' in topups[0]
    assert '"new_balance_minor":50000' in topups[0]


def test_credit_refuses_unknown_account(ledger: Ledger) -> None:
    with pytest.raises(UnknownAccountError):
        ledger.credit("nobody", 100)
    assert ledger.balance("902101") == 45000, "nothing changed"


def test_credit_refuses_non_positive_amount(ledger: Ledger) -> None:
    with pytest.raises(LedgerError):
        ledger.credit("902101", 0)
    with pytest.raises(LedgerError):
        ledger.credit("902101", -100)
    assert ledger.balance("902101") == 45000


def test_credit_chain_still_verifies_with_the_signer_key(ledger: Ledger, tmp_path: Path) -> None:
    signer = ledger.audit._signer
    assert signer is not None
    verify_key = signer.verify_key
    ledger.credit("coffee_shop", 2500)
    ledger.credit("902101", 1250)
    result = ledger.verify_audit(verify_key)
    assert result.ok, result.failures
    assert result.entries >= 2
    events = [event for _seq, event, _payload in _audit_rows(tmp_path / "ledger.db")]
    assert events.count("TOPUP") == 2


_TXN = "TXN-0000000001-AAAAAAAAAAAA"


def _decline_kwargs(**over: object) -> dict:
    base = {
        "txn_id": _TXN,
        "payer_id": "902101",
        "merchant_id": "coffee_shop",
        "amount_minor": 1250,
        "currency": "AED",
        "payer_sig": "student-decline-sig",
        "decided_ts": 1700000000,
    }
    base.update(over)
    return base


def test_decline_payment_is_audited_and_moves_no_money(ledger: Ledger, tmp_path: Path) -> None:
    ledger.register_payment_request(**_request())
    seq = ledger.decline_payment(**_decline_kwargs())
    assert seq >= 1
    record = ledger.get_txn(_TXN)
    assert record is not None and record.status == "REJECTED"
    assert ledger.balance("902101") == 45000
    assert ledger.balance("coffee_shop") == 220000
    declined = [
        payload
        for _seq, event, payload in _audit_rows(tmp_path / "ledger.db")
        if event == "payment_declined"
    ]
    assert len(declined) == 1
    assert '"reason_code":"declined_by_payer"' in declined[0]
    assert '"payer_sig":"student-decline-sig"' in declined[0]
    events = [event for _seq, event, _payload in _audit_rows(tmp_path / "ledger.db")]
    assert "payment_rejected" not in events


def test_decline_chain_still_verifies(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    ledger.decline_payment(**_decline_kwargs())
    signer = ledger.audit._signer
    assert signer is not None
    result = ledger.verify_audit(signer.verify_key)
    assert result.ok, result.failures


def test_decline_twice_or_after_settlement_refused(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request())
    ledger.decline_payment(**_decline_kwargs())
    with pytest.raises(PendingRequestError):
        ledger.decline_payment(**_decline_kwargs())

    ledger.register_payment_request(**_request("TXN-0000000002-BBBBBBBBBBBB"))
    ledger.settle_payment(
        txn_id="TXN-0000000002-BBBBBBBBBBBB",
        payer_id="902101",
        merchant_id="coffee_shop",
        amount_minor=1250,
        currency="AED",
        client_nonce=1,
        payer_sig="sig",
        receipt_factory=_factory,
    )
    with pytest.raises(PendingRequestError):
        ledger.decline_payment(**_decline_kwargs(txn_id="TXN-0000000002-BBBBBBBBBBBB"))
    record = ledger.get_txn("TXN-0000000002-BBBBBBBBBBBB")
    assert record is not None and record.status == STATUS_SETTLED


def test_decline_must_match_the_request(ledger: Ledger, tmp_path: Path) -> None:
    ledger.register_payment_request(**_request())
    with pytest.raises(PendingRequestError):
        ledger.decline_payment(**_decline_kwargs(amount_minor=1))
    with pytest.raises(PendingRequestError):
        ledger.decline_payment(**_decline_kwargs(txn_id="TXN-0000000009-ZZZZZZZZZZZZ"))
    record = ledger.get_txn(_TXN)
    assert record is not None and record.status == STATUS_PENDING
    events = [event for _seq, event, _payload in _audit_rows(tmp_path / "ledger.db")]
    assert "payment_declined" not in events, "a refused decline must leave no audit entry"


def test_non_aed_currency_rejected(ledger: Ledger) -> None:
    request = _request()
    request["currency"] = "USD"
    with pytest.raises(LedgerError):
        ledger.register_payment_request(**request)
    assert ledger.get_txn(request["txn_id"]) is None


def test_request_ts_is_stored_and_returned(ledger: Ledger) -> None:
    ledger.register_payment_request(**_request(), request_ts=1_700_000_123)
    record = ledger.get_txn("TXN-0000000001-AAAAAAAAAAAA")
    assert record is not None
    assert record.request_ts == 1_700_000_123


def test_old_ledger_without_request_ts_is_migrated(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE transactions (
            txn_id TEXT PRIMARY KEY, payer_id TEXT NOT NULL, merchant_id TEXT NOT NULL,
            amount_minor INTEGER NOT NULL CHECK (amount_minor > 0), currency TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('PENDING','SETTLED','REJECTED','EXPIRED')),
            created_ts INTEGER NOT NULL, settled_ts INTEGER, session_id TEXT NOT NULL,
            client_nonce INTEGER NOT NULL, merchant_sig TEXT NOT NULL,
            payer_sig TEXT NOT NULL, receipt TEXT
        );
        """
    )
    conn.commit()
    conn.close()
    ledger = Ledger(db, generate_signing_key())
    ledger.create_account("902101", "student", "Sarah Ahmed", 45000)
    ledger.create_account("coffee_shop", "merchant", "UOWD Espresso Bar", 0)
    ledger.register_payment_request(**_request())
    record = ledger.get_txn("TXN-0000000001-AAAAAAAAAAAA")
    assert record is not None and record.request_ts is None
