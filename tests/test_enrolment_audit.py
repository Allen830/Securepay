from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from securepay.audit import AuditLog
from securepay.bootstrap import (
    _load_switch_signer,
    issue_entity_certificate,
    provision_network,
)
from securepay.errors import BadPassphraseError, DuplicateTxnError, LedgerError
from securepay.ledger import Ledger
from securepay.pki import generate_signing_key


@pytest.fixture
def ledger(tmp_path: Path) -> Ledger:
    return Ledger(tmp_path / "ledger.db", generate_signing_key())


def _events(db_path: Path) -> list[tuple[str, dict]]:
    conn = sqlite3.connect(db_path)
    try:
        return [
            (event, json.loads(payload))
            for event, payload in conn.execute("SELECT event, payload FROM audit_log ORDER BY seq")
        ]
    finally:
        conn.close()


def test_enrol_creates_account_and_signed_audit_entry(ledger: Ledger, tmp_path: Path) -> None:
    seq = ledger.enrol_account("902201", "student", "New Student", 10000, {"serial": "abc"})
    assert seq == 1
    assert ledger.balance("902201") == 10000
    [(event, payload)] = _events(tmp_path / "ledger.db")
    assert event == "entity_enrolled"
    assert payload["entity_id"] == "902201"
    assert payload["role"] == "student"
    assert payload["opening_balance_minor"] == 10000
    assert payload["serial"] == "abc"
    signer = ledger.audit._signer
    assert signer is not None
    result = ledger.verify_audit(signer.verify_key)
    assert result.ok, result.failures


def test_enrol_with_zero_balance_is_audited_without_an_account_row(
    ledger: Ledger, tmp_path: Path
) -> None:
    ledger.enrol_account("902202", "merchant", "Kiosk", 0)
    assert [e for e, _p in _events(tmp_path / "ledger.db")] == ["entity_enrolled"]
    assert ledger.accounts() == []


def test_duplicate_enrolment_rolls_back_the_audit_entry(ledger: Ledger, tmp_path: Path) -> None:
    ledger.enrol_account("902203", "student", "First", 500)
    with pytest.raises(DuplicateTxnError):
        ledger.enrol_account("902203", "student", "Again", 900)
    assert ledger.balance("902203") == 500
    assert len(_events(tmp_path / "ledger.db")) == 1, "the failed enrolment left no audit entry"


def test_enrol_rejects_bad_role_and_negative_balance(ledger: Ledger, tmp_path: Path) -> None:
    with pytest.raises(LedgerError):
        ledger.enrol_account("x1", "switch", "Nope", 100)
    with pytest.raises(LedgerError):
        ledger.enrol_account("x2", "student", "Nope", -1)
    assert _events(tmp_path / "ledger.db") == []


@pytest.fixture(scope="module")
def network(tmp_path_factory: pytest.TempPathFactory):
    return provision_network(
        tmp_path_factory.mktemp("net"),
        students=[{"id": "902101", "name": "Sarah Ahmed", "balance": "450.00"}],
        merchants=[{"id": "coffee_shop", "name": "UOWD Espresso Bar", "balance": "2200.00"}],
    )


def test_issue_cert_enrolment_is_in_the_verified_chain(network) -> None:
    paths = network.paths
    switch_pass = network.passphrases["switch"]
    issue_entity_certificate(
        paths,
        network.ca_passphrase,
        role="student",
        entity_id="902301",
        name="Chain Student",
        opening_balance="100.00",
        switch_passphrase=switch_pass,
    )
    verify_key = _load_switch_signer(paths, switch_pass).verify_key
    verdict = AuditLog.verify_file(paths.ledger, verify_key)
    assert verdict.ok, verdict.failures
    enrolled = AuditLog.read_file(paths.ledger, frozenset({"entity_enrolled"}))
    assert [e.payload["entity_id"] for e in enrolled] == ["902301"]
    payload = enrolled[0].payload
    assert payload["opening_balance_minor"] == 10000
    assert "seed" not in payload and "card" not in payload, "no secrets in the audit log"


def test_wrong_switch_passphrase_enrols_nothing(network) -> None:
    paths = network.paths
    before = paths.registry.read_text(encoding="utf-8")
    with pytest.raises(BadPassphraseError):
        issue_entity_certificate(
            paths,
            network.ca_passphrase,
            role="student",
            entity_id="902302",
            name="Never Enrolled",
            opening_balance="50.00",
            switch_passphrase="not the switch passphrase",
        )
    assert paths.registry.read_text(encoding="utf-8") == before


_TXN = "TXN-0000000001-AAAAAAAAAAAA"


@pytest.fixture
def funded_ledger(ledger: Ledger) -> Ledger:
    ledger.create_account("902101", "student", "Sarah Ahmed", 45000)
    ledger.create_account("coffee_shop", "merchant", "UOWD Espresso Bar", 220000)
    ledger.register_payment_request(
        txn_id=_TXN,
        payer_id="902101",
        merchant_id="coffee_shop",
        amount_minor=1250,
        currency="AED",
        session_id="ab" * 16,
        merchant_sig="b64sig",
    )
    return ledger


def test_student_decline_is_logged_as_warning(
    funded_ledger: Ledger, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="securepay.ledger"):
        funded_ledger.decline_payment(
            txn_id=_TXN,
            payer_id="902101",
            merchant_id="coffee_shop",
            amount_minor=1250,
            currency="AED",
            payer_sig="student-decline-sig",
            decided_ts=1700000000,
        )
    levels = [r.levelname for r in caplog.records if "event=payment_declined" in r.getMessage()]
    assert levels == ["WARNING"]


def test_switch_rejection_is_logged_as_warning(
    funded_ledger: Ledger, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level("INFO", logger="securepay.ledger"):
        funded_ledger.reject_payment(_TXN, "insufficient_funds")
    records = [r for r in caplog.records if "event=payment_rejected" in r.getMessage()]
    assert [r.levelname for r in records] == ["WARNING"]
    assert "reason=insufficient_funds" in records[0].getMessage()
