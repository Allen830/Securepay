from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from securepay.audit import GENESIS_PREV_HASH, AuditLog
from securepay.pki import generate_signing_key


@pytest.fixture
def db(tmp_path: Path) -> tuple[sqlite3.Connection, AuditLog, object]:
    conn = sqlite3.connect(tmp_path / "ledger.db", isolation_level=None)
    conn.execute(
        "CREATE TABLE audit_log (seq INTEGER PRIMARY KEY, ts INTEGER NOT NULL,"
        " event TEXT NOT NULL, payload TEXT NOT NULL, hash_prev TEXT NOT NULL,"
        " hash_this TEXT NOT NULL, switch_sig TEXT NOT NULL)"
    )
    signer = generate_signing_key()
    return conn, AuditLog(conn, signer), signer


def test_append_and_verify(db: tuple) -> None:
    conn, audit, _signer = db
    conn.execute("BEGIN")
    audit.append("session_established", {"peer": "902101"})
    audit.append("payment_settled", {"txn_id": "TXN-0000000001-AAAAAAAAAAAA"})
    conn.execute("COMMIT")
    result = audit.verify(_verify_key(db))
    assert result.ok and result.entries == 2


def test_chain_links_each_entry(db: tuple) -> None:
    conn, audit, _signer = db
    conn.execute("BEGIN")
    audit.append("session_established", {"peer": "a"})
    audit.append("session_closed", {"peer": "a"})
    conn.execute("COMMIT")
    rows = conn.execute("SELECT seq, hash_prev, hash_this FROM audit_log ORDER BY seq").fetchall()
    assert rows[0][1] == GENESIS_PREV_HASH
    assert rows[1][1] == rows[0][2]


def test_tampered_payload_detected(db: tuple) -> None:
    conn, audit, _signer = db
    conn.execute("BEGIN")
    audit.append("payment_settled", {"amount_minor": 1250})
    conn.execute("COMMIT")
    row = conn.execute("SELECT payload FROM audit_log WHERE seq = 1").fetchone()
    payload = json.loads(row[0])
    payload["amount_minor"] = 1
    conn.execute(
        "UPDATE audit_log SET payload = ? WHERE seq = 1",
        (json.dumps(payload),),
    )
    result = audit.verify(_verify_key(db))
    assert not result.ok
    assert any("hash_this" in f for f in result.failures)
    assert any("signature" in f for f in result.failures)


def test_deleted_entry_detected(db: tuple) -> None:
    conn, audit, _signer = db
    conn.execute("BEGIN")
    for i in range(3):
        audit.append("session_established", {"peer": f"p{i}"})
    conn.execute("COMMIT")
    conn.execute("DELETE FROM audit_log WHERE seq = 2")
    result = audit.verify(_verify_key(db))
    assert not result.ok
    assert any("sequence gap" in f for f in result.failures)


def test_unknown_event_rejected(db: tuple) -> None:
    _conn, audit, _signer = db
    from securepay.errors import PKIError

    with pytest.raises(PKIError):
        audit.append("totally_made_up_event", {"x": 1})


def test_verify_file_offline(db: tuple, tmp_path: Path) -> None:
    conn, audit, _signer = db
    conn.execute("BEGIN")
    audit.append("network_provisioned", {"students": 12})
    conn.execute("COMMIT")
    conn.close()
    path = tmp_path / "ledger.db"
    result = AuditLog.verify_file(path, _verify_key(db))
    assert result.ok and result.entries == 1


def _verify_key(db: tuple):
    _conn, _audit, signer = db
    return signer.verify_key
