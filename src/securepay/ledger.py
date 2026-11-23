from __future__ import annotations

import logging
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.audit import AuditLog, AuditVerification
from securepay.encoding import canonical_bytes, now_ts
from securepay.errors import (
    DuplicateTxnError,
    InsufficientFundsError,
    LedgerError,
    PendingRequestError,
    StaleNonceError,
    UnknownAccountError,
)

logger = logging.getLogger(__name__)

__all__ = ["Ledger", "TxnRecord"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id   TEXT PRIMARY KEY,
    role         TEXT NOT NULL CHECK (role IN ('merchant', 'student')),
    name         TEXT NOT NULL,
    balance_minor INTEGER NOT NULL CHECK (balance_minor >= 0)
);
CREATE TABLE IF NOT EXISTS transactions (
    txn_id      TEXT PRIMARY KEY,
    payer_id    TEXT NOT NULL,
    merchant_id TEXT NOT NULL,
    amount_minor INTEGER NOT NULL CHECK (amount_minor > 0),
    currency    TEXT NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('PENDING', 'SETTLED', 'REJECTED', 'EXPIRED')),
    created_ts  INTEGER NOT NULL,
    settled_ts  INTEGER,
    session_id  TEXT NOT NULL,
    client_nonce INTEGER NOT NULL,
    merchant_sig TEXT NOT NULL,
    payer_sig   TEXT NOT NULL,
    receipt     TEXT,
    request_ts  INTEGER
);
CREATE TABLE IF NOT EXISTS payer_nonces (
    payer_id   TEXT PRIMARY KEY,
    last_nonce INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    event      TEXT NOT NULL,
    payload    TEXT NOT NULL,
    hash_prev  TEXT NOT NULL,
    hash_this  TEXT NOT NULL,
    switch_sig TEXT NOT NULL
);
"""

STATUS_PENDING = "PENDING"
STATUS_SETTLED = "SETTLED"
STATUS_REJECTED = "REJECTED"
STATUS_EXPIRED = "EXPIRED"


class TxnRecord:

    def __init__(self, row: sqlite3.Row | tuple) -> None:
        (
            self.txn_id,
            self.payer_id,
            self.merchant_id,
            self.amount_minor,
            self.currency,
            self.status,
            self.created_ts,
            self.settled_ts,
            self.session_id,
            self.client_nonce,
            self.merchant_sig,
            self.payer_sig,
            self.receipt_json,
            self.request_ts,
        ) = tuple(row)

    def as_dict(self) -> dict[str, object]:
        return {
            "txn_id": self.txn_id,
            "payer_id": self.payer_id,
            "merchant_id": self.merchant_id,
            "amount_minor": self.amount_minor,
            "currency": self.currency,
            "status": self.status,
            "created_ts": self.created_ts,
            "settled_ts": self.settled_ts,
            "session_id": self.session_id,
            "client_nonce": self.client_nonce,
        }


_TXN_COLUMNS = (
    "txn_id, payer_id, merchant_id, amount_minor, currency, status,"
    " created_ts, settled_ts, session_id, client_nonce, merchant_sig,"
    " payer_sig, receipt, request_ts"
)


class Ledger:

    def __init__(self, db_path: Path, signer: SigningKey) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._migrate_schema()
        self.audit = AuditLog(self._conn, signer)

    def _migrate_schema(self) -> None:
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(transactions)")}
        if "request_ts" not in columns:
            self._conn.execute("ALTER TABLE transactions ADD COLUMN request_ts INTEGER")


    def _transaction(self) -> _Transaction:
        return _Transaction(self._conn, self._lock)


    def create_account(self, account_id: str, role: str, name: str, balance_minor: int) -> None:
        if role not in ("merchant", "student"):
            raise LedgerError(f"invalid account role {role!r}")
        if balance_minor < 0:
            raise LedgerError("opening balance must be non-negative")
        with self._transaction():
            try:
                self._conn.execute(
                    "INSERT INTO accounts (account_id, role, name, balance_minor)"
                    " VALUES (?, ?, ?, ?)",
                    (account_id, role, name, balance_minor),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateTxnError(f"account {account_id} already exists") from exc

    def enrol_account(
        self,
        account_id: str,
        role: str,
        name: str,
        balance_minor: int,
        details: dict[str, object] | None = None,
    ) -> int:
        if role not in ("merchant", "student"):
            raise LedgerError(f"invalid account role {role!r}")
        if balance_minor < 0:
            raise LedgerError("opening balance must be non-negative")
        with self._transaction():
            if balance_minor > 0:
                try:
                    self._conn.execute(
                        "INSERT INTO accounts (account_id, role, name, balance_minor)"
                        " VALUES (?, ?, ?, ?)",
                        (account_id, role, name, balance_minor),
                    )
                except sqlite3.IntegrityError as exc:
                    raise DuplicateTxnError(f"account {account_id} already exists") from exc
            payload: dict[str, object] = dict(details or {})
            payload.update(
                {
                    "entity_id": account_id,
                    "role": role,
                    "name": name,
                    "opening_balance_minor": balance_minor,
                }
            )
            seq = self.audit.append("entity_enrolled", payload)
            logger.info(
                "event=entity_enrolled entity=%s role=%s opening=%d seq=%d",
                account_id,
                role,
                balance_minor,
                seq,
            )
            return seq

    def balance(self, account_id: str) -> int:
        row = self._conn.execute(
            "SELECT balance_minor FROM accounts WHERE account_id = ?",
            (account_id,),
        ).fetchone()
        if row is None:
            raise UnknownAccountError(f"unknown account {account_id}")
        return int(row[0])

    def account_role(self, account_id: str) -> str:
        row = self._conn.execute(
            "SELECT role FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise UnknownAccountError(f"unknown account {account_id}")
        return str(row[0])

    def accounts(self) -> list[dict[str, object]]:
        rows = self._conn.execute(
            "SELECT account_id, role, name, balance_minor FROM accounts ORDER BY role, account_id"
        ).fetchall()
        return [dict(row) for row in rows]


    def register_payment_request(
        self,
        *,
        txn_id: str,
        payer_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        session_id: str,
        merchant_sig: str,
        request_ts: int | None = None,
    ) -> int:
        if currency != config.CURRENCY:
            raise LedgerError(f"unsupported currency {currency!r}; only {config.CURRENCY}")
        with self._transaction():
            self._require_account(payer_id)
            self._require_account(merchant_id)
            existing = self.get_txn(txn_id)
            if existing is not None:
                raise DuplicateTxnError(f"txn_id {txn_id} already exists")
            self._conn.execute(
                "INSERT INTO transactions (txn_id, payer_id, merchant_id,"
                " amount_minor, currency, status, created_ts, session_id,"
                " client_nonce, merchant_sig, payer_sig, request_ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, '', ?)",
                (
                    txn_id,
                    payer_id,
                    merchant_id,
                    amount_minor,
                    currency,
                    STATUS_PENDING,
                    now_ts(),
                    session_id,
                    merchant_sig,
                    request_ts,
                ),
            )
            return self.audit.append(
                "payment_request_registered",
                {
                    "txn_id": txn_id,
                    "payer_id": payer_id,
                    "merchant_id": merchant_id,
                    "amount_minor": amount_minor,
                    "currency": currency,
                },
            )

    def get_txn(self, txn_id: str) -> TxnRecord | None:
        row = self._conn.execute(
            f"SELECT {_TXN_COLUMNS} FROM transactions WHERE txn_id = ?",
            (txn_id,),
        ).fetchone()
        return None if row is None else TxnRecord(row)

    def pending_requests_for(self, payer_id: str) -> list[TxnRecord]:
        rows = self._conn.execute(
            f"SELECT {_TXN_COLUMNS} FROM transactions"
            " WHERE payer_id = ? AND status = ? ORDER BY created_ts ASC",
            (payer_id, STATUS_PENDING),
        ).fetchall()
        return [TxnRecord(row) for row in rows]


    def settle_payment(
        self,
        *,
        txn_id: str,
        payer_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        client_nonce: int,
        payer_sig: str,
        receipt_factory: Callable[[int], dict[str, object]],
    ) -> tuple[dict[str, object], int]:
        with self._transaction():
            record = self.get_txn(txn_id)
            if record is None:
                raise PendingRequestError(f"no payment request for {txn_id}")
            if record.status == STATUS_SETTLED:
                raise DuplicateTxnError(f"txn {txn_id} is already settled")
            if record.status != STATUS_PENDING:
                raise PendingRequestError(f"txn {txn_id} is {record.status}, not PENDING")
            if (
                record.payer_id != payer_id
                or record.merchant_id != merchant_id
                or record.amount_minor != amount_minor
                or record.currency != currency
            ):
                raise PendingRequestError(f"authorisation does not match the request for {txn_id}")

            nonce_row = self._conn.execute(
                "SELECT last_nonce FROM payer_nonces WHERE payer_id = ?",
                (payer_id,),
            ).fetchone()
            last_nonce = 0 if nonce_row is None else int(nonce_row[0])
            if client_nonce <= last_nonce:
                raise StaleNonceError(f"client_nonce {client_nonce} <= last_nonce {last_nonce}")

            cursor = self._conn.execute(
                "UPDATE accounts SET balance_minor = balance_minor - ?"
                " WHERE account_id = ? AND balance_minor >= ?",
                (amount_minor, payer_id, amount_minor),
            )
            if cursor.rowcount != 1:
                raise InsufficientFundsError(f"payer {payer_id} has insufficient funds")
            cursor = self._conn.execute(
                "UPDATE accounts SET balance_minor = balance_minor + ? WHERE account_id = ?",
                (amount_minor, merchant_id),
            )
            if cursor.rowcount != 1:
                raise LedgerError(f"merchant account {merchant_id} vanished")

            self._conn.execute(
                "INSERT INTO payer_nonces (payer_id, last_nonce) VALUES (?, ?)"
                " ON CONFLICT(payer_id) DO UPDATE SET last_nonce = excluded.last_nonce",
                (payer_id, client_nonce),
            )
            settled_ts = now_ts()
            ledger_seq = self.audit.append(
                "payment_settled",
                {
                    "txn_id": txn_id,
                    "payer_id": payer_id,
                    "merchant_id": merchant_id,
                    "amount_minor": amount_minor,
                    "currency": currency,
                    "client_nonce": client_nonce,
                    "merchant_sig": record.merchant_sig,
                    "payer_sig": payer_sig,
                    "session_id": record.session_id,
                },
            )
            receipt = receipt_factory(ledger_seq)
            self._conn.execute(
                "UPDATE transactions SET status = ?, settled_ts = ?, payer_sig = ?,"
                " receipt = ? WHERE txn_id = ?",
                (
                    STATUS_SETTLED,
                    settled_ts,
                    payer_sig,
                    canonical_bytes(receipt).decode("utf-8"),
                    txn_id,
                ),
            )
            logger.info(
                "event=payment_settled txn=%s payer=%s merchant=%s amount=%d seq=%d",
                txn_id,
                payer_id,
                merchant_id,
                amount_minor,
                ledger_seq,
            )
            return receipt, ledger_seq

    def store_receipt(self, txn_id: str, receipt: dict[str, object]) -> None:
        with self._transaction():
            self._conn.execute(
                "UPDATE transactions SET receipt = ? WHERE txn_id = ? AND status = ?",
                (canonical_bytes(receipt).decode("utf-8"), txn_id, STATUS_SETTLED),
            )

    def credit(self, account_id: str, amount_minor: int) -> tuple[int, int]:
        if amount_minor <= 0:
            raise LedgerError("top-up amount must be positive")
        with self._transaction():
            row = self._conn.execute(
                "SELECT balance_minor FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            if row is None:
                raise UnknownAccountError(f"unknown account {account_id}")
            old_balance = int(row[0])
            cursor = self._conn.execute(
                "UPDATE accounts SET balance_minor = balance_minor + ?"
                " WHERE account_id = ? AND balance_minor >= 0",
                (amount_minor, account_id),
            )
            if cursor.rowcount != 1:
                raise LedgerError(f"account {account_id} vanished during the top-up")
            new_balance = old_balance + amount_minor
            self.audit.append(
                "TOPUP",
                {
                    "account_id": account_id,
                    "amount_minor": amount_minor,
                    "old_balance_minor": old_balance,
                    "new_balance_minor": new_balance,
                },
            )
            logger.info(
                "event=TOPUP account=%s amount=%d old=%d new=%d",
                account_id,
                amount_minor,
                old_balance,
                new_balance,
            )
            return old_balance, new_balance

    def reject_payment(self, txn_id: str, reason_code: str) -> None:
        with self._transaction():
            record = self.get_txn(txn_id)
            if record is None or record.status != STATUS_PENDING:
                return
            self._conn.execute(
                "UPDATE transactions SET status = ? WHERE txn_id = ?",
                (STATUS_REJECTED, txn_id),
            )
            self.audit.append(
                "payment_rejected",
                {"txn_id": txn_id, "reason_code": reason_code},
            )
            logger.warning(
                "event=payment_rejected txn=%s payer=%s merchant=%s reason=%s",
                txn_id,
                record.payer_id,
                record.merchant_id,
                reason_code,
            )

    def decline_payment(
        self,
        *,
        txn_id: str,
        payer_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        payer_sig: str,
        decided_ts: int,
    ) -> int:
        with self._transaction():
            record = self.get_txn(txn_id)
            if record is None:
                raise PendingRequestError(f"no payment request for {txn_id}")
            if record.status != STATUS_PENDING:
                raise PendingRequestError(f"txn {txn_id} is {record.status}, not PENDING")
            if (
                record.payer_id != payer_id
                or record.merchant_id != merchant_id
                or record.amount_minor != amount_minor
                or record.currency != currency
            ):
                raise PendingRequestError(f"decline does not match the request for {txn_id}")
            self._conn.execute(
                "UPDATE transactions SET status = ?, payer_sig = ? WHERE txn_id = ?",
                (STATUS_REJECTED, payer_sig, txn_id),
            )
            seq = self.audit.append(
                "payment_declined",
                {
                    "txn_id": txn_id,
                    "payer_id": payer_id,
                    "merchant_id": merchant_id,
                    "amount_minor": amount_minor,
                    "currency": currency,
                    "reason_code": "declined_by_payer",
                    "decided_ts": decided_ts,
                    "payer_sig": payer_sig,
                    "session_id": record.session_id,
                },
            )
            logger.warning(
                "event=payment_declined txn=%s payer=%s merchant=%s amount=%d seq=%d",
                txn_id,
                payer_id,
                merchant_id,
                amount_minor,
                seq,
            )
            return seq


    def _require_account(self, account_id: str) -> None:
        row = self._conn.execute(
            "SELECT 1 FROM accounts WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise UnknownAccountError(f"unknown account {account_id}")

    def verify_audit(self, verify_key: VerifyKey) -> AuditVerification:
        with self._lock:
            return self.audit.verify(verify_key)

    def audit_event(self, event: str, payload: dict[str, object]) -> int:
        with self._transaction():
            return self.audit.append(event, payload)

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class _Transaction:

    def __init__(self, conn: sqlite3.Connection, lock: threading.RLock) -> None:
        self._conn = conn
        self._lock = lock

    def __enter__(self) -> sqlite3.Connection:
        self._lock.acquire()
        self._conn.execute("BEGIN IMMEDIATE")
        return self._conn

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        try:
            if exc_type is None:
                self._conn.execute("COMMIT")
            else:
                self._conn.execute("ROLLBACK")
        finally:
            self._lock.release()
