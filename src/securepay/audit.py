from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

from securepay.encoding import b64_decode, b64_encode, canonical_bytes, now_ts, sha256_hex, u32be
from securepay.errors import PKIError
from securepay.pki import sign_bytes, verify_bytes

__all__ = ["GENESIS_PREV_HASH", "AuditEntry", "AuditLog", "AuditVerification"]

GENESIS_PREV_HASH = "00" * 32

EVENTS = frozenset(
    {
        "payment_settled",
        "payment_rejected",
        "payment_declined",
        "payment_request_registered",
        "session_established",
        "session_closed",
        "error_sent",
        "network_provisioned",
        "TOPUP",
        "entity_enrolled",
    }
)


@dataclass(frozen=True)
class AuditEntry:

    seq: int
    ts: int
    event: str
    payload: dict[str, object]
    hash_prev: str
    hash_this: str
    switch_sig: str


@dataclass
class AuditVerification:

    entries: int = 0
    ok: bool = True
    failures: list[str] = field(default_factory=list)

    def note(self, problem: str) -> None:
        self.ok = False
        self.failures.append(problem)


def entry_digest(seq: int, ts: int, event: str, hash_prev: str, payload: dict[str, object]) -> str:
    material = (
        u32be(seq)
        + u32be(ts)
        + event.encode("ascii")
        + bytes.fromhex(hash_prev)
        + canonical_bytes(payload)
    )
    return sha256_hex(material)


def _sig_payload(entry: AuditEntry) -> bytes:
    return canonical_bytes(
        {
            "event": entry.event,
            "hash_prev": entry.hash_prev,
            "hash_this": entry.hash_this,
            "payload": entry.payload,
            "seq": entry.seq,
            "ts": entry.ts,
        }
    )


class AuditLog:

    def __init__(self, conn: sqlite3.Connection, signer: SigningKey | None) -> None:
        self._conn = conn
        self._signer = signer


    def append(self, event: str, payload: dict[str, object], *, ts: int | None = None) -> int:
        if self._signer is None:
            raise PKIError("audit signing key not configured for writes")
        if event not in EVENTS:
            raise PKIError(f"unknown audit event {event!r}")
        ts = now_ts() if ts is None else ts
        row = self._conn.execute(
            "SELECT seq, hash_this FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            seq, hash_prev = 1, GENESIS_PREV_HASH
        else:
            seq, hash_prev = int(row[0]) + 1, str(row[1])
        hash_this = entry_digest(seq, ts, event, hash_prev, payload)
        entry = AuditEntry(
            seq=seq,
            ts=ts,
            event=event,
            payload=payload,
            hash_prev=hash_prev,
            hash_this=hash_this,
            switch_sig="",
        )
        signature = sign_bytes(self._signer, _sig_payload(entry))
        self._conn.execute(
            "INSERT INTO audit_log (seq, ts, event, payload, hash_prev, hash_this,"
            " switch_sig) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                seq,
                ts,
                event,
                canonical_bytes(payload).decode("utf-8"),
                hash_prev,
                hash_this,
                b64_encode(signature),
            ),
        )
        return seq


    def verify(self, switch_verify_key: VerifyKey) -> AuditVerification:
        result = AuditVerification()
        rows = self._conn.execute(
            "SELECT seq, ts, event, payload, hash_prev, hash_this, switch_sig"
            " FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        expected_prev = GENESIS_PREV_HASH
        for row in rows:
            seq, ts, event, payload_json, hash_prev, hash_this, sig_b64 = row
            result.entries += 1
            if seq != result.entries:
                result.note(f"entry {seq}: sequence gap (expected {result.entries})")
            try:
                payload = json.loads(payload_json)
                if not isinstance(payload, dict):
                    raise json.JSONDecodeError("not an object", payload_json, 0)
            except json.JSONDecodeError:
                result.note(f"entry {seq}: payload is not valid JSON")
                continue
            if hash_prev != expected_prev:
                result.note(f"entry {seq}: hash_prev does not chain to previous entry")
            expected_digest = entry_digest(seq, ts, event, hash_prev, payload)
            if hash_this != expected_digest:
                result.note(f"entry {seq}: hash_this does not match recomputed digest")
            entry = AuditEntry(
                seq=seq,
                ts=ts,
                event=event,
                payload=payload,
                hash_prev=hash_prev,
                hash_this=hash_this,
                switch_sig=sig_b64,
            )
            try:
                verify_bytes(switch_verify_key, _sig_payload(entry), b64_decode(sig_b64))
            except Exception:
                result.note(f"entry {seq}: switch signature verification failed")
            expected_prev = hash_this
        return result

    @staticmethod
    def read_file(db_path: Path, events: frozenset[str] | None = None) -> list[AuditEntry]:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT seq, ts, event, payload, hash_prev, hash_this, switch_sig"
                " FROM audit_log ORDER BY seq ASC"
            ).fetchall()
        finally:
            conn.close()
        entries: list[AuditEntry] = []
        for seq, ts, event, payload_json, hash_prev, hash_this, sig_b64 in rows:
            if events is not None and event not in events:
                continue
            try:
                payload = json.loads(payload_json)
            except json.JSONDecodeError:
                payload = {}
            if not isinstance(payload, dict):
                payload = {}
            entries.append(AuditEntry(seq, ts, event, payload, hash_prev, hash_this, sig_b64))
        return entries

    @staticmethod
    def verify_file(db_path: Path, switch_verify_key: VerifyKey) -> AuditVerification:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return AuditLog(conn, None).verify(switch_verify_key)
        finally:
            conn.close()
