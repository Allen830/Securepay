from __future__ import annotations

import contextlib
import json
import logging
import socket
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.channel import Channel
from securepay.encoding import now_ts
from securepay.errors import BadSignatureError, ProtocolError, SecurePayError, ValidationError
from securepay.framing import FramingError
from securepay.handshake import (
    HandshakeIdentity,
    HandshakeResult,
    TrustAnchor,
    run_client_handshake,
)
from securepay.pki import cert_from_pem, load_crl, read_cert, verify_certificate
from securepay.protocol import (
    MSG_AUTH_REJECTED,
    MSG_AUTHORISATION_REQUEST,
    MSG_BALANCE_QUERY,
    MSG_BALANCE_REPORT,
    MSG_ERROR,
    MSG_GET_PENDING,
    MSG_PAYMENT_DECLINE,
    MSG_PENDING_LIST,
    MSG_RECEIPT,
    payment_authorisation_sig_payload,
    payment_decline_sig_payload,
    receipt_sig_payload,
    sign_payment_authorisation,
    sign_payment_decline,
    validate_authorisation_request,
    validate_receipt,
    verify_payment_request_sig,
    verify_receipt_sig,
)
from securepay.ratelimit import AttemptTracker
from securepay.switch import load_registry

logger = logging.getLogger(__name__)

__all__ = ["WalletClient", "load_receipt_file", "save_receipt", "verify_receipt_artefact"]


class WalletClient:

    def __init__(
        self,
        paths: config.NetworkPaths,
        student_id: str,
        passphrase: str,
        *,
        host: str = config.DEFAULT_HOST,
        port: int = config.DEFAULT_SWITCH_PORT,
    ) -> None:
        from securepay.keystore import unlock_vault

        self.paths = paths
        self.student_id = student_id
        registry = load_registry(paths.registry)
        entry = registry.get(student_id)
        if entry is None or entry.role != config.ROLE_STUDENT:
            raise ProtocolError(f"student {student_id} is not enrolled")
        self.entry = entry

        self._vault_path = paths.wallet_vault(student_id)
        self._vault_aad = {"kind": "student", "id": student_id}
        self._passphrase = passphrase
        tracker = AttemptTracker(paths.lockout(self._vault_path))
        self._vault_payload = unlock_vault(
            self._vault_path, passphrase, expected_aad=self._vault_aad, tracker=tracker
        )
        self.signing_key = SigningKey(bytes.fromhex(self._vault_payload["seed"]))
        self.cert = cert_from_pem(self._vault_payload["cert_pem"])
        self._ca_cert = read_cert(paths.ca_cert)

        self._sock = socket.create_connection((host, port), timeout=config.HANDSHAKE_TIMEOUT)
        anchor = TrustAnchor(
            ca_cert=self._ca_cert,
            crl_provider=lambda: load_crl(paths.crl),
            expected_peer_id=config.SWITCH_ID,
            expected_peer_role=config.ROLE_SWITCH,
        )
        identity = HandshakeIdentity(
            id=student_id,
            role=config.ROLE_STUDENT,
            signing_key=self.signing_key,
            cert=self.cert,
        )
        result: HandshakeResult = run_client_handshake(self._sock, identity, anchor)
        self.channel = Channel(self._sock, "client", result.secrets)
        self.session_id = result.session_id
        logger.info(
            "event=wallet_connected student=%s session=%s",
            student_id,
            self.session_id[:12],
        )


    def pending_requests(self) -> list[dict[str, object]]:
        self.channel.send({"type": MSG_GET_PENDING, "v": config.PROTOCOL_VERSION})
        while True:
            message = self._recv_or_raise()
            if message.get("type") == MSG_PENDING_LIST:
                requests = message.get("requests")
                if not isinstance(requests, list):
                    raise ValidationError("requests must be a list", field="requests")
                return requests
            if message.get("type") == MSG_ERROR:
                raise SecurePayError(f"switch refused: {message.get('code')}")

    def verify_merchant_artefact(self, request: dict[str, object]) -> str:
        validate_authorisation_request(request)
        merchant_cert = cert_from_pem(str(request["merchant_cert_pem"]))
        identity = verify_certificate(merchant_cert, self._ca_cert, load_crl(self.paths.crl))
        if identity.subject_id != str(request["merchant_id"]):
            raise BadSignatureError("merchant certificate does not match the request")
        if identity.role != config.ROLE_MERCHANT:
            raise BadSignatureError("certificate is not a merchant certificate")
        payload = merchant_request_sig_payload(request)
        verify_payment_request_sig(
            VerifyKey(identity.public_key), payload, str(request["merchant_sig"])
        )
        return identity.subject_id


    def authorise(
        self,
        request: dict[str, object],
        *,
        expect_amount_minor: int | None = None,
        expect_merchant: str | None = None,
    ) -> dict[str, object]:
        merchant_id = self.verify_merchant_artefact(request)
        if expect_merchant is not None and merchant_id != expect_merchant:
            raise ValidationError(
                f"request is from {merchant_id}, expected {expect_merchant}",
                field="merchant_id",
            )
        if expect_amount_minor is not None and int(request["amount_minor"]) != expect_amount_minor:
            raise ValidationError(
                f"request amount is {request['amount_minor']}, expected {expect_amount_minor}",
                field="amount_minor",
            )

        client_nonce = int(self._vault_payload["next_nonce"])
        ts = int(request["ts"])
        payload = payment_authorisation_sig_payload(
            txn_id=str(request["txn_id"]),
            payer_id=self.student_id,
            merchant_id=merchant_id,
            amount_minor=int(request["amount_minor"]),
            currency=str(request["currency"]),
            ts=ts,
            client_nonce=client_nonce,
            channel_binding=self.session_id,
        )
        message: dict[str, object] = {
            "type": "payment_authorisation",
            "v": config.PROTOCOL_VERSION,
            "txn_id": request["txn_id"],
            "payer_id": self.student_id,
            "merchant_id": merchant_id,
            "amount_minor": request["amount_minor"],
            "currency": request["currency"],
            "ts": ts,
            "client_nonce": client_nonce,
            "payer_sig": sign_payment_authorisation(self.signing_key, payload),
        }
        self._vault_payload["next_nonce"] = client_nonce + 1
        self._save_vault()
        self.channel.send(message)

        while True:
            reply = self._recv_or_raise()
            reply_type = reply.get("type")
            receipt_obj = reply.get("receipt")
            if (
                reply_type == MSG_RECEIPT
                and isinstance(receipt_obj, dict)
                and receipt_obj.get("txn_id") == request["txn_id"]
            ):
                receipt = dict(receipt_obj)
                validate_receipt(receipt)
                self._verify_switch_receipt(receipt)
                save_receipt(self.paths, receipt)
                return receipt
            if reply_type == MSG_AUTH_REJECTED and reply.get("txn_id") == request["txn_id"]:
                raise SecurePayError(
                    f"switch rejected the authorisation: {reply.get('reason_code')}"
                )
            if reply_type == MSG_ERROR:
                raise SecurePayError(f"switch refused: {reply.get('code')}")

    def decline(self, request: dict[str, object]) -> dict[str, object]:
        validate_authorisation_request(request)
        ts = now_ts()
        payload = payment_decline_sig_payload(
            txn_id=str(request["txn_id"]),
            payer_id=self.student_id,
            merchant_id=str(request["merchant_id"]),
            amount_minor=int(request["amount_minor"]),
            currency=str(request["currency"]),
            ts=ts,
            channel_binding=self.session_id,
        )
        self.channel.send(
            {
                "type": MSG_PAYMENT_DECLINE,
                "v": config.PROTOCOL_VERSION,
                "txn_id": request["txn_id"],
                "payer_id": self.student_id,
                "merchant_id": request["merchant_id"],
                "amount_minor": request["amount_minor"],
                "currency": request["currency"],
                "ts": ts,
                "payer_sig": sign_payment_decline(self.signing_key, payload),
            }
        )
        while True:
            reply = self._recv_or_raise()
            reply_type = reply.get("type")
            if reply_type == MSG_AUTH_REJECTED and reply.get("txn_id") == request["txn_id"]:
                if reply.get("reason_code") != "declined_by_payer":
                    raise SecurePayError(f"switch rejected the decline: {reply.get('reason_code')}")
                return reply
            if reply_type == MSG_ERROR:
                raise SecurePayError(f"switch refused the decline: {reply.get('code')}")

    def _verify_switch_receipt(self, receipt: dict[str, object]) -> None:
        switch_entry = load_registry(self.paths.registry).get(config.SWITCH_ID)
        if switch_entry is None:
            raise ProtocolError("switch is not in the registry")
        verify_receipt_sig(
            VerifyKey(switch_entry.public_key),
            receipt_sig_payload(receipt),
            str(receipt["switch_sig"]),
        )


    def listen(
        self,
        *,
        expect_merchant: str | None = None,
        expect_amount_minor: int | None = None,
        auto_approve: bool = False,
        count: int = 1,
    ) -> list[dict[str, object]]:
        receipts: list[dict[str, object]] = []
        while len(receipts) < count:
            message = self._recv_or_raise()
            if message.get("type") != MSG_AUTHORISATION_REQUEST:
                logger.debug("event=wallet_ignoring type=%s", message.get("type"))
                continue
            if auto_approve:
                receipts.append(
                    self.authorise(
                        message,
                        expect_amount_minor=expect_amount_minor,
                        expect_merchant=expect_merchant,
                    )
                )
            else:
                print_pending_request(message)
                receipts.append(message)
        return receipts


    def balance(self) -> dict[str, object]:
        self.channel.send({"type": MSG_BALANCE_QUERY, "v": config.PROTOCOL_VERSION})
        while True:
            message = self._recv_or_raise()
            if message.get("type") == MSG_BALANCE_REPORT:
                return message
            if message.get("type") == MSG_ERROR:
                raise SecurePayError(f"balance query refused: {message.get('code')}")


    def _recv_or_raise(self, timeout: float | None = None) -> dict[str, object]:
        try:
            return self.channel.recv(timeout=timeout)
        except FramingError as exc:
            raise ProtocolError("connection to the switch was lost") from exc

    def _save_vault(self) -> None:
        from securepay.keystore import save_vault

        save_vault(self._vault_path, self._passphrase, self._vault_payload, self._vault_aad)

    def close(self) -> None:
        self.channel.close()
        with contextlib.suppress(OSError):
            self._sock.close()


def merchant_request_sig_payload(request: dict[str, object]) -> bytes:
    from securepay.protocol import payment_request_sig_payload

    return payment_request_sig_payload(
        txn_id=str(request["txn_id"]),
        merchant_id=str(request["merchant_id"]),
        payer_id=str(request["payer_id"]),
        amount_minor=int(request["amount_minor"]),
        currency=str(request["currency"]),
        ts=int(request["ts"]),
        channel_binding=str(request["merchant_session"]),
    )


def print_pending_request(request: dict[str, object]) -> None:
    from securepay.encoding import format_amount

    print(
        f"  {request['merchant_name']} ({request['merchant_id']}) requests "
        f"{format_amount(int(request['amount_minor']))} {request['currency']} "
        f"for txn {request['txn_id']}"
    )


def verify_receipt_artefact(
    receipt: dict[str, object],
    switch_verify_key: VerifyKey,
    *,
    ledger_path: Path | None = None,
) -> tuple[bool, str]:
    try:
        validate_receipt(receipt)
        verify_receipt_sig(
            switch_verify_key,
            receipt_sig_payload(receipt),
            str(receipt["switch_sig"]),
        )
    except ValidationError as exc:
        return False, f"receipt malformed: {exc.field or exc.message}"
    except BadSignatureError:
        return False, "switch signature on the receipt is invalid"

    if ledger_path is not None:
        import sqlite3

        conn = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT status, amount_minor, payer_id, merchant_id FROM"
                " transactions WHERE txn_id = ?",
                (str(receipt["txn_id"]),),
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return False, "receipt has no matching ledger transaction"
        if row[0] != "SETTLED" or int(row[1]) != int(receipt["amount_minor"]):
            return False, "receipt does not match the ledger transaction"
        if row[2] != receipt["payer_id"] or row[3] != receipt["merchant_id"]:
            return False, "receipt parties do not match the ledger transaction"
    return True, "receipt verified against the switch signature"


def save_receipt(paths: config.NetworkPaths, receipt: dict[str, object]) -> Path:
    from securepay.encoding import canonical_bytes

    paths.receipts_dir.mkdir(parents=True, exist_ok=True)
    path = paths.receipt(str(receipt["txn_id"]))
    path.write_bytes(canonical_bytes(receipt) + b"\n")
    logger.info("event=receipt_saved txn=%s path=%s", receipt["txn_id"], path.name)
    return path


def load_receipt_file(path: Path) -> dict[str, object]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValidationError("receipt file is not a JSON object", field="receipt")
    return data
