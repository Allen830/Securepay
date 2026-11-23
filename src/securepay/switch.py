from __future__ import annotations

import contextlib
import logging
import socket
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.channel import Channel
from securepay.encoding import b64_decode, now_ts
from securepay.errors import (
    DuplicateTxnError,
    PendingRequestError,
    ProtocolError,
    SecurePayError,
    UnknownIdentityError,
    ValidationError,
)
from securepay.framing import FramingError
from securepay.handshake import (
    HandshakeIdentity,
    HandshakeResult,
    TrustAnchor,
    run_server_handshake,
)
from securepay.ledger import Ledger
from securepay.pki import cert_from_pem, load_crl, read_cert
from securepay.protocol import (
    MSG_AUTH_REJECTED,
    MSG_AUTHORISATION_REQUEST,
    MSG_BALANCE_QUERY,
    MSG_BALANCE_REPORT,
    MSG_ERROR,
    MSG_GET_PENDING,
    MSG_PAYMENT_AUTHORISATION,
    MSG_PAYMENT_DECLINE,
    MSG_PAYMENT_REQUEST,
    MSG_PAYMENT_REQUEST_ACK,
    MSG_PAYMENT_RESULT,
    MSG_PENDING_LIST,
    MSG_RECEIPT,
    RECEIPT_STATUS_SETTLED,
    payment_authorisation_sig_payload,
    payment_decline_sig_payload,
    payment_request_sig_payload,
    receipt_sig_payload,
    sign_receipt,
    validate_message,
    verify_payment_authorisation_sig,
    verify_payment_decline_sig,
    verify_payment_request_sig,
)
from securepay.ratelimit import TokenBucket

logger = logging.getLogger(__name__)

__all__ = ["RegistryEntry", "SwitchCore", "SwitchServer", "SwitchSession"]


@dataclass(frozen=True)
class RegistryEntry:

    id: str
    role: str
    name: str
    cert_pem: str
    public_key: bytes
    serial: int
    card_token: str = ""
    pan_masked: str = ""
    revoked: bool = False


def load_registry(path: Path) -> dict[str, RegistryEntry]:
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    entries: dict[str, RegistryEntry] = {}
    for entity in data["entities"]:
        entries[entity["id"]] = RegistryEntry(
            id=entity["id"],
            role=entity["role"],
            name=entity["name"],
            cert_pem=entity["cert_pem"],
            public_key=b64_decode(entity["public_key"]),
            serial=int(entity["serial"]),
            card_token=entity.get("card_token", ""),
            pan_masked=entity.get("pan_masked", ""),
            revoked=bool(entity.get("revoked", False)),
        )
    return entries


class SwitchCore:

    def __init__(self, paths: config.NetworkPaths, passphrase: str) -> None:
        from securepay.keystore import load_vault

        self.paths = paths
        self.ca_cert = read_cert(paths.ca_cert)
        vault = load_vault(
            paths.switch_vault,
            passphrase,
            expected_aad={"kind": "switch", "id": config.SWITCH_ID},
        )
        self.signing_key = SigningKey(bytes.fromhex(vault["seed"]))
        self.cert = cert_from_pem(vault["cert_pem"])
        self.verify_key = self.signing_key.verify_key
        self.registry = load_registry(paths.registry)
        self.ledger = Ledger(paths.ledger, self.signing_key)
        self._sessions: dict[str, SwitchSession] = {}
        self._sessions_lock = threading.Lock()


    def crl_provider(self) -> x509.CertificateRevocationList | None:
        return load_crl(self.paths.crl)

    def enrollment_check(self, subject_id: str, role: str, public_key: bytes) -> None:
        entry = self.registry.get(subject_id)
        if entry is None:
            raise UnknownIdentityError(f"identity {subject_id} is not enrolled")
        if entry.role != role:
            raise UnknownIdentityError(f"identity {subject_id} has role {entry.role}")
        if entry.public_key != public_key:
            raise UnknownIdentityError(f"identity {subject_id} key does not match the registry")
        if entry.revoked:
            raise UnknownIdentityError(f"identity {subject_id} has been revoked")

    def trust_anchor(self) -> TrustAnchor:
        return TrustAnchor(
            ca_cert=self.ca_cert,
            crl_provider=self.crl_provider,
            expected_peer_id=None,
            expected_peer_role=None,
            peer_enrollment_check=self.enrollment_check,
        )


    def register_session(self, session: SwitchSession) -> None:
        with self._sessions_lock:
            self.ledger.audit_event(
                "session_established",
                {
                    "peer": session.peer_id,
                    "role": session.peer_role,
                    "session_id": session.session_id,
                },
            )
            self._sessions[session.peer_id] = session

    def unregister_session(self, session: SwitchSession) -> None:
        with self._sessions_lock:
            if self._sessions.get(session.peer_id) is session:
                del self._sessions[session.peer_id]

    def online_session(self, entity_id: str) -> SwitchSession | None:
        with self._sessions_lock:
            return self._sessions.get(entity_id)

    def receipt_for(
        self,
        *,
        ledger_seq: int,
        txn_id: str,
        payer_id: str,
        merchant_id: str,
        amount_minor: int,
        currency: str,
        session_id: str,
    ) -> dict[str, object]:
        payer = self.registry.get(payer_id)
        receipt: dict[str, object] = {
            "type": "receipt",
            "v": config.PROTOCOL_VERSION,
            "txn_id": txn_id,
            "payer_id": payer_id,
            "merchant_id": merchant_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ts": now_ts(),
            "session_id": session_id,
            "status": RECEIPT_STATUS_SETTLED,
            "ledger_seq": ledger_seq,
            "pan_masked": payer.pan_masked if payer else "",
            "card_token": payer.card_token if payer else "",
        }
        receipt["switch_sig"] = sign_receipt(
            self.signing_key,
            receipt_sig_payload(receipt),
        )
        return receipt


class SwitchSession:

    def __init__(self, core: SwitchCore, sock: socket.socket, addr: tuple) -> None:
        self._core = core
        self._sock = sock
        self._addr = addr
        self.channel: Channel | None = None
        self.peer_id = ""
        self.peer_role = ""
        self.session_id = ""
        self._bucket = TokenBucket(config.SESSION_MESSAGE_RATE, config.SESSION_MESSAGE_BURST)


    def run(self) -> None:
        try:
            identity = HandshakeIdentity(
                id=config.SWITCH_ID,
                role=config.ROLE_SWITCH,
                signing_key=self._core.signing_key,
                cert=self._core.cert,
            )
            result: HandshakeResult = run_server_handshake(
                self._sock, identity, self._core.trust_anchor()
            )
            self.channel = Channel(self._sock, "server", result.secrets)
            self.peer_id = result.peer_id
            self.peer_role = result.peer_role
            self.session_id = result.session_id
            self._core.register_session(self)
            logger.info(
                "event=session_open peer=%s role=%s addr=%s",
                self.peer_id,
                self.peer_role,
                self._addr[0],
            )
            self._message_loop()
        except SecurePayError as exc:
            logger.warning(
                "event=session_failed peer=%s addr=%s code=%s",
                self.peer_id or "?",
                self._addr[0],
                exc.code,
            )
        except OSError as exc:
            logger.warning("event=session_io_error addr=%s err=%s", self._addr[0], exc)
        finally:
            self._teardown()

    def _teardown(self) -> None:
        if self.peer_id:
            self._core.unregister_session(self)
            try:
                self._core.ledger.audit_event(
                    "session_closed",
                    {"peer": self.peer_id, "session_id": self.session_id},
                )
            except SecurePayError:
                logger.warning("event=audit_write_failed peer=%s", self.peer_id)
        if self.channel is not None:
            self.channel.close()
        with contextlib.suppress(OSError):
            self._sock.close()
        logger.info("event=session_closed peer=%s", self.peer_id or "?")


    def _message_loop(self) -> None:
        channel = self._require_channel()
        while True:
            try:
                message = channel.recv()
            except FramingError:
                return
            if not self._bucket.allow():
                self._send_error("rate_limited", "too many messages; slow down")
                logger.warning("event=rate_limited peer=%s", self.peer_id)
                return
            try:
                self._dispatch(message)
            except ValidationError as exc:
                self._send_error("validation_failed", f"invalid field: {exc.field}")
            except SecurePayError as exc:
                self._send_error(exc.code, "request refused")
                logger.warning(
                    "event=request_failed peer=%s code=%s detail=%s",
                    self.peer_id,
                    exc.code,
                    exc.detail or exc.message,
                )

    def _dispatch(self, message: dict[str, object]) -> None:
        msg_type = validate_message(message)
        if msg_type == MSG_PAYMENT_REQUEST:
            self._require_role(config.ROLE_MERCHANT)
            self._handle_payment_request(message)
        elif msg_type == MSG_PAYMENT_AUTHORISATION:
            self._require_role(config.ROLE_STUDENT)
            self._handle_authorisation(message)
        elif msg_type == MSG_PAYMENT_DECLINE:
            self._require_role(config.ROLE_STUDENT)
            self._handle_decline(message)
        elif msg_type == MSG_BALANCE_QUERY:
            self._handle_balance()
        elif msg_type == MSG_GET_PENDING:
            self._require_role(config.ROLE_STUDENT)
            self._handle_get_pending()
        else:
            raise ProtocolError("message type is not valid from a client")

    def _require_role(self, role: str) -> None:
        if self.peer_role != role:
            raise ProtocolError("message not allowed for this session role")

    def _require_channel(self) -> Channel:
        if self.channel is None:
            raise ProtocolError("session channel is not established")
        return self.channel


    def _handle_payment_request(self, message: dict[str, object]) -> None:
        channel = self._require_channel()
        merchant_id = str(message["merchant_id"])
        if merchant_id != self.peer_id:
            raise ProtocolError("a merchant may only charge under its own identity")

        if message["currency"] != config.CURRENCY:
            raise ValidationError("unsupported currency", field="currency")

        merchant = self._core.registry.get(merchant_id)
        payer = self._core.registry.get(str(message["payer_id"]))
        if merchant is None or payer is None or payer.role != config.ROLE_STUDENT:
            raise ValidationError("unknown payer", field="payer_id")

        payload = payment_request_sig_payload(
            txn_id=str(message["txn_id"]),
            merchant_id=merchant_id,
            payer_id=str(message["payer_id"]),
            amount_minor=int(message["amount_minor"]),
            currency=str(message["currency"]),
            ts=int(message["ts"]),
            channel_binding=self.session_id,
        )
        verify_payment_request_sig(
            VerifyKey(merchant.public_key), payload, str(message["merchant_sig"])
        )

        self._core.ledger.register_payment_request(
            txn_id=str(message["txn_id"]),
            payer_id=str(message["payer_id"]),
            merchant_id=merchant_id,
            amount_minor=int(message["amount_minor"]),
            currency=str(message["currency"]),
            session_id=self.session_id,
            merchant_sig=str(message["merchant_sig"]),
            request_ts=int(message["ts"]),
        )
        channel.send(
            {
                "type": MSG_PAYMENT_REQUEST_ACK,
                "v": config.PROTOCOL_VERSION,
                "txn_id": message["txn_id"],
                "status": "pending_authorisation",
                "expires_at": now_ts() + config.PENDING_TTL_SECONDS,
            }
        )
        wallet = self._core.online_session(str(message["payer_id"]))
        if wallet is not None:
            wallet.push(self._authorisation_request(message, merchant))

    def _authorisation_request(
        self, request: dict[str, object], merchant: RegistryEntry
    ) -> dict[str, object]:
        return {
            "type": MSG_AUTHORISATION_REQUEST,
            "v": config.PROTOCOL_VERSION,
            "txn_id": request["txn_id"],
            "merchant_id": merchant.id,
            "merchant_name": merchant.name,
            "merchant_cert_pem": merchant.cert_pem,
            "merchant_session": self.session_id,
            "payer_id": request["payer_id"],
            "amount_minor": request["amount_minor"],
            "currency": request["currency"],
            "ts": request["ts"],
            "merchant_sig": request["merchant_sig"],
        }

    def _handle_authorisation(self, message: dict[str, object]) -> None:
        channel = self._require_channel()
        payer_id = str(message["payer_id"])
        if payer_id != self.peer_id:
            raise ProtocolError("a wallet may only authorise its own payments")
        txn_id = str(message["txn_id"])

        record = self._core.ledger.get_txn(txn_id)
        if record is None:
            raise PendingRequestError(f"no payment request for {txn_id}")
        if record.status == "SETTLED":
            raise DuplicateTxnError(f"txn {txn_id} is already settled")
        if record.status != "PENDING":
            raise PendingRequestError(f"txn {txn_id} is {record.status}, not PENDING")
        if now_ts() - record.created_ts > config.PENDING_TTL_SECONDS:
            self._core.ledger.reject_payment(txn_id, "request_expired")
            raise PendingRequestError("payment request expired")

        payer = self._core.registry.get(payer_id)
        if payer is None:
            raise UnknownIdentityError(f"payer {payer_id} not enrolled")

        payload = payment_authorisation_sig_payload(
            txn_id=txn_id,
            payer_id=payer_id,
            merchant_id=str(message["merchant_id"]),
            amount_minor=int(message["amount_minor"]),
            currency=str(message["currency"]),
            ts=int(message["ts"]),
            client_nonce=int(message["client_nonce"]),
            channel_binding=self.session_id,
        )
        verify_payment_authorisation_sig(
            VerifyKey(payer.public_key), payload, str(message["payer_sig"])
        )

        merchant_session = self._core.online_session(str(message["merchant_id"]))
        try:
            receipt, _seq = self._core.ledger.settle_payment(
                txn_id=txn_id,
                payer_id=payer_id,
                merchant_id=str(message["merchant_id"]),
                amount_minor=int(message["amount_minor"]),
                currency=str(message["currency"]),
                client_nonce=int(message["client_nonce"]),
                payer_sig=str(message["payer_sig"]),
                receipt_factory=lambda seq: self._core.receipt_for(
                    ledger_seq=seq,
                    txn_id=txn_id,
                    payer_id=payer_id,
                    merchant_id=str(message["merchant_id"]),
                    amount_minor=int(message["amount_minor"]),
                    currency=str(message["currency"]),
                    session_id=self.session_id,
                ),
            )
        except SecurePayError as exc:
            self._core.ledger.reject_payment(txn_id, exc.code)
            channel.send(
                {
                    "type": MSG_AUTH_REJECTED,
                    "v": config.PROTOCOL_VERSION,
                    "txn_id": txn_id,
                    "reason_code": exc.code,
                }
            )
            if merchant_session is not None:
                merchant_session.push(
                    {
                        "type": MSG_PAYMENT_RESULT,
                        "v": config.PROTOCOL_VERSION,
                        "txn_id": txn_id,
                        "status": "REJECTED",
                        "reason_code": exc.code,
                    }
                )
            return
        self._core.ledger.store_receipt(txn_id, receipt)
        channel.send(
            {
                "type": MSG_RECEIPT,
                "v": config.PROTOCOL_VERSION,
                "receipt": receipt,
            }
        )
        if merchant_session is not None:
            merchant_session.push(
                {
                    "type": MSG_PAYMENT_RESULT,
                    "v": config.PROTOCOL_VERSION,
                    "txn_id": txn_id,
                    "status": "SETTLED",
                    "receipt": receipt,
                }
            )

    def _handle_decline(self, message: dict[str, object]) -> None:
        channel = self._require_channel()
        payer_id = str(message["payer_id"])
        if payer_id != self.peer_id:
            raise ProtocolError("a wallet may only decline its own payments")
        txn_id = str(message["txn_id"])
        merchant_id = str(message["merchant_id"])

        record = self._core.ledger.get_txn(txn_id)
        if record is None:
            raise PendingRequestError(f"no payment request for {txn_id}")
        if record.status != "PENDING":
            raise PendingRequestError(f"txn {txn_id} is {record.status}, not PENDING")

        payer = self._core.registry.get(payer_id)
        if payer is None:
            raise UnknownIdentityError(f"payer {payer_id} not enrolled")
        payload = payment_decline_sig_payload(
            txn_id=txn_id,
            payer_id=payer_id,
            merchant_id=merchant_id,
            amount_minor=int(message["amount_minor"]),
            currency=str(message["currency"]),
            ts=int(message["ts"]),
            channel_binding=self.session_id,
        )
        verify_payment_decline_sig(VerifyKey(payer.public_key), payload, str(message["payer_sig"]))

        self._core.ledger.decline_payment(
            txn_id=txn_id,
            payer_id=payer_id,
            merchant_id=merchant_id,
            amount_minor=int(message["amount_minor"]),
            currency=str(message["currency"]),
            payer_sig=str(message["payer_sig"]),
            decided_ts=int(message["ts"]),
        )
        channel.send(
            {
                "type": MSG_AUTH_REJECTED,
                "v": config.PROTOCOL_VERSION,
                "txn_id": txn_id,
                "reason_code": "declined_by_payer",
            }
        )
        merchant_session = self._core.online_session(merchant_id)
        if merchant_session is not None:
            merchant_session.push(
                {
                    "type": MSG_PAYMENT_RESULT,
                    "v": config.PROTOCOL_VERSION,
                    "txn_id": txn_id,
                    "status": "REJECTED",
                    "reason_code": "declined_by_payer",
                }
            )

    def _handle_balance(self) -> None:
        channel = self._require_channel()
        balance = self._core.ledger.balance(self.peer_id)
        channel.send(
            {
                "type": MSG_BALANCE_REPORT,
                "v": config.PROTOCOL_VERSION,
                "account_id": self.peer_id,
                "balance_minor": balance,
                "currency": config.CURRENCY,
            }
        )

    def _handle_get_pending(self) -> None:
        channel = self._require_channel()
        requests = []
        for record in self._core.ledger.pending_requests_for(self.peer_id):
            if now_ts() - record.created_ts > config.PENDING_TTL_SECONDS:
                continue
            merchant = self._core.registry.get(record.merchant_id)
            if merchant is None:
                continue
            requests.append(
                {
                    "type": MSG_AUTHORISATION_REQUEST,
                    "v": config.PROTOCOL_VERSION,
                    "txn_id": record.txn_id,
                    "merchant_id": merchant.id,
                    "merchant_name": merchant.name,
                    "merchant_cert_pem": merchant.cert_pem,
                    "merchant_session": record.session_id,
                    "payer_id": record.payer_id,
                    "amount_minor": record.amount_minor,
                    "currency": record.currency,
                    "ts": record.request_ts if record.request_ts is not None else record.created_ts,
                    "merchant_sig": record.merchant_sig,
                }
            )
        channel.send(
            {
                "type": MSG_PENDING_LIST,
                "v": config.PROTOCOL_VERSION,
                "requests": requests,
            }
        )


    def push(self, message: dict[str, object]) -> None:
        if self.channel is None:
            raise ProtocolError("session is not established")
        self.channel.send(message)

    def _send_error(self, code: str, message: str) -> None:
        if self.channel is None:
            return
        try:
            self.channel.send(
                {
                    "type": MSG_ERROR,
                    "v": config.PROTOCOL_VERSION,
                    "code": code,
                    "message": message,
                }
            )
        except (SecurePayError, OSError):
            logger.warning("event=error_send_failed peer=%s", self.peer_id)


class SwitchServer:

    def __init__(self, core: SwitchCore, host: str, port: int = 0) -> None:
        self._core = core
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self._sock.listen(16)
        self._sock.settimeout(0.5)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sessions: set[SwitchSession] = set()
        self._sessions_lock = threading.Lock()
        logger.info("event=switch_listening host=%s port=%d", host, self.port)

    @property
    def host(self) -> str:
        return self._sock.getsockname()[0]

    @property
    def port(self) -> int:
        return int(self._sock.getsockname()[1])

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self.serve_forever, name="switch-accept", daemon=True
        )
        self._thread.start()

    def serve_forever(self) -> None:
        while not self._stop.is_set():
            try:
                sock, addr = self._sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            session = SwitchSession(self._core, sock, addr)
            with self._sessions_lock:
                self._sessions.add(session)
            thread = threading.Thread(
                target=self._run_session,
                args=(session,),
                name=f"switch-session-{addr[0]}:{addr[1]}",
                daemon=True,
            )
            thread.start()

    def _run_session(self, session: SwitchSession) -> None:
        try:
            session.run()
        finally:
            with self._sessions_lock:
                self._sessions.discard(session)

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
