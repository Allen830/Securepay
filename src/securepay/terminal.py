from __future__ import annotations

import contextlib
import logging
import socket
import time

from nacl.signing import SigningKey

from securepay import config
from securepay.channel import Channel
from securepay.encoding import new_txn_id, now_ts
from securepay.errors import ProtocolError, SecurePayError
from securepay.framing import FramingError
from securepay.handshake import (
    HandshakeIdentity,
    HandshakeResult,
    TrustAnchor,
    run_client_handshake,
)
from securepay.pki import cert_from_pem, load_crl, read_cert
from securepay.protocol import (
    MSG_BALANCE_QUERY,
    MSG_BALANCE_REPORT,
    MSG_ERROR,
    MSG_PAYMENT_REQUEST,
    MSG_PAYMENT_REQUEST_ACK,
    MSG_PAYMENT_RESULT,
    payment_request_sig_payload,
    sign_payment_request,
    validate_message,
)
from securepay.ratelimit import AttemptTracker
from securepay.switch import RegistryEntry, load_registry

logger = logging.getLogger(__name__)

__all__ = ["TerminalClient"]


class TerminalClient:

    def __init__(
        self,
        paths: config.NetworkPaths,
        merchant_id: str,
        passphrase: str,
        *,
        host: str = config.DEFAULT_HOST,
        port: int = config.DEFAULT_SWITCH_PORT,
    ) -> None:
        from securepay.keystore import unlock_vault

        self.merchant_id = merchant_id
        self.paths = paths
        registry = load_registry(paths.registry)
        entry = registry.get(merchant_id)
        if entry is None or entry.role != config.ROLE_MERCHANT:
            raise ProtocolError(f"merchant {merchant_id} is not enrolled")
        self.entry: RegistryEntry = entry

        tracker = AttemptTracker(paths.lockout(paths.terminal_vault(merchant_id)))
        vault = unlock_vault(
            paths.terminal_vault(merchant_id),
            passphrase,
            expected_aad={"kind": "merchant", "id": merchant_id},
            tracker=tracker,
        )
        self.signing_key = SigningKey(bytes.fromhex(vault["seed"]))
        self.cert = cert_from_pem(vault["cert_pem"])

        self._sock = socket.create_connection((host, port), timeout=config.HANDSHAKE_TIMEOUT)
        anchor = TrustAnchor(
            ca_cert=read_cert(paths.ca_cert),
            crl_provider=lambda: load_crl(paths.crl),
            expected_peer_id=config.SWITCH_ID,
            expected_peer_role=config.ROLE_SWITCH,
        )
        identity = HandshakeIdentity(
            id=merchant_id,
            role=config.ROLE_MERCHANT,
            signing_key=self.signing_key,
            cert=self.cert,
        )
        result: HandshakeResult = run_client_handshake(self._sock, identity, anchor)
        self.channel = Channel(self._sock, "client", result.secrets)
        self.session_id = result.session_id
        logger.info(
            "event=terminal_connected merchant=%s session=%s",
            merchant_id,
            self.session_id[:12],
        )


    def request_payment(
        self,
        payer_id: str,
        amount_minor: int,
        *,
        currency: str = config.CURRENCY,
        txn_id: str | None = None,
    ) -> str:
        txn_id = txn_id or new_txn_id()
        ts = now_ts()
        payload = payment_request_sig_payload(
            txn_id=txn_id,
            merchant_id=self.merchant_id,
            payer_id=payer_id,
            amount_minor=amount_minor,
            currency=currency,
            ts=ts,
            channel_binding=self.session_id,
        )
        request: dict[str, object] = {
            "type": MSG_PAYMENT_REQUEST,
            "v": config.PROTOCOL_VERSION,
            "txn_id": txn_id,
            "merchant_id": self.merchant_id,
            "payer_id": payer_id,
            "amount_minor": amount_minor,
            "currency": currency,
            "ts": ts,
            "merchant_sig": sign_payment_request(self.signing_key, payload),
        }
        self.channel.send(request)
        while True:
            message = self._recv_or_raise()
            msg_type = validate_message(message)
            if msg_type == MSG_PAYMENT_REQUEST_ACK and message.get("txn_id") == txn_id:
                return txn_id
            if msg_type == MSG_ERROR:
                raise SecurePayError(f"switch refused the request: {message.get('code')}")

    def await_result(self, txn_id: str, *, wait_seconds: float = 30.0) -> dict[str, object]:
        deadline = time.monotonic() + wait_seconds
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            message = self._recv_or_raise(timeout=remaining)
            msg_type = validate_message(message)
            if msg_type == MSG_PAYMENT_RESULT and message.get("txn_id") == txn_id:
                return message
            if msg_type == MSG_ERROR:
                raise SecurePayError(f"switch refused the request: {message.get('code')}")

    def charge(
        self,
        payer_id: str,
        amount_minor: int,
        *,
        currency: str = config.CURRENCY,
        wait_seconds: float = 30.0,
        txn_id: str | None = None,
    ) -> dict[str, object]:
        txn = self.request_payment(payer_id, amount_minor, currency=currency, txn_id=txn_id)
        return self.await_result(txn, wait_seconds=wait_seconds)

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

    def close(self) -> None:
        self.channel.close()
        with contextlib.suppress(OSError):
            self._sock.close()
