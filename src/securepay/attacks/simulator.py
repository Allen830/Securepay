from __future__ import annotations

import contextlib
import json
import logging
import shutil
import socket
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from securepay import config
from securepay.attacks.mitm_proxy import MITMProxy, reframe
from securepay.bootstrap import (
    issue_entity_certificate,
    provision_network,
    revoke_entity_certificate,
)
from securepay.channel import seal_frame
from securepay.client import WalletClient
from securepay.encoding import b64_encode, canonical_bytes, now_ts
from securepay.errors import BadPassphraseError, RateLimitError, SecurePayError
from securepay.framing import send_frame
from securepay.handshake import x25519_ephemeral
from securepay.keystore import unlock_vault
from securepay.pki import create_ca, generate_signing_key, issue_certificate
from securepay.protocol import (
    MSG_PAYMENT_AUTHORISATION,
    payment_authorisation_sig_payload,
    sign_payment_authorisation,
)
from securepay.ratelimit import AttemptTracker, generate_passphrase
from securepay.switch import SwitchCore, SwitchServer
from securepay.terminal import TerminalClient

logger = logging.getLogger(__name__)

__all__ = [
    "CASES",
    "HIGH_IMPACT",
    "CaseResult",
    "Lab",
    "LogCapture",
    "result_level",
    "run_all",
    "run_case",
]

HIGH_IMPACT = frozenset(
    {
        "mitm-key-substitution",
        "impersonate-switch",
        "downgrade",
        "revoked-certificate",
        "vault-bruteforce",
        "double-spend",
        "mitm-modify-amount",
    }
)

_PROPERTY = {
    "bit-flip": "Integrity",
    "aad-tamper": "Integrity",
    "replay-same-session": "Integrity",
    "replay-new-session": "Non-repudiation",
    "reorder": "Integrity",
    "stale-frame": "Integrity",
    "mitm-modify-amount": "Integrity",
    "mitm-key-substitution": "Authentication",
    "impersonate-switch": "Authentication",
    "revoked-certificate": "Authentication",
    "expired-certificate": "Authentication",
    "downgrade": "Authentication",
    "vault-bruteforce": "Confidentiality",
    "malformed-frame": "Integrity",
    "double-spend": "Integrity",
}

_FAST_KDF = {"ARGON2ID_OPSLIMIT": 1, "ARGON2ID_MEMLIMIT": 8 * 1024 * 1024}


@contextlib.contextmanager
def fast_kdf() -> Iterator[None]:
    with config.temporary(**_FAST_KDF):
        yield


class LogCapture(logging.Handler):

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[tuple[str, str]] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append((record.levelname, record.getMessage()))

    def expect(self, *fragments: str, count: int = 1, timeout: float = 3.0) -> str:
        deadline = time.monotonic() + timeout
        while True:
            hits = sum(1 for _lv, msg in list(self.records) if all(f in msg for f in fragments))
            if hits >= count:
                return ""
            if time.monotonic() >= deadline:
                return f"expected log not seen: {' '.join(fragments)} (need {count}, saw {hits})"
            time.sleep(0.05)


def result_level(name: str, passed: bool, detail: str) -> int:
    if detail.startswith("harness error") or not passed:
        return logging.ERROR
    return logging.ERROR if name in HIGH_IMPACT else logging.WARNING


@dataclass
class CaseResult:

    name: str
    passed: bool
    detail: str


class Lab:

    def __init__(self, *, fast: bool = True) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="securepay-lab-"))
        self.fast = fast
        self.logs = LogCapture()
        logging.getLogger("securepay").addHandler(self.logs)
        self._fast_ctx: contextlib.AbstractContextManager[None] | None = (
            fast_kdf() if fast else None
        )
        if self._fast_ctx is not None:
            self._fast_ctx.__enter__()
        try:
            self.network = provision_network(self.root)
            self.core = SwitchCore(self.network.paths, self.network.passphrases[config.SWITCH_ID])
            self.server = SwitchServer(self.core, config.DEFAULT_HOST, 0)
            self.server.start()
        except BaseException:
            self.stop()
            raise


    def expect_log(self, *fragments: str, count: int = 1, timeout: float = 3.0) -> str:
        return self.logs.expect(*fragments, count=count, timeout=timeout)

    def _kdf(self) -> contextlib.AbstractContextManager[None]:
        return fast_kdf() if self.fast else contextlib.nullcontext()

    @property
    def paths(self) -> config.NetworkPaths:
        return self.network.paths

    @property
    def port(self) -> int:
        return self.server.port

    def terminal(
        self, merchant_id: str = "coffee_shop", *, via: tuple[str, int] | None = None
    ) -> TerminalClient:
        host, port = via if via else (config.DEFAULT_HOST, self.port)
        with self._kdf():
            return TerminalClient(
                self.paths,
                merchant_id,
                self.network.passphrases[merchant_id],
                host=host,
                port=port,
            )

    def wallet(
        self, student_id: str = "902101", *, via: tuple[str, int] | None = None
    ) -> WalletClient:
        host, port = via if via else (config.DEFAULT_HOST, self.port)
        with self._kdf():
            return WalletClient(
                self.paths,
                student_id,
                self.network.passphrases[student_id],
                host=host,
                port=port,
            )

    def balance(self, account_id: str) -> int:
        return self.core.ledger.balance(account_id)

    def restart_switch(self) -> None:
        self.server.stop()
        self.core.ledger.close()
        self.core = SwitchCore(self.network.paths, self.network.passphrases[config.SWITCH_ID])
        self.server = SwitchServer(self.core, config.DEFAULT_HOST, 0)
        self.server.start()

    def stop(self) -> None:
        if getattr(self, "server", None) is not None:
            self.server.stop()
        if getattr(self, "core", None) is not None:
            self.core.ledger.close()
        shutil.rmtree(self.root, ignore_errors=True)
        logging.getLogger("securepay").removeHandler(self.logs)
        if self._fast_ctx is not None:
            self._fast_ctx.__exit__(None, None, None)
            self._fast_ctx = None


def _channel_payload(frame: bytes) -> bytes:
    if len(frame) < 5:
        return b""
    outer_len = int.from_bytes(frame[:4], "big")
    payload = frame[4:]
    if len(payload) != outer_len:
        return b""
    return payload


def _mutate_channel_frame(
    frame: bytes, *, flip_byte: int | None = None, ts_delta: int = 0
) -> bytes:
    payload = _channel_payload(frame)
    header_len = int.from_bytes(payload[:4], "big")
    header = json.loads(payload[4 : 4 + header_len])
    ciphertext = payload[4 + header_len :]
    if ts_delta:
        header["ts"] = int(header["ts"]) + ts_delta
    new_header = canonical_bytes(header)
    if flip_byte is not None:
        pos = flip_byte % len(ciphertext)
        ciphertext = ciphertext[:pos] + bytes([ciphertext[pos] ^ 0x01]) + ciphertext[pos + 1 :]
    return reframe(len(new_header).to_bytes(4, "big") + new_header + ciphertext)


def _is_channel_frame(frame: bytes) -> bool:
    payload = _channel_payload(frame)
    if len(payload) < 5:
        return False
    header_len = int.from_bytes(payload[:4], "big")
    if header_len <= 0 or 4 + header_len >= len(payload):
        return False
    try:
        header = json.loads(payload[4 : 4 + header_len])
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(header, dict) and "sid" in header and "n" in header


def _channel_frame_hook(
    *,
    flip_byte: int | None = None,
    ts_delta: int = 0,
    duplicate: bool = False,
    reorder: bool = False,
    target: int = 1,
) -> Callable[[int, bytes], bytes | list[bytes] | None]:
    seen_channel_frames: list[bytes] = []
    held: list[bytes] = []

    def hook(index: int, frame: bytes) -> bytes | list[bytes] | None:
        if not _is_channel_frame(frame):
            return frame
        seen_channel_frames.append(frame)
        position = len(seen_channel_frames)
        if reorder:
            if position == 1:
                held.append(frame)
                return None
            if held:
                first = held.pop()
                return [frame, first]
            return frame
        if duplicate and position == 1:
            return [frame, frame]
        if position == target:
            return _mutate_channel_frame(frame, flip_byte=flip_byte, ts_delta=ts_delta)
        return frame

    return hook


def _expect_blocked(callable_: Callable[[], object], *needles: str) -> str:
    try:
        callable_()
    except SecurePayError as exc:
        if exc.message == "frame transport timeout":
            return "no rejection observed: the read timed out"
        text = f"{exc.code} {exc.message}"
        if needles and not any(needle in text for needle in needles):
            return f"blocked with unexpected error: {text}"
        return ""
    except OSError as exc:
        return f"harness socket error: {exc}"
    return "attack was NOT blocked"


def _send_query(wallet: WalletClient, message: dict[str, object]) -> None:
    wallet.channel.send(message)


def attack_bit_flip(lab: Lab) -> tuple[bool, str]:
    proxy = MITMProxy(
        config.DEFAULT_HOST, lab.port, on_client_frame=_channel_frame_hook(flip_byte=8), record=True
    )
    proxy.start()
    wallet = lab.wallet(via=(proxy.host, proxy.port))
    try:
        _send_query(wallet, {"type": "get_pending", "v": config.PROTOCOL_VERSION})
        result = _expect_blocked(lambda: wallet.channel.recv(timeout=5.0))
        if result:
            return False, result
        missing = lab.expect_log("event=session_failed", "code=decrypt_failed")
        if missing:
            return False, missing
        return True, "tampered frame rejected: AEAD tag failed, session aborted"
    finally:
        wallet.close()
        proxy.stop()


def attack_aad_tamper(lab: Lab) -> tuple[bool, str]:
    proxy = MITMProxy(
        config.DEFAULT_HOST, lab.port, on_client_frame=_channel_frame_hook(ts_delta=1), record=True
    )
    proxy.start()
    wallet = lab.wallet(via=(proxy.host, proxy.port))
    try:
        _send_query(wallet, {"type": "get_pending", "v": config.PROTOCOL_VERSION})
        result = _expect_blocked(lambda: wallet.channel.recv(timeout=5.0))
        if result:
            return False, result
        missing = lab.expect_log("event=session_failed", "code=decrypt_failed")
        if missing:
            return False, missing
        return True, "modified AAD rejected: header no longer matches the AEAD tag"
    finally:
        wallet.close()
        proxy.stop()


def attack_replay_same_session(lab: Lab) -> tuple[bool, str]:
    proxy = MITMProxy(
        config.DEFAULT_HOST,
        lab.port,
        on_client_frame=_channel_frame_hook(duplicate=True),
        record=True,
    )
    proxy.start()
    wallet = lab.wallet(via=(proxy.host, proxy.port))
    try:
        _send_query(wallet, {"type": "get_pending", "v": config.PROTOCOL_VERSION})
        wallet.channel.recv(timeout=5.0)
        result = _expect_blocked(lambda: wallet.channel.recv(timeout=5.0))
        if result:
            return False, result
        missing = lab.expect_log("event=session_failed", "code=replay_detected")
        if missing:
            return False, missing
        return True, "duplicate frame rejected: strict monotonic counter (replay)"
    finally:
        wallet.close()
        proxy.stop()


def attack_replay_new_session(lab: Lab) -> tuple[bool, str]:
    terminal = lab.terminal("coffee_shop")
    wallet1 = lab.wallet("902101")
    try:
        txn_id = terminal.request_payment("902101", 1250)
        request = wallet1.pending_requests()[0]

        crafted = _authorisation_from(wallet1, request, channel_binding=wallet1.session_id)
        wallet2 = lab.wallet("902101")
        try:
            wallet2.channel.send(crafted)
            reply = wallet2.channel.recv(timeout=5.0)
            if reply.get("type") != "error" or reply.get("code") != "bad_signature":
                return False, f"cross-session artefact accepted: {reply.get('code')}"
            still = wallet2.pending_requests()
            if not any(r["txn_id"] == txn_id for r in still):
                return False, "pending request vanished after rejected replay"
            receipt = wallet2.authorise(request)
            if receipt.get("txn_id") != txn_id:
                return False, "settlement returned a different transaction"
        finally:
            wallet2.close()

        wallet3 = lab.wallet("902101")
        try:
            result = _expect_blocked(lambda: wallet3.authorise(request), "duplicate_txn")
            if result:
                return False, f"double-spend attempt not blocked: {result}"
        finally:
            wallet3.close()
        missing = lab.expect_log("event=request_failed", "code=bad_signature")
        if missing:
            return False, missing
        missing = lab.expect_log("event=request_failed", "code=duplicate_txn")
        if missing:
            return False, missing
        return True, (
            "captured artefact rejected (bad_signature: channel binding); "
            "re-signed duplicate rejected (duplicate_txn: persistent idempotency)"
        )
    finally:
        terminal.close()
        wallet1.close()


def _authorisation_from(
    wallet: WalletClient, request: dict[str, object], *, channel_binding: str
) -> dict[str, object]:
    payload = payment_authorisation_sig_payload(
        txn_id=str(request["txn_id"]),
        payer_id=wallet.student_id,
        merchant_id=str(request["merchant_id"]),
        amount_minor=int(request["amount_minor"]),
        currency=str(request["currency"]),
        ts=int(request["ts"]),
        client_nonce=int(wallet._vault_payload["next_nonce"]),
        channel_binding=channel_binding,
    )
    return {
        "type": MSG_PAYMENT_AUTHORISATION,
        "v": config.PROTOCOL_VERSION,
        "txn_id": request["txn_id"],
        "payer_id": wallet.student_id,
        "merchant_id": request["merchant_id"],
        "amount_minor": request["amount_minor"],
        "currency": request["currency"],
        "ts": request["ts"],
        "client_nonce": wallet._vault_payload["next_nonce"],
        "payer_sig": sign_payment_authorisation(wallet.signing_key, payload),
    }


def attack_reorder(lab: Lab) -> tuple[bool, str]:
    proxy = MITMProxy(
        config.DEFAULT_HOST,
        lab.port,
        on_client_frame=_channel_frame_hook(reorder=True),
        record=True,
    )
    proxy.start()
    wallet = lab.wallet(via=(proxy.host, proxy.port))
    try:
        _send_query(wallet, {"type": "get_pending", "v": config.PROTOCOL_VERSION})
        _send_query(wallet, {"type": "balance_query", "v": config.PROTOCOL_VERSION})
        result = _expect_blocked(lambda: wallet.channel.recv(timeout=5.0))
        if result:
            return False, result
        missing = lab.expect_log("event=session_failed", "code=reorder_detected")
        if missing:
            return False, missing
        return True, "reordered frames rejected: counter must match exactly"
    finally:
        wallet.close()
        proxy.stop()


def attack_stale_frame(lab: Lab) -> tuple[bool, str]:
    wallet = lab.wallet()
    try:
        payload = canonical_bytes({"type": "get_pending", "v": config.PROTOCOL_VERSION})
        frame = seal_frame(
            wallet.channel._send_key,
            wallet.channel._send_prefix,
            wallet.channel.session_id,
            "c2s",
            wallet.channel.epoch,
            wallet.channel._send_counter,
            now_ts() - 7 * 24 * 3600,
            payload,
        )
        send_frame(wallet._sock, frame)
        result = _expect_blocked(lambda: wallet.channel.recv(timeout=5.0))
        if result:
            return False, result
        missing = lab.expect_log("event=session_failed", "code=stale_frame")
        if missing:
            return False, missing
        return True, "old frame rejected: timestamp outside freshness window"
    finally:
        wallet.close()


def attack_mitm_modify_amount(lab: Lab) -> tuple[bool, str]:
    terminal = lab.terminal("coffee_shop")
    txn_id = terminal.request_payment("902101", 1250)
    payer_before = lab.balance("902101")
    merchant_before = lab.balance("coffee_shop")

    proxy = MITMProxy(
        config.DEFAULT_HOST,
        lab.port,
        on_client_frame=_channel_frame_hook(flip_byte=3, target=2),
        record=True,
    )
    proxy.start()
    wallet = lab.wallet(via=(proxy.host, proxy.port))
    try:
        requests = wallet.pending_requests()
        blocked = _expect_blocked(lambda: wallet.authorise(requests[0]))
        if blocked:
            return False, f"tampered authorisation not blocked: {blocked}"
        if lab.balance("902101") != payer_before or lab.balance("coffee_shop") != merchant_before:
            return False, "balances moved despite a tampered authorisation"
        record = lab.core.ledger.get_txn(txn_id)
        if record is None or record.status != "PENDING":
            return False, f"tampered txn unexpectedly in state {record and record.status}"
        missing = lab.expect_log("event=session_failed", "code=decrypt_failed")
        if missing:
            return False, missing
        return True, (
            "amount is inside the AEAD ciphertext; flipping it breaks the tag,"
            " the session aborts and nothing settles"
        )
    finally:
        wallet.close()
        proxy.stop()
        terminal.close()


def attack_mitm_key_substitution(lab: Lab) -> tuple[bool, str]:

    def hook(index: int, frame: bytes) -> bytes:
        if index != 1:
            return frame
        message = json.loads(_channel_payload(frame).decode("utf-8"))
        if message.get("type") != "client_hello":
            return frame
        _attacker_priv, attacker_pub = x25519_ephemeral()
        message["eph"] = b64_encode(attacker_pub)
        return reframe(canonical_bytes(message))

    proxy = MITMProxy(config.DEFAULT_HOST, lab.port, on_client_frame=hook)
    proxy.start()
    try:
        try:
            lab.wallet(via=(proxy.host, proxy.port))
            return False, "handshake succeeded through a substituted ephemeral key"
        except SecurePayError as exc:
            missing = lab.expect_log("event=client_handshake_failed")
            if missing:
                return False, missing
            return True, (
                f"key substitution detected during handshake ({exc.code}):"
                " transcript signatures / Finished MAC no longer match"
            )
    finally:
        proxy.stop()


def attack_impersonate_switch(lab: Lab) -> tuple[bool, str]:

    class FakeSwitch(threading.Thread):
        def __init__(self) -> None:
            super().__init__(daemon=True)
            self.key = generate_signing_key()
            self.ca_key = generate_signing_key()
            self.ca_cert = create_ca(self.ca_key)
            self.cert = issue_certificate(
                self.ca_key,
                self.ca_cert,
                config.SWITCH_ID,
                config.ROLE_SWITCH,
                self.key.verify_key,
            )
            self.listener = socket.socket()
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind((config.DEFAULT_HOST, 0))
            self.listener.listen(1)
            self.listener.settimeout(5.0)
            self.port = self.listener.getsockname()[1]

        def run(self) -> None:
            from securepay.handshake import HandshakeIdentity, TrustAnchor, run_server_handshake

            try:
                sock, _ = self.listener.accept()
            except OSError:
                return
            anchor = TrustAnchor(
                ca_cert=self.ca_cert,
                crl_provider=lambda: None,
                expected_peer_id=None,
                expected_peer_role=None,
            )
            identity = HandshakeIdentity(
                id=config.SWITCH_ID,
                role=config.ROLE_SWITCH,
                signing_key=self.key,
                cert=self.cert,
            )
            try:
                run_server_handshake(sock, identity, anchor, timeout=5.0)
            except Exception:
                pass
            finally:
                sock.close()

    fake = FakeSwitch()
    fake.start()
    try:
        try:
            lab.wallet(via=(config.DEFAULT_HOST, fake.port))
            return False, "wallet accepted an untrusted switch certificate"
        except SecurePayError as exc:
            if exc.code != "untrusted_certificate":
                return False, f"blocked for the wrong reason: {exc.code}"
            missing = lab.expect_log("event=client_handshake_failed", "code=untrusted_certificate")
            if missing:
                return False, missing
            return True, "rogue certificate rejected: not signed by the campus CA"
    finally:
        fake.listener.close()
        fake.join(timeout=2.0)


def _terminal_session_is_dead(lab: Lab, merchant_id: str) -> bool:
    if lab.core.online_session(merchant_id) is not None:
        return False
    try:
        terminal = lab.terminal(merchant_id)
    except (SecurePayError, OSError):
        return True
    try:
        terminal.balance()
        return False
    except (SecurePayError, OSError):
        return True
    finally:
        terminal.close()


def attack_revoked_certificate(lab: Lab) -> tuple[bool, str]:
    revoke_entity_certificate(lab.paths, lab.network.ca_passphrase, "library")
    if not _terminal_session_is_dead(lab, "library"):
        return False, "revoked certificate was accepted and served"
    missing = lab.expect_log("event=session_failed", "code=certificate_revoked")
    if missing:
        return False, missing
    return True, "revoked certificate rejected: the re-read CRL aborts the session"


def attack_expired_certificate(lab: Lab) -> tuple[bool, str]:
    now = datetime.now(timezone.utc)
    issue_entity_certificate(
        lab.paths,
        lab.network.ca_passphrase,
        role=config.ROLE_MERCHANT,
        entity_id="old_pos",
        name="Retired POS",
        passphrase=lab.network.passphrases.setdefault("old_pos", generate_passphrase()),
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    lab.restart_switch()
    if not _terminal_session_is_dead(lab, "old_pos"):
        return False, "expired certificate was accepted and served"
    missing = lab.expect_log("event=session_failed", "code=certificate_expired")
    if missing:
        return False, missing
    return True, "expired certificate rejected: outside its validity window"


def attack_downgrade(lab: Lab) -> tuple[bool, str]:
    sock = socket.create_connection((config.DEFAULT_HOST, lab.port), timeout=5.0)
    try:
        hello = canonical_bytes(
            {
                "type": "client_hello",
                "v": 0,
                "suite": "SP1-EXPORT-GRADE",
                "id": "902101",
                "eph": b64_encode(b"\x11" * 32),
                "nonce": b64_encode(b"\x22" * 32),
                "ts": now_ts(),
            }
        )
        send_frame(sock, hello)
        sock.settimeout(5.0)
        try:
            data = sock.recv(4096)
        except OSError as exc:
            return False, f"harness error reading switch reply: {exc}"
        if data:
            return False, "switch answered a version-0 hello instead of aborting"
    finally:
        sock.close()

    def hook(index: int, frame: bytes) -> bytes:
        if index != 1:
            return frame
        message = json.loads(_channel_payload(frame).decode("utf-8"))
        if message.get("type") != "client_hello":
            return frame
        message["suite"] = "SP1-EXPORT-GRADE"
        return reframe(canonical_bytes(message))

    proxy = MITMProxy(config.DEFAULT_HOST, lab.port, on_client_frame=hook)
    proxy.start()
    try:
        try:
            lab.wallet(via=(proxy.host, proxy.port))
            return False, "handshake succeeded with a rewritten cipher suite"
        except SecurePayError:
            pass
    finally:
        proxy.stop()

    missing = lab.expect_log("event=session_failed", "code=version_mismatch", count=2)
    if missing:
        return False, missing

    wallet = lab.wallet()
    wallet.close()
    return True, (
        "version-0 hello and a real hello with a rewritten suite both rejected"
        " (version_mismatch); switch stays healthy"
    )


def attack_vault_bruteforce(lab: Lab) -> tuple[bool, str]:
    tracker = AttemptTracker(lab.paths.lockout(lab.paths.wallet_vault("902101")))
    vault_path = lab.paths.wallet_vault("902101")
    aad = {"kind": "student", "id": "902101"}
    with lab._kdf():
        for attempt in range(1, config.UNLOCK_MAX_FAILURES + 1):
            try:
                unlock_vault(vault_path, "wrong-passphrase", aad, tracker)
                return False, f"wrong passphrase accepted on attempt {attempt}"
            except BadPassphraseError:
                continue
        try:
            unlock_vault(
                vault_path,
                lab.network.passphrases["902101"],
                aad,
                tracker,
            )
            return False, "correct passphrase accepted during lockout"
        except RateLimitError:
            missing = lab.expect_log("event=vault_unlock_failed", count=config.UNLOCK_MAX_FAILURES)
            if missing:
                return False, missing
            missing = lab.expect_log("event=vault_locked_out")
            if missing:
                return False, missing
            return True, (
                f"{config.UNLOCK_MAX_FAILURES} failures trigger lockout;"
                " the correct passphrase is refused while locked"
            )


def attack_malformed_frame(lab: Lab) -> tuple[bool, str]:
    probes = [
        (0xFFFFFFFF).to_bytes(4, "big"),
        (0).to_bytes(4, "big"),
        (64).to_bytes(4, "big") + b"part",
        b"\xff\x00\xde\xad\xbe\xef",
    ]
    for probe in probes:
        sock = socket.create_connection((config.DEFAULT_HOST, lab.port), timeout=5.0)
        try:
            sock.sendall(probe)
            sock.settimeout(5.0)
            try:
                chunk = sock.recv(4096)
            except OSError:
                chunk = b""
            if chunk:
                return False, f"switch answered malformed probe {probe!r}"
        finally:
            sock.close()
    wallet = lab.wallet()
    wallet.close()
    missing = lab.expect_log("event=session_failed", "code=framing_error", count=len(probes))
    if missing:
        return False, missing
    return True, "malformed/oversized frames close the connection; switch stays healthy"


def attack_double_spend(lab: Lab) -> tuple[bool, str]:
    terminal = lab.terminal("coffee_shop")
    try:
        txn_id = terminal.request_payment("902101", 2500)
        terminal2 = lab.terminal("coffee_shop")
        try:
            result = _expect_blocked(
                lambda: terminal2.request_payment("902101", 2500, txn_id=txn_id),
                "duplicate_txn",
            )
            if result:
                return False, f"duplicate request accepted: {result}"
        finally:
            terminal2.close()

        wallet = lab.wallet("902101")
        try:
            request = wallet.pending_requests()[0]
            receipt = wallet.authorise(request)
            if receipt.get("txn_id") != txn_id:
                return False, "settlement returned a different transaction"
        finally:
            wallet.close()

        wallet2 = lab.wallet("902101")
        try:
            result = _expect_blocked(lambda: wallet2.authorise(request), "duplicate_txn")
            if result:
                return False, f"double authorisation accepted: {result}"
        finally:
            wallet2.close()

        payer, merchant = lab.balance("902101"), lab.balance("coffee_shop")
        if payer != 45000 - 2500 or merchant != 220000 + 2500:
            return False, f"balances wrong after double-spend attempt: {payer}/{merchant}"
        missing = lab.expect_log("event=request_failed", "code=duplicate_txn", count=2)
        if missing:
            return False, missing
        return True, (
            "duplicate txn_id refused on request AND authorisation; balances moved exactly once"
        )
    finally:
        terminal.close()


CASES: dict[str, tuple[str, Callable[[Lab], tuple[bool, str]]]] = {
    "bit-flip": ("Flip one ciphertext bit in a live session frame", attack_bit_flip),
    "aad-tamper": ("Rewrite the AAD/header timestamp of a frame", attack_aad_tamper),
    "replay-same-session": ("Duplicate a frame inside one session", attack_replay_same_session),
    "replay-new-session": (
        "Replay a captured authorisation in a new session; re-sign the same txn",
        attack_replay_new_session,
    ),
    "reorder": ("Deliver two frames in reverse order", attack_reorder),
    "stale-frame": (
        "Craft a validly encrypted frame with a week-old timestamp",
        attack_stale_frame,
    ),
    "mitm-modify-amount": ("MITM modifies a payment amount in flight", attack_mitm_modify_amount),
    "mitm-key-substitution": (
        "MITM swaps the ClientHello ephemeral key",
        attack_mitm_key_substitution,
    ),
    "impersonate-switch": (
        "Rogue switch presents an untrusted certificate",
        attack_impersonate_switch,
    ),
    "revoked-certificate": (
        "Revoked merchant certificate tries to connect",
        attack_revoked_certificate,
    ),
    "expired-certificate": (
        "Expired merchant certificate tries to connect",
        attack_expired_certificate,
    ),
    "downgrade": ("Offer an old protocol version / weak suite", attack_downgrade),
    "vault-bruteforce": (
        "Brute-force the wallet passphrase until lockout",
        attack_vault_bruteforce,
    ),
    "malformed-frame": (
        "Oversized, zero-length, truncated, garbage frames",
        attack_malformed_frame,
    ),
    "double-spend": ("Duplicate txn_id on request and authorisation", attack_double_spend),
}


def run_case(name: str, *, fast: bool = True) -> CaseResult:
    if name not in CASES:
        raise KeyError(f"unknown attack {name!r}; available: {', '.join(CASES)}")
    _description, case = CASES[name]
    logger.info("event=attack_start name=%s", name)
    lab = Lab(fast=fast)
    try:
        try:
            passed, detail = case(lab)
            result = CaseResult(name, passed, detail)
        except Exception as exc:
            result = CaseResult(name, False, f"harness error: {exc!r}")
    finally:
        lab.stop()
    _log_result(result)
    return result


def _log_result(result: CaseResult) -> None:
    if result.detail.startswith("harness error"):
        status = "error"
    else:
        status = "blocked" if result.passed else "not_blocked"
    logger.log(
        result_level(result.name, result.passed, result.detail),
        "event=attack_%s name=%s property=%s impact=%s detail=%s",
        status,
        result.name,
        _PROPERTY.get(result.name, "unknown"),
        "high" if result.name in HIGH_IMPACT else "standard",
        " ".join(result.detail.split())[:300],
    )


def run_all(*, fast: bool = True) -> list[CaseResult]:
    return [run_case(name, fast=fast) for name in CASES]
