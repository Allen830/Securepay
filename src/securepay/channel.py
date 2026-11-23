from __future__ import annotations

import json
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Literal

from nacl import bindings as sodium
from nacl.exceptions import CryptoError

from securepay import config
from securepay.encoding import (
    b64_decode,
    b64_encode,
    canonical_bytes,
    now_ts,
    parse_u32be,
    sha256_hex,
    u32be,
)
from securepay.errors import (
    ChannelError,
    CounterExhaustedError,
    DecryptError,
    EpochError,
    RekeyError,
    ReorderError,
    ReplayError,
    StaleFrameError,
)
from securepay.framing import recv_frame, send_frame
from securepay.handshake import (
    SessionSecrets,
    hkdf_expand,
    hkdf_extract,
    x25519_ephemeral,
    x25519_shared,
)
from securepay.keystore import zeroise

logger = logging.getLogger(__name__)

__all__ = ["Channel", "ParsedFrame", "open_frame", "parse_frame_payload", "seal_frame"]

Direction = Literal["c2s", "s2c"]
Role = Literal["client", "server"]

_LABEL_EPOCH_C2S_KEY = b"SP1/epoch/%d/c2s key"
_LABEL_EPOCH_S2C_KEY = b"SP1/epoch/%d/s2c key"
_LABEL_EPOCH_C2S_NONCE = b"SP1/epoch/%d/c2s nonce"
_LABEL_EPOCH_S2C_NONCE = b"SP1/epoch/%d/s2c nonce"

MSG_REKEY = "rekey"
MSG_REKEY_ACK = "rekey_ack"

MAX_HEADER_BYTES = 256


@dataclass(frozen=True)
class ParsedFrame:

    header: dict[str, object]
    header_bytes: bytes
    ciphertext: bytes


def seal_frame(
    key: bytes | bytearray,
    nonce_prefix: bytes | bytearray,
    session_id: str,
    direction: Direction,
    epoch: int,
    counter: int,
    ts: int,
    plaintext: bytes,
) -> bytes:
    header = {"dir": direction, "ep": epoch, "n": counter, "sid": session_id, "ts": ts}
    header_bytes = canonical_bytes(header)
    nonce = bytes(nonce_prefix) + counter.to_bytes(config.NONCE_COUNTER_BYTES, "big")
    ciphertext = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
        plaintext, header_bytes, nonce, bytes(key)
    )
    return u32be(len(header_bytes)) + header_bytes + ciphertext


def parse_frame_payload(payload: bytes) -> ParsedFrame:
    if len(payload) < 5:
        raise ChannelError("channel frame too short")
    header_len = parse_u32be(payload[: config.FRAME_HEADER_BYTES])
    if not 0 < header_len <= MAX_HEADER_BYTES:
        raise ChannelError("channel frame header length out of bounds")
    header_bytes = payload[4 : 4 + header_len]
    ciphertext = payload[4 + header_len :]
    if len(header_bytes) != header_len or not ciphertext:
        raise ChannelError("channel frame is truncated")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ChannelError("channel frame header is not valid JSON") from exc
    if not isinstance(header, dict):
        raise ChannelError("channel frame header is not an object")
    if canonical_bytes(header) != header_bytes:
        raise ChannelError("channel frame header is not canonical")
    for field_name in ("dir", "ep", "n", "sid", "ts"):
        if field_name not in header:
            raise ChannelError(f"channel frame header missing {field_name}")
    if header["dir"] not in ("c2s", "s2c"):
        raise ChannelError("channel frame direction invalid")
    if (
        not isinstance(header["ep"], int)
        or not isinstance(header["n"], int)
        or not isinstance(header["ts"], int)
    ):
        raise ChannelError("channel frame header field types invalid")
    if not isinstance(header["sid"], str):
        raise ChannelError("channel frame header field types invalid")
    return ParsedFrame(header=header, header_bytes=header_bytes, ciphertext=ciphertext)


def open_frame(
    key: bytes | bytearray,
    nonce_prefix: bytes | bytearray,
    parsed: ParsedFrame,
) -> bytes:
    counter = int(parsed.header["n"])
    nonce = bytes(nonce_prefix) + counter.to_bytes(config.NONCE_COUNTER_BYTES, "big")
    try:
        return sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            parsed.ciphertext, parsed.header_bytes, nonce, bytes(key)
        )
    except CryptoError as exc:
        raise DecryptError("AEAD authentication failed (tampered frame)") from exc


class Channel:

    def __init__(
        self,
        sock: object,
        role: Role,
        secrets: SessionSecrets,
        *,
        io_timeout: float = config.IO_TIMEOUT,
    ) -> None:
        self._sock = sock
        self._role: Role = role
        self._io_timeout = io_timeout
        self.session_id = secrets.session_id
        self._prk = bytearray(secrets.prk)
        self._th_final = secrets.th_final
        self.epoch = 1
        self._send_key = bytearray()
        self._recv_key = bytearray()
        self._send_prefix = bytearray()
        self._recv_prefix = bytearray()
        self._install_direction_keys(
            secrets.c2s_key, secrets.s2c_key, secrets.c2s_nonce_prefix, secrets.s2c_nonce_prefix
        )
        self._send_counter = 1
        self._recv_counter = 1
        self._messages_in_epoch = 0
        self._epoch_started = time.monotonic()
        self._inbox: deque[dict[str, object]] = deque()
        self._pending_rekey: dict[str, object] | None = None
        self._send_lock = threading.Lock()
        self._closed = False


    @property
    def _my_direction(self) -> Direction:
        return "c2s" if self._role == "client" else "s2c"

    @property
    def _peer_direction(self) -> Direction:
        return "s2c" if self._role == "client" else "c2s"

    def _install_direction_keys(
        self,
        c2s_key: bytes | bytearray,
        s2c_key: bytes | bytearray,
        c2s_prefix: bytes | bytearray,
        s2c_prefix: bytes | bytearray,
    ) -> None:
        if self._role == "client":
            self._send_key = bytearray(c2s_key)
            self._recv_key = bytearray(s2c_key)
            self._send_prefix = bytearray(c2s_prefix)
            self._recv_prefix = bytearray(s2c_prefix)
        else:
            self._send_key = bytearray(s2c_key)
            self._recv_key = bytearray(c2s_key)
            self._send_prefix = bytearray(s2c_prefix)
            self._recv_prefix = bytearray(c2s_prefix)

    def key_fingerprint(self) -> str:
        return sha256_hex(bytes(self._send_key))[:8]


    @property
    def messages_in_epoch(self) -> int:
        return self._messages_in_epoch

    def send(self, message: dict[str, object]) -> None:
        with self._send_lock:
            if self._closed:
                raise ChannelError("channel is closed")
            self._maybe_rekey()
            self._send_plain(canonical_bytes(message))

    def recv(self, timeout: float | None = None) -> dict[str, object]:
        if self._inbox:
            return self._inbox.popleft()
        while True:
            message = self._recv_one(timeout)
            msg_type = message.get("type")
            if msg_type == MSG_REKEY:
                self._handle_rekey(message)
                continue
            if msg_type == MSG_REKEY_ACK:
                raise ChannelError("rekey_ack received outside a pending rekey")
            return message

    def close(self) -> None:
        self._closed = True
        zeroise(self._send_key)
        zeroise(self._recv_key)
        zeroise(self._send_prefix)
        zeroise(self._recv_prefix)
        zeroise(self._prk)
        if self._pending_rekey is not None:
            eph_priv = self._pending_rekey.get("eph_priv")
            if isinstance(eph_priv, bytes):
                zeroise(bytearray(eph_priv))
            self._pending_rekey = None
        logger.info("event=channel_closed session=%s", self.session_id[:12])


    def _send_plain(self, plaintext: bytes) -> None:
        if self._send_counter > config.MAX_COUNTER:
            raise CounterExhaustedError("per-direction counter exhausted; rekey required")
        frame = seal_frame(
            self._send_key,
            self._send_prefix,
            self.session_id,
            self._my_direction,
            self.epoch,
            self._send_counter,
            now_ts(),
            plaintext,
        )
        send_frame(self._sock, frame)
        self._send_counter += 1
        self._messages_in_epoch += 1

    def _recv_one(self, timeout: float | None) -> dict[str, object]:
        self._sock.settimeout(self._io_timeout if timeout is None else timeout)
        payload = recv_frame(self._sock)
        parsed = parse_frame_payload(payload)

        if parsed.header["sid"] != self.session_id:
            raise ChannelError("frame belongs to a different session")
        if parsed.header["dir"] != self._peer_direction:
            raise ChannelError("frame direction does not match peer role")
        if parsed.header["ep"] != self.epoch:
            raise EpochError(
                f"frame epoch {parsed.header['ep']} does not match current {self.epoch}"
            )

        counter = int(parsed.header["n"])
        if counter < self._recv_counter:
            raise ReplayError(f"counter {counter} already consumed")
        if counter > self._recv_counter:
            raise ReorderError(f"expected counter {self._recv_counter}, got {counter}")

        ts = int(parsed.header["ts"])
        if abs(now_ts() - ts) > config.MAX_CLOCK_SKEW_SECONDS:
            raise StaleFrameError("frame timestamp outside freshness window")

        plaintext = open_frame(self._recv_key, self._recv_prefix, parsed)
        try:
            message = json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChannelError("decrypted payload is not valid JSON") from exc
        if not isinstance(message, dict):
            raise ChannelError("decrypted payload is not a JSON object")

        self._recv_counter += 1
        self._messages_in_epoch += 1
        return message


    def _maybe_rekey(self) -> None:
        if self._role != "client" or self._pending_rekey is not None:
            return
        reasons = 0
        if self._messages_in_epoch >= config.REKEY_AFTER_MESSAGES:
            reasons = config.REKEY_AFTER_MESSAGES
        elif time.monotonic() - self._epoch_started >= config.REKEY_AFTER_SECONDS:
            reasons = -1
        if not reasons:
            return
        eph_priv, eph_pub = x25519_ephemeral()
        self._pending_rekey = {
            "new_epoch": self.epoch + 1,
            "eph_priv": eph_priv,
        }
        logger.info(
            "event=rekey_started session=%s from_epoch=%d trigger=%s",
            self.session_id[:12],
            self.epoch,
            "messages" if reasons > 0 else "age",
        )
        self._send_plain(
            canonical_bytes(
                {
                    "type": MSG_REKEY,
                    "v": config.PROTOCOL_VERSION,
                    "epoch": self.epoch + 1,
                    "eph": b64_encode(eph_pub),
                }
            )
        )
        self._await_rekey_ack()

    def _await_rekey_ack(self) -> None:
        if self._pending_rekey is None:
            raise RekeyError("rekey ack awaited without a pending rekey")
        deadline = time.monotonic() + config.REKEY_TIMEOUT
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RekeyError("rekey acknowledgement timed out")
            message = self._recv_one(timeout=remaining)
            if message.get("type") != MSG_REKEY_ACK:
                self._inbox.append(message)
                continue
            expected_epoch = int(self._pending_rekey["new_epoch"])
            if message.get("epoch") != expected_epoch:
                raise RekeyError("rekey_ack has wrong epoch")
            eph_pub = b64_decode(str(message.get("eph", "")))
            if len(eph_pub) != 32:
                raise RekeyError("rekey_ack ephemeral key malformed")
            shared = x25519_shared(
                bytes(self._pending_rekey["eph_priv"]),
                eph_pub,
            )
            self._install_epoch(expected_epoch, shared)
            return

    def _handle_rekey(self, message: dict[str, object]) -> None:
        if self._role != "server":
            raise ChannelError("rekey message sent by the wrong peer role")
        new_epoch = message.get("epoch")
        if not isinstance(new_epoch, int) or new_epoch != self.epoch + 1:
            raise RekeyError("rekey proposes an invalid epoch")
        eph_pub = b64_decode(str(message.get("eph", "")))
        if len(eph_pub) != 32:
            raise RekeyError("rekey ephemeral key malformed")
        eph_priv, our_eph_pub = x25519_ephemeral()
        shared = x25519_shared(eph_priv, eph_pub)
        with self._send_lock:
            self._send_plain(
                canonical_bytes(
                    {
                        "type": MSG_REKEY_ACK,
                        "v": config.PROTOCOL_VERSION,
                        "epoch": new_epoch,
                        "eph": b64_encode(our_eph_pub),
                    }
                )
            )
            zeroise(bytearray(eph_priv))
            self._install_epoch(new_epoch, shared)
        logger.info(
            "event=rekey_complete side=server session=%s epoch=%d",
            self.session_id[:12],
            new_epoch,
        )

    def _install_epoch(self, new_epoch: int, shared: bytes) -> None:
        prk_new = bytearray(hkdf_extract(bytes(self._prk), shared))
        c2s_key = hkdf_expand(
            bytes(prk_new), self._th_final + _LABEL_EPOCH_C2S_KEY % new_epoch, config.KEY_BYTES
        )
        s2c_key = hkdf_expand(
            bytes(prk_new), self._th_final + _LABEL_EPOCH_S2C_KEY % new_epoch, config.KEY_BYTES
        )
        c2s_prefix = hkdf_expand(
            bytes(prk_new),
            self._th_final + _LABEL_EPOCH_C2S_NONCE % new_epoch,
            config.NONCE_PREFIX_BYTES,
        )
        s2c_prefix = hkdf_expand(
            bytes(prk_new),
            self._th_final + _LABEL_EPOCH_S2C_NONCE % new_epoch,
            config.NONCE_PREFIX_BYTES,
        )
        zeroise(self._send_key)
        zeroise(self._recv_key)
        zeroise(self._send_prefix)
        zeroise(self._recv_prefix)
        zeroise(self._prk)
        self._prk = prk_new
        self._install_direction_keys(c2s_key, s2c_key, c2s_prefix, s2c_prefix)
        self.epoch = new_epoch
        self._send_counter = 1
        self._recv_counter = 1
        self._messages_in_epoch = 0
        self._epoch_started = time.monotonic()
        self._pending_rekey = None
        logger.info(
            "event=rekey_complete side=%s session=%s epoch=%d key_fp=%s",
            self._role,
            self.session_id[:12],
            new_epoch,
            self.key_fingerprint(),
        )
