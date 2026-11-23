from __future__ import annotations

import json
import threading

import pytest

from securepay import config
from securepay.channel import open_frame, parse_frame_payload, seal_frame
from securepay.encoding import canonical_bytes, now_ts
from securepay.errors import (
    ChannelError,
    DecryptError,
    ReorderError,
    ReplayError,
    StaleFrameError,
)
from securepay.framing import send_frame
from tests.conftest import ChannelPair


def test_roundtrip_both_directions(channel_pair: ChannelPair) -> None:
    channel_pair.client.send({"type": "ping", "v": 1})
    assert channel_pair.server.recv() == {"type": "ping", "v": 1}
    channel_pair.server.send({"type": "pong", "v": 1})
    assert channel_pair.client.recv() == {"type": "pong", "v": 1}


def test_seal_and_parse_frame_primitives() -> None:
    frame = seal_frame(b"k" * 32, b"np" * 2, "ab" * 16, "c2s", 1, 7, 1000, b"payload")
    parsed = parse_frame_payload(frame)
    assert parsed.header == {"dir": "c2s", "ep": 1, "n": 7, "sid": "ab" * 16, "ts": 1000}
    plaintext = open_frame(b"k" * 32, b"np" * 2, parsed)
    assert plaintext == b"payload"


def test_parse_rejects_non_canonical_header() -> None:
    header = {"dir": "c2s", "ep": 1, "n": 1, "sid": "ab" * 16, "ts": 1}
    raw = json.dumps(header, sort_keys=False).encode()
    frame = len(raw).to_bytes(4, "big") + raw + b"ct"
    with pytest.raises(ChannelError):
        parse_frame_payload(frame)


def _start_responder(channel: object) -> list[dict[str, object]]:
    received: list[dict[str, object]] = []

    def loop() -> None:
        try:
            while True:
                message = channel.recv(timeout=15.0)
                received.append(message)
                channel.send({"type": "pong", "v": 1, "i": message.get("i")})
        except Exception:
            return

    threading.Thread(target=loop, daemon=True).start()
    return received


def test_bit_flip_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    payload = canonical_bytes({"type": "ping", "v": 1})
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        pair.client._send_counter,
        now_ts(),
        payload,
    )
    header_len = int.from_bytes(frame[:4], "big")
    ciphertext = bytearray(frame[4 + header_len :])
    ciphertext[3] ^= 0x01
    tampered = frame[: 4 + header_len] + bytes(ciphertext)
    send_frame(pair.csock, tampered)
    with pytest.raises(DecryptError):
        pair.server.recv(timeout=5.0)


def test_replay_same_frame_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    payload = canonical_bytes({"type": "ping", "v": 1})
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        pair.client._send_counter,
        now_ts(),
        payload,
    )
    send_frame(pair.csock, frame)
    assert pair.server.recv(timeout=5.0) == {"type": "ping", "v": 1}
    send_frame(pair.csock, frame)
    with pytest.raises((ReplayError, ChannelError)):
        pair.server.recv(timeout=5.0)


def test_reorder_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    frame1 = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        1,
        now_ts(),
        canonical_bytes({"type": "a", "v": 1}),
    )
    frame2 = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        2,
        now_ts(),
        canonical_bytes({"type": "b", "v": 1}),
    )
    send_frame(pair.csock, frame2)
    with pytest.raises((ReorderError, ChannelError)):
        pair.server.recv(timeout=5.0)
    send_frame(pair.csock, frame1)
    assert pair.server.recv(timeout=5.0) == {"type": "a", "v": 1}
    send_frame(pair.csock, frame1)
    with pytest.raises((ReplayError, ChannelError)):
        pair.server.recv(timeout=5.0)


def test_stale_timestamp_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        pair.client._send_counter,
        now_ts() - 10 * 365 * 24 * 3600,
        canonical_bytes({"type": "ping", "v": 1}),
    )
    send_frame(pair.csock, frame)
    with pytest.raises((StaleFrameError, ChannelError)):
        pair.server.recv(timeout=5.0)


def test_wrong_session_id_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        "ff" * 16,
        "c2s",
        1,
        pair.client._send_counter,
        now_ts(),
        canonical_bytes({"type": "ping", "v": 1}),
    )
    send_frame(pair.csock, frame)
    with pytest.raises(ChannelError):
        pair.server.recv(timeout=5.0)


def test_aad_header_timestamp_tamper_rejected(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    payload = canonical_bytes({"type": "ping", "v": 1})
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        pair.client._send_counter,
        now_ts(),
        payload,
    )
    header_len = int.from_bytes(frame[:4], "big")
    header = json.loads(frame[4 : 4 + header_len])
    header["ts"] += 1
    new_header = canonical_bytes(header)
    tampered = len(new_header).to_bytes(4, "big") + new_header + frame[4 + header_len :]
    send_frame(pair.csock, tampered)
    with pytest.raises((DecryptError, ChannelError)):
        pair.server.recv(timeout=5.0)


def test_automatic_rekey_rotates_keys(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    seen = _start_responder(pair.server)
    with config.temporary(REKEY_AFTER_MESSAGES=3):
        for i in range(10):
            pair.client.send({"type": "ping", "v": 1, "i": i})
            assert pair.client.recv(timeout=5.0) == {"type": "pong", "v": 1, "i": i}
        assert len(seen) == 10
        assert pair.client.epoch >= 2
        assert pair.server.epoch == pair.client.epoch
    frame = seal_frame(
        pair.client._send_key,
        pair.client._send_prefix,
        pair.client.session_id,
        "c2s",
        1,
        1,
        now_ts(),
        canonical_bytes({"type": "stale", "v": 1}),
    )
    parsed = parse_frame_payload(frame)
    assert int(parsed.header["ep"]) == 1
    assert pair.server.epoch > 1


def test_rekey_changes_key_fingerprint(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    before = pair.client.key_fingerprint()
    _start_responder(pair.server)
    with config.temporary(REKEY_AFTER_MESSAGES=2):
        for i in range(6):
            pair.client.send({"type": "ping", "v": 1, "i": i})
            assert pair.client.recv(timeout=5.0) == {"type": "pong", "v": 1, "i": i}
    assert pair.client.key_fingerprint() != before


def test_counter_exhaustion_guard() -> None:
    pair = ChannelPair()
    try:
        pair.client._send_counter = config.MAX_COUNTER + 1
        with pytest.raises(ChannelError):
            pair.client.send({"type": "ping", "v": 1})
    finally:
        pair.close()


def test_close_zeroises_keys(channel_pair: ChannelPair) -> None:
    pair = channel_pair
    pair.client.close()
    assert bytes(pair.client._send_key) == b"\x00" * 32
    assert bytes(pair.client._recv_key) == b"\x00" * 32
    with pytest.raises(ChannelError):
        pair.client.send({"type": "ping", "v": 1})


def test_server_rekey_holds_send_lock(channel_pair: ChannelPair) -> None:
    import inspect

    from securepay.channel import Channel

    source = inspect.getsource(Channel._handle_rekey)
    assert "with self._send_lock" in source
