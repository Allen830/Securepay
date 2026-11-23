from __future__ import annotations

import socket

import pytest

from securepay import config
from securepay.errors import FramingError
from securepay.framing import recv_frame, send_frame


def _socketpair() -> tuple[socket.socket, socket.socket]:
    listener = socket.socket()
    listener.bind((config.DEFAULT_HOST, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    client = socket.create_connection((config.DEFAULT_HOST, port), timeout=5.0)
    server, _ = listener.accept()
    listener.close()
    return client, server


def test_roundtrip() -> None:
    a, b = _socketpair()
    try:
        send_frame(a, b"hello frame")
        assert recv_frame(b) == b"hello frame"
    finally:
        a.close()
        b.close()


def test_merged_frames_are_split_correctly() -> None:
    a, b = _socketpair()
    try:
        wire = (5).to_bytes(4, "big") + b"first" + (7).to_bytes(4, "big") + b"second!"
        a.sendall(wire)
        assert recv_frame(b) == b"first"
        assert recv_frame(b) == b"second!"
    finally:
        a.close()
        b.close()


def test_dribbled_frame_reassembled() -> None:
    a, b = _socketpair()
    try:
        b.settimeout(5.0)
        frame = (4).to_bytes(4, "big") + b"ABCD"
        for byte in frame:
            a.sendall(bytes([byte]))
        assert recv_frame(b) == b"ABCD"
    finally:
        a.close()
        b.close()


def test_oversized_frame_rejected_before_reading() -> None:
    a, b = _socketpair()
    try:
        a.sendall((config.MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
        with pytest.raises(FramingError):
            recv_frame(b)
    finally:
        a.close()
        b.close()


def test_empty_frame_rejected() -> None:
    a, b = _socketpair()
    try:
        a.sendall((0).to_bytes(4, "big"))
        with pytest.raises(FramingError):
            recv_frame(b)
    finally:
        a.close()
        b.close()


def test_truncated_frame_raises() -> None:
    a, b = _socketpair()
    try:
        a.sendall((100).to_bytes(4, "big") + b"only-a-few")
        a.close()
        with pytest.raises(FramingError):
            recv_frame(b)
    finally:
        b.close()


def test_send_frame_rejects_oversized_payload() -> None:
    a, b = _socketpair()
    try:
        with pytest.raises(FramingError):
            send_frame(a, b"x" * (config.MAX_FRAME_BYTES + 1))
    finally:
        a.close()
        b.close()


def test_connection_close_raises_not_hangs() -> None:
    a, b = _socketpair()
    b.settimeout(5.0)
    a.close()
    with pytest.raises(FramingError):
        recv_frame(b)
    b.close()
