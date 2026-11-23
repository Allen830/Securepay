from __future__ import annotations

import socket

from securepay import config
from securepay.errors import FramingError

__all__ = ["recv_exact", "recv_frame", "send_frame"]


def _wrap_transport_error(exc: Exception) -> FramingError:
    if isinstance(exc, TimeoutError | socket.timeout):
        return FramingError("frame transport timeout", detail=repr(exc))
    return FramingError("frame transport failure", detail=repr(exc))


def send_frame(sock: socket.socket, payload: bytes) -> None:
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise FramingError("frame payload must be bytes")
    if len(payload) > config.MAX_FRAME_BYTES:
        raise FramingError(
            f"frame of {len(payload)} bytes exceeds MAX_FRAME_BYTES",
        )
    if len(payload) == 0:
        raise FramingError("empty frames are not valid")
    frame_bytes = len(payload).to_bytes(config.FRAME_HEADER_BYTES, "big") + bytes(payload)
    try:
        sock.sendall(frame_bytes)
    except OSError as exc:
        raise _wrap_transport_error(exc) from exc


def recv_exact(sock: socket.socket, count: int) -> bytes:
    if count < 0:
        raise FramingError("negative read count")
    received_chunks: list[bytes] = []
    bytes_remaining = count
    while bytes_remaining > 0:
        try:
            chunk = sock.recv(min(bytes_remaining, 65536))
        except OSError as exc:
            raise _wrap_transport_error(exc) from exc
        if not chunk:
            raise FramingError(f"connection closed with {bytes_remaining} bytes still expected")
        received_chunks.append(chunk)
        bytes_remaining -= len(chunk)
    return b"".join(received_chunks)


def recv_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, config.FRAME_HEADER_BYTES)
    payload_length = int.from_bytes(header, "big")
    if payload_length == 0:
        raise FramingError("zero-length frame")
    if payload_length > config.MAX_FRAME_BYTES:
        raise FramingError(f"peer advertised {payload_length} bytes, exceeding MAX_FRAME_BYTES")
    return recv_exact(sock, payload_length)
