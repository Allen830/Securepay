from __future__ import annotations

import contextlib
import logging
import socket
import threading
from collections.abc import Callable

from securepay import config

logger = logging.getLogger(__name__)

__all__ = ["MITMProxy", "parse_frames_from_buffer", "reframe"]

FrameHook = Callable[[int, bytes], "bytes | list[bytes] | None"]


def reframe(payload: bytes) -> bytes:
    return len(payload).to_bytes(config.FRAME_HEADER_BYTES, "big") + payload


def parse_frames_from_buffer(buffer: bytes) -> tuple[list[bytes], bytes]:
    frames: list[bytes] = []
    offset = 0
    while len(buffer) - offset >= config.FRAME_HEADER_BYTES:
        length = int.from_bytes(buffer[offset : offset + config.FRAME_HEADER_BYTES], "big")
        end = offset + config.FRAME_HEADER_BYTES + length
        if length == 0 or length > config.MAX_FRAME_BYTES:
            break
        if len(buffer) < end:
            break
        frames.append(buffer[offset:end])
        offset = end
    return frames, buffer[offset:]


class MITMProxy:

    def __init__(
        self,
        target_host: str,
        target_port: int,
        *,
        on_client_frame: FrameHook | None = None,
        on_server_frame: FrameHook | None = None,
        record: bool = False,
    ) -> None:
        self._target = (target_host, target_port)
        self._on_client_frame = on_client_frame
        self._on_server_frame = on_server_frame
        self._record = record
        self.client_frames: list[bytes] = []
        self.server_frames: list[bytes] = []
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind((config.DEFAULT_HOST, 0))
        self._listen.listen(4)
        self._listen.settimeout(0.2)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    @property
    def host(self) -> str:
        return self._listen.getsockname()[0]

    @property
    def port(self) -> int:
        return int(self._listen.getsockname()[1])

    def start(self) -> None:
        thread = threading.Thread(target=self._accept_loop, name="mitm-accept", daemon=True)
        thread.start()
        self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listen.close()
        for thread in self._threads:
            thread.join(timeout=1.0)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                victim_sock, _addr = self._listen.accept()
            except (TimeoutError, OSError):
                continue
            try:
                switch_sock = socket.create_connection(self._target, timeout=5.0)
            except OSError:
                victim_sock.close()
                continue
            self._pump(victim_sock, switch_sock, self._on_client_frame, self.client_frames)
            self._pump(switch_sock, victim_sock, self._on_server_frame, self.server_frames)

    def _pump(
        self,
        source: socket.socket,
        sink: socket.socket,
        hook: FrameHook | None,
        record: list[bytes],
    ) -> None:

        def run() -> None:
            index = 0
            buffer = b""
            try:
                source.settimeout(0.2)
                while not self._stop.is_set():
                    try:
                        chunk = source.recv(65536)
                    except TimeoutError:
                        continue
                    if not chunk:
                        break
                    buffer += chunk
                    frames, buffer = parse_frames_from_buffer(buffer)
                    for frame in frames:
                        index += 1
                        if self._record:
                            record.append(frame)
                        if hook is None:
                            sink.sendall(frame)
                            continue
                        result = hook(index, frame)
                        if result is None:
                            logger.info("event=mitm_drop frame=%d", index)
                            continue
                        outputs = result if isinstance(result, list) else [result]
                        for out in outputs:
                            logger.info("event=mitm_forward frame=%d bytes=%d", index, len(out))
                            sink.sendall(out)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    sink.shutdown(socket.SHUT_WR)

        thread = threading.Thread(target=run, daemon=True, name="mitm-pump")
        thread.start()
        self._threads.append(thread)
