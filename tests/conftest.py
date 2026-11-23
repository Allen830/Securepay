from __future__ import annotations

import socket
import threading
from collections.abc import Iterator

import pytest

from securepay import config
from securepay.attacks.simulator import Lab, fast_kdf
from securepay.channel import Channel
from securepay.handshake import (
    HandshakeIdentity,
    HandshakeResult,
    TrustAnchor,
    run_client_handshake,
    run_server_handshake,
)
from securepay.pki import create_ca, generate_signing_key, issue_certificate


@pytest.fixture
def fast_kdf_ctx() -> Iterator[None]:
    with fast_kdf():
        yield


@pytest.fixture
def lab(fast_kdf_ctx: None) -> Iterator[Lab]:
    lab = Lab(fast=True)
    yield lab
    lab.stop()


def _handshake_pair_with_sockets() -> tuple[
    HandshakeResult, HandshakeResult, socket.socket, socket.socket
]:
    ca_key = generate_signing_key()
    ca_cert = create_ca(ca_key)
    client_key = generate_signing_key()
    client_cert = issue_certificate(ca_key, ca_cert, "alice", "student", client_key.verify_key)
    server_key = generate_signing_key()
    server_cert = issue_certificate(ca_key, ca_cert, "bob", "switch", server_key.verify_key)
    listener = socket.socket()
    listener.bind((config.DEFAULT_HOST, 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    server_out: dict[str, object] = {}

    def server_thread() -> None:
        sock, _ = listener.accept()
        try:
            identity = HandshakeIdentity("bob", "switch", server_key, server_cert)
            anchor = TrustAnchor(
                ca_cert=ca_cert,
                crl_provider=lambda: None,
                expected_peer_id="alice",
                expected_peer_role="student",
            )
            server_out["result"] = run_server_handshake(sock, identity, anchor)
            server_out["sock"] = sock
        except Exception as exc:
            server_out["error"] = exc
            sock.close()

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    csock = socket.create_connection((config.DEFAULT_HOST, port), timeout=5.0)
    client_identity = HandshakeIdentity("alice", "student", client_key, client_cert)
    client_anchor = TrustAnchor(
        ca_cert=ca_cert,
        crl_provider=lambda: None,
        expected_peer_id="bob",
        expected_peer_role="switch",
    )
    client_result = run_client_handshake(csock, client_identity, client_anchor)
    thread.join(timeout=5.0)
    listener.close()
    if "error" in server_out:
        raise server_out["error"]
    server_result = server_out["result"]
    ssock = server_out["sock"]
    assert isinstance(server_result, HandshakeResult)
    assert isinstance(ssock, socket.socket)
    return client_result, server_result, csock, ssock


class ChannelPair:

    def __init__(self) -> None:
        (
            self.client_result,
            self.server_result,
            self.csock,
            self.ssock,
        ) = _handshake_pair_with_sockets()
        self.client = Channel(self.csock, "client", self.client_result.secrets)
        self.server = Channel(self.ssock, "server", self.server_result.secrets)

    def close(self) -> None:
        self.client.close()
        self.server.close()
        self.csock.close()
        self.ssock.close()


@pytest.fixture
def channel_pair() -> Iterator[ChannelPair]:
    pair = ChannelPair()
    yield pair
    pair.close()
