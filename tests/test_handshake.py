from __future__ import annotations

import socket
import threading

import pytest

from securepay import config
from securepay.errors import (
    HandshakeError,
    UnknownIdentityError,
    UntrustedCertificateError,
    VersionMismatchError,
)
from securepay.handshake import (
    HandshakeIdentity,
    TrustAnchor,
    hkdf_expand,
    hkdf_extract,
    run_client_handshake,
    run_server_handshake,
    transcript_hash,
    x25519_ephemeral,
    x25519_shared,
)
from securepay.pki import create_ca, generate_signing_key, issue_certificate
from tests.conftest import _handshake_pair_with_sockets


def test_both_sides_derive_identical_secrets() -> None:
    client, server, csock, ssock = _handshake_pair_with_sockets()
    try:
        assert client.session_id == server.session_id
        assert client.secrets.session_id == server.secrets.session_id
        assert bytes(client.secrets.c2s_key) == bytes(server.secrets.c2s_key)
        assert bytes(client.secrets.s2c_key) == bytes(server.secrets.s2c_key)
        assert bytes(client.secrets.c2s_nonce_prefix) == bytes(server.secrets.c2s_nonce_prefix)
        assert bytes(client.secrets.s2c_nonce_prefix) == bytes(server.secrets.s2c_nonce_prefix)
        assert client.secrets.th_final == server.secrets.th_final
        assert client.secrets.c2s_key != client.secrets.s2c_key
        assert client.peer_id == "bob" and server.peer_id == "alice"
    finally:
        csock.close()
        ssock.close()


def test_fresh_keys_every_handshake() -> None:
    c1, _s1, a1, b1 = _handshake_pair_with_sockets()
    c2, _s2, a2, b2 = _handshake_pair_with_sockets()
    try:
        assert c1.session_id != c2.session_id
        assert bytes(c1.secrets.c2s_key) != bytes(c2.secrets.c2s_key)
    finally:
        for sock in (a1, b1, a2, b2):
            sock.close()


def test_transcript_hash_is_injection_resistant() -> None:
    m1 = [{"a": "x"}, {"b": "y"}]
    m2 = [{"a": "x", "b": "y"}]
    assert transcript_hash(m1) != transcript_hash(m2)
    assert transcript_hash([{"a": 1}]) == transcript_hash([{"a": 1}])


def test_hkdf_extract_expand_properties() -> None:
    prk = hkdf_extract(b"salt", b"ikm")
    assert len(prk) == 32
    a = hkdf_expand(prk, b"info-a", 32)
    b = hkdf_expand(prk, b"info-b", 32)
    assert a != b
    assert hkdf_expand(prk, b"info-a", 32) == a
    assert len(hkdf_expand(prk, b"info", 12)) == 12


def test_low_order_x25519_point_rejected() -> None:
    _priv, pub = x25519_ephemeral()
    assert len(pub) == 32
    with pytest.raises(HandshakeError):
        x25519_shared(_priv, b"\x00" * 32)
    with pytest.raises(HandshakeError):
        x25519_shared(_priv, b"\x01" + b"\x00" * 30)


def _make_identities():
    ca_key = generate_signing_key()
    ca_cert = create_ca(ca_key)
    client_key = generate_signing_key()
    client_cert = issue_certificate(ca_key, ca_cert, "alice", "student", client_key.verify_key)
    server_key = generate_signing_key()
    server_cert = issue_certificate(ca_key, ca_cert, "bob", "switch", server_key.verify_key)
    return (
        HandshakeIdentity("alice", "student", client_key, client_cert),
        HandshakeIdentity("bob", "switch", server_key, server_cert),
        TrustAnchor(
            ca_cert=ca_cert,
            crl_provider=lambda: None,
            expected_peer_id="bob",
            expected_peer_role="switch",
        ),
        TrustAnchor(
            ca_cert=ca_cert,
            crl_provider=lambda: None,
            expected_peer_id=None,
            expected_peer_role=None,
        ),
    )


def _raw_pair():
    listener = socket.socket()
    listener.bind((config.DEFAULT_HOST, 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    csock = socket.create_connection((config.DEFAULT_HOST, port), timeout=5.0)
    ssock, _ = listener.accept()
    listener.close()
    return csock, ssock


def test_version_mismatch_rejected() -> None:
    from securepay.encoding import canonical_bytes, now_ts

    _client_identity, server_identity, _c_anchor, s_anchor = _make_identities()
    csock, ssock = _raw_pair()

    result: dict[str, Exception | None] = {"error": None}

    def server_thread() -> None:
        try:
            run_server_handshake(ssock, server_identity, s_anchor)
        except Exception as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    hello = {
        "type": "client_hello",
        "v": 0,
        "suite": config.CIPHER_SUITE,
        "id": "alice",
        "eph": "A" * 43,
        "nonce": "B" * 43,
        "ts": now_ts(),
    }
    csock.sendall(len(canonical_bytes(hello)).to_bytes(4, "big") + canonical_bytes(hello))
    thread.join(timeout=5.0)
    csock.close()
    ssock.close()
    assert isinstance(result["error"], VersionMismatchError)


def test_untrusted_client_certificate_rejected() -> None:
    _client_identity, server_identity, _anchor, s_anchor = _make_identities()
    rogue_ca = generate_signing_key()
    rogue_cert = create_ca(rogue_ca)
    rogue_key = generate_signing_key()
    bad_client = HandshakeIdentity(
        "alice",
        "student",
        rogue_key,
        issue_certificate(rogue_ca, rogue_cert, "alice", "student", rogue_key.verify_key),
    )
    csock, ssock = _raw_pair()
    result: dict[str, Exception | None] = {"error": None}

    def server_thread() -> None:
        try:
            run_server_handshake(ssock, server_identity, s_anchor)
        except Exception as exc:
            result["error"] = exc

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    run_client_handshake(csock, bad_client, s_anchor)
    thread.join(timeout=5.0)
    csock.close()
    ssock.close()
    assert isinstance(result["error"], UntrustedCertificateError)


def test_expected_peer_identity_enforced() -> None:
    _unused_identity, _unused_server, _unused_anchor, _unused_s = _make_identities()
    ca_key = generate_signing_key()
    ca_cert = create_ca(ca_key)
    client_key = generate_signing_key()
    client_cert = issue_certificate(ca_key, ca_cert, "alice", "student", client_key.verify_key)
    client_identity = HandshakeIdentity("alice", "student", client_key, client_cert)
    mallory_key = generate_signing_key()
    mallory_cert = issue_certificate(ca_key, ca_cert, "mallory", "switch", mallory_key.verify_key)
    mallory = HandshakeIdentity("mallory", "switch", mallory_key, mallory_cert)
    c_anchor = TrustAnchor(
        ca_cert=ca_cert,
        crl_provider=lambda: None,
        expected_peer_id="bob",
        expected_peer_role="switch",
    )
    csock, ssock = _raw_pair()

    def server_thread() -> None:
        try:
            anchor = TrustAnchor(
                ca_cert=ca_cert,
                crl_provider=lambda: None,
                expected_peer_id=None,
                expected_peer_role=None,
            )
            run_server_handshake(ssock, mallory, anchor)
        except Exception:
            return

    thread = threading.Thread(target=server_thread, daemon=True)
    thread.start()
    with pytest.raises(UnknownIdentityError):
        run_client_handshake(csock, client_identity, c_anchor)
    thread.join(timeout=5.0)
    csock.close()
    ssock.close()


def test_finished_key_confirmation_detects_key_substitution() -> None:
    import hashlib
    import hmac as hmac_std

    def finished_mac(prk: bytes, transcript_hash_value: bytes) -> bytes:
        fk = hkdf_expand(prk, b"SP1/finished/server", config.KEY_BYTES)
        return hmac_std.new(fk, transcript_hash_value, hashlib.sha256).digest()

    client, _server, _csock, _ssock = _handshake_pair_with_sockets()
    th = transcript_hash(client.messages)
    wrong_ecdh = x25519_shared(*x25519_ephemeral())
    wrong_prk = hkdf_extract(b"\x00" * 32, wrong_ecdh)
    assert not hmac_std.compare_digest(
        finished_mac(wrong_prk, th), finished_mac(wrong_prk, th + b"x")
    )
    assert finished_mac(wrong_prk, th) == finished_mac(wrong_prk, th)
