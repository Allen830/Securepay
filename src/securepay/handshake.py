from __future__ import annotations

import hashlib
import hmac as hmac_std
import json
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from nacl import bindings as sodium
from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.encoding import b64_decode, b64_encode, canonical_bytes, domain_tag
from securepay.errors import (
    BadFinishedError,
    HandshakeError,
    SecurePayError,
    UnknownIdentityError,
    VersionMismatchError,
)
from securepay.framing import recv_frame, send_frame
from securepay.keystore import zeroise
from securepay.pki import cert_from_pem, cert_to_pem, verify_certificate

logger = logging.getLogger(__name__)

__all__ = [
    "HandshakeIdentity",
    "HandshakeResult",
    "SessionSecrets",
    "TrustAnchor",
    "derive_application_secrets",
    "hkdf_expand",
    "hkdf_extract",
    "run_client_handshake",
    "run_server_handshake",
    "transcript_hash",
    "x25519_ephemeral",
    "x25519_shared",
]

MSG_CLIENT_HELLO = "client_hello"
MSG_SERVER_HELLO = "server_hello"
MSG_CERTIFICATE = "certificate"
MSG_CERTIFICATE_VERIFY = "certificate_verify"
MSG_FINISHED = "finished"

_NONCE_BYTES = 32
_X25519_BYTES = 32

_TAG_CV_SERVER = domain_tag("SP1", "CV", "server")
_TAG_CV_CLIENT = domain_tag("SP1", "CV", "client")
_LABEL_FINISHED_SERVER = b"SP1/finished/server"
_LABEL_FINISHED_CLIENT = b"SP1/finished/client"
_LABEL_APP_C2S_KEY = b"SP1/app/c2s key"
_LABEL_APP_S2C_KEY = b"SP1/app/s2c key"
_LABEL_APP_C2S_NONCE = b"SP1/app/c2s nonce"
_LABEL_APP_S2C_NONCE = b"SP1/app/s2c nonce"
_LABEL_SESSION_ID = b"SP1/session id"


@dataclass(frozen=True)
class HandshakeIdentity:

    id: str
    role: str
    signing_key: SigningKey
    cert: x509.Certificate


@dataclass(frozen=True)
class TrustAnchor:

    ca_cert: x509.Certificate
    crl_provider: Callable[[], x509.CertificateRevocationList | None]
    expected_peer_id: str | None
    expected_peer_role: str | None
    peer_enrollment_check: Callable[[str, str, bytes], None] | None = None


@dataclass
class SessionSecrets:

    prk: bytearray
    c2s_key: bytearray
    s2c_key: bytearray
    c2s_nonce_prefix: bytearray
    s2c_nonce_prefix: bytearray
    th_final: bytes
    session_id: str

    def zeroise(self) -> None:
        zeroise(self.prk)
        zeroise(self.c2s_key)
        zeroise(self.s2c_key)
        zeroise(self.c2s_nonce_prefix)
        zeroise(self.s2c_nonce_prefix)


@dataclass(frozen=True)
class HandshakeResult:

    session_id: str
    peer_id: str
    peer_role: str
    peer_cert: x509.Certificate
    secrets: SessionSecrets
    messages: list[dict[str, object]] = field(default_factory=list)


def transcript_hash(messages: list[dict[str, object]]) -> bytes:
    digest = hashlib.sha256()
    for message in messages:
        encoded = canonical_bytes(message)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.digest()


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac_std.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(prk)


def x25519_ephemeral() -> tuple[bytes, bytes]:
    private = sodium.randombytes(_X25519_BYTES)
    public = sodium.crypto_scalarmult_base(private)
    return private, public


def x25519_shared(private: bytes, peer_public: bytes) -> bytes:
    if len(peer_public) != _X25519_BYTES:
        raise HandshakeError("peer ephemeral key has wrong length")
    try:
        return bytes(sodium.crypto_scalarmult(private, peer_public))
    except (RuntimeError, ValueError) as exc:
        raise HandshakeError("peer ephemeral key is invalid (low-order point)") from exc


def _derive_handshake_secrets(
    ecdh_shared: bytes, client_nonce: bytes, server_nonce: bytes
) -> tuple[bytes, bytes, bytes]:
    prk = hkdf_extract(client_nonce + server_nonce, ecdh_shared)
    finished_key_server = hkdf_expand(prk, _LABEL_FINISHED_SERVER, config.KEY_BYTES)
    finished_key_client = hkdf_expand(prk, _LABEL_FINISHED_CLIENT, config.KEY_BYTES)
    return prk, finished_key_server, finished_key_client


def derive_application_secrets(prk: bytes, th_final: bytes) -> SessionSecrets:
    c2s_key = hkdf_expand(prk, th_final + _LABEL_APP_C2S_KEY, config.KEY_BYTES)
    s2c_key = hkdf_expand(prk, th_final + _LABEL_APP_S2C_KEY, config.KEY_BYTES)
    c2s_prefix = hkdf_expand(prk, th_final + _LABEL_APP_C2S_NONCE, config.NONCE_PREFIX_BYTES)
    s2c_prefix = hkdf_expand(prk, th_final + _LABEL_APP_S2C_NONCE, config.NONCE_PREFIX_BYTES)
    session_id = hkdf_expand(prk, th_final + _LABEL_SESSION_ID, 16).hex()
    return SessionSecrets(
        prk=bytearray(prk),
        c2s_key=bytearray(c2s_key),
        s2c_key=bytearray(s2c_key),
        c2s_nonce_prefix=bytearray(c2s_prefix),
        s2c_nonce_prefix=bytearray(s2c_prefix),
        th_final=th_final,
        session_id=session_id,
    )


def _send(sock: object, message: dict[str, object]) -> None:
    send_frame(sock, canonical_bytes(message))


def _recv(sock: object, expected_type: str) -> dict[str, object]:
    frame = recv_frame(sock)
    try:
        message = json.loads(frame.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HandshakeError("handshake message is not valid JSON") from exc
    if not isinstance(message, dict):
        raise HandshakeError("handshake message is not a JSON object")
    if message.get("type") != expected_type:
        raise HandshakeError(f"expected {expected_type}, got {message.get('type')!r}")
    return message


def _require(message: dict[str, object], key: str, kind: type) -> object:
    value = message.get(key)
    if not isinstance(value, kind):
        raise HandshakeError(f"handshake field {key} missing or wrong type")
    return value


def _check_hello(message: dict[str, object], who: str) -> tuple[bytes, bytes, str]:
    version = _require(message, "v", int)
    suite = _require(message, "suite", str)
    if version != config.PROTOCOL_VERSION or suite != config.CIPHER_SUITE:
        raise VersionMismatchError(f"peer proposed unsupported protocol version/suite ({who})")
    ts = _require(message, "ts", int)
    if not isinstance(ts, int) or abs(_now() - ts) > config.MAX_CLOCK_SKEW_SECONDS:
        raise HandshakeError(f"{who} hello timestamp outside freshness window")
    eph = b64_decode(_require(message, "eph", str))
    nonce = b64_decode(_require(message, "nonce", str))
    sender = _require(message, "id", str)
    if len(eph) != _X25519_BYTES or len(nonce) != _NONCE_BYTES:
        raise HandshakeError(f"{who} hello has malformed ephemeral key or nonce")
    return eph, nonce, str(sender)


def _now() -> int:
    return int(time.time())


def _verify_certificate_message(
    cert_message: dict[str, object],
    hello_id: str,
    anchor: TrustAnchor,
) -> tuple[x509.Certificate, str, str, bytes]:
    pem = _require(cert_message, "cert_pem", str)
    cert = cert_from_pem(str(pem))
    identity = verify_certificate(cert, anchor.ca_cert, anchor.crl_provider())
    if identity.subject_id != hello_id:
        raise UnknownIdentityError("certificate does not match the hello identity")
    if anchor.expected_peer_id is not None and identity.subject_id != anchor.expected_peer_id:
        raise UnknownIdentityError("peer identity is not the one we expected")
    if anchor.expected_peer_role is not None and identity.role != anchor.expected_peer_role:
        raise UnknownIdentityError("peer certificate role is unexpected")
    if anchor.peer_enrollment_check is not None:
        anchor.peer_enrollment_check(identity.subject_id, identity.role, identity.public_key)
    return cert, identity.subject_id, identity.role, identity.public_key


def _verify_certificate_verify(
    message: dict[str, object],
    tag: bytes,
    public_key: bytes,
    transcript: list[dict[str, object]],
) -> None:
    algorithm = _require(message, "algorithm", str)
    if algorithm != "Ed25519":
        raise HandshakeError("unsupported signature algorithm")
    signature = b64_decode(_require(message, "signature", str))
    payload = tag + transcript_hash(transcript)
    try:
        VerifyKey(public_key).verify(payload, signature)
    except Exception as exc:
        raise HandshakeError("certificate_verify signature is invalid") from exc


def _build_certificate_verify(
    signing_key: SigningKey, tag: bytes, transcript: list[dict[str, object]]
) -> dict[str, object]:
    return {
        "type": MSG_CERTIFICATE_VERIFY,
        "algorithm": "Ed25519",
        "signature": b64_encode(signing_key.sign(tag + transcript_hash(transcript)).signature),
    }


def _finished_mac(finished_key: bytes, transcript: list[dict[str, object]]) -> str:
    return b64_encode(
        hmac_std.new(finished_key, transcript_hash(transcript), hashlib.sha256).digest()
    )


def _check_finished(
    message: dict[str, object], finished_key: bytes, transcript: list[dict[str, object]]
) -> None:
    received = _require(message, "mac", str)
    expected = _finished_mac(finished_key, transcript)
    if not hmac_std.compare_digest(received, expected):
        raise BadFinishedError("finished MAC mismatch (key confirmation failed)")


def run_client_handshake(
    sock: object,
    identity: HandshakeIdentity,
    anchor: TrustAnchor,
    *,
    timeout: float = config.HANDSHAKE_TIMEOUT,
) -> HandshakeResult:
    try:
        return _run_client_handshake(sock, identity, anchor, timeout=timeout)
    except SecurePayError as exc:
        logger.warning("event=client_handshake_failed id=%s code=%s", identity.id, exc.code)
        raise


def _run_client_handshake(
    sock: object,
    identity: HandshakeIdentity,
    anchor: TrustAnchor,
    *,
    timeout: float = config.HANDSHAKE_TIMEOUT,
) -> HandshakeResult:
    sock.settimeout(timeout)
    client_eph_priv, client_eph_pub = x25519_ephemeral()
    client_nonce = os.urandom(_NONCE_BYTES)

    client_hello: dict[str, object] = {
        "type": MSG_CLIENT_HELLO,
        "v": config.PROTOCOL_VERSION,
        "suite": config.CIPHER_SUITE,
        "id": identity.id,
        "eph": b64_encode(client_eph_pub),
        "nonce": b64_encode(client_nonce),
        "ts": _now(),
    }
    transcript: list[dict[str, object]] = [client_hello]
    _send(sock, client_hello)

    server_hello = _recv(sock, MSG_SERVER_HELLO)
    server_eph_pub, server_nonce, server_id = _check_hello(server_hello, "server")
    transcript.append(server_hello)

    server_cert_msg = _recv(sock, MSG_CERTIFICATE)
    transcript.append(server_cert_msg)
    cert, subject_id, role, public_key = _verify_certificate_message(
        server_cert_msg, server_id, anchor
    )

    server_cv = _recv(sock, MSG_CERTIFICATE_VERIFY)
    _verify_certificate_verify(server_cv, _TAG_CV_SERVER, public_key, transcript)
    transcript.append(server_cv)

    ecdh = x25519_shared(client_eph_priv, server_eph_pub)
    prk, finished_key_server, finished_key_client = _derive_handshake_secrets(
        ecdh, client_nonce, server_nonce
    )

    server_finished = _recv(sock, MSG_FINISHED)
    _check_finished(server_finished, finished_key_server, transcript)
    transcript.append(server_finished)

    client_cert_msg: dict[str, object] = {
        "type": MSG_CERTIFICATE,
        "role": identity.role,
        "cert_pem": cert_pem_of(identity),
    }
    transcript.append(client_cert_msg)
    _send(sock, client_cert_msg)

    client_cv = _build_certificate_verify(identity.signing_key, _TAG_CV_CLIENT, transcript)
    transcript.append(client_cv)
    _send(sock, client_cv)

    client_finished: dict[str, object] = {
        "type": MSG_FINISHED,
        "mac": _finished_mac(finished_key_client, transcript),
    }
    transcript.append(client_finished)
    _send(sock, client_finished)

    secrets = derive_application_secrets(prk, transcript_hash(transcript))
    zeroise(client_eph_priv)
    logger.info(
        "event=handshake_complete side=client peer=%s session=%s",
        subject_id,
        secrets.session_id[:12],
    )
    return HandshakeResult(
        session_id=secrets.session_id,
        peer_id=subject_id,
        peer_role=role,
        peer_cert=cert,
        secrets=secrets,
        messages=transcript,
    )


def run_server_handshake(
    sock: object,
    identity: HandshakeIdentity,
    anchor: TrustAnchor,
    *,
    timeout: float = config.HANDSHAKE_TIMEOUT,
) -> HandshakeResult:
    sock.settimeout(timeout)

    client_hello = _recv(sock, MSG_CLIENT_HELLO)
    client_eph_pub, client_nonce, client_id = _check_hello(client_hello, "client")
    transcript: list[dict[str, object]] = [client_hello]

    server_eph_priv, server_eph_pub = x25519_ephemeral()
    server_nonce = os.urandom(_NONCE_BYTES)
    server_hello: dict[str, object] = {
        "type": MSG_SERVER_HELLO,
        "v": config.PROTOCOL_VERSION,
        "suite": config.CIPHER_SUITE,
        "id": identity.id,
        "eph": b64_encode(server_eph_pub),
        "nonce": b64_encode(server_nonce),
        "ts": _now(),
    }
    transcript.append(server_hello)
    _send(sock, server_hello)

    server_cert_msg: dict[str, object] = {
        "type": MSG_CERTIFICATE,
        "role": identity.role,
        "cert_pem": cert_pem_of(identity),
    }
    transcript.append(server_cert_msg)
    _send(sock, server_cert_msg)

    server_cv = _build_certificate_verify(identity.signing_key, _TAG_CV_SERVER, transcript)
    transcript.append(server_cv)
    _send(sock, server_cv)

    ecdh = x25519_shared(server_eph_priv, client_eph_pub)
    prk, finished_key_server, finished_key_client = _derive_handshake_secrets(
        ecdh, client_nonce, server_nonce
    )

    server_finished: dict[str, object] = {
        "type": MSG_FINISHED,
        "mac": _finished_mac(finished_key_server, transcript),
    }
    transcript.append(server_finished)
    _send(sock, server_finished)

    client_cert_msg = _recv(sock, MSG_CERTIFICATE)
    transcript.append(client_cert_msg)
    cert, subject_id, role, public_key = _verify_certificate_message(
        client_cert_msg, client_id, anchor
    )

    client_cv = _recv(sock, MSG_CERTIFICATE_VERIFY)
    _verify_certificate_verify(client_cv, _TAG_CV_CLIENT, public_key, transcript)
    transcript.append(client_cv)

    client_finished = _recv(sock, MSG_FINISHED)
    _check_finished(client_finished, finished_key_client, transcript)
    transcript.append(client_finished)

    secrets = derive_application_secrets(prk, transcript_hash(transcript))
    zeroise(server_eph_priv)
    logger.info(
        "event=handshake_complete side=server peer=%s session=%s",
        subject_id,
        secrets.session_id[:12],
    )
    return HandshakeResult(
        session_id=secrets.session_id,
        peer_id=subject_id,
        peer_role=role,
        peer_cert=cert,
        secrets=secrets,
        messages=transcript,
    )


def cert_pem_of(identity: HandshakeIdentity) -> str:
    return cert_to_pem(identity.cert)
