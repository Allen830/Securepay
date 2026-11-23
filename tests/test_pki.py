from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from securepay import config
from securepay.errors import (
    ExpiredCertificateError,
    PKIError,
    RevokedCertificateError,
    UntrustedCertificateError,
)
from securepay.pki import (
    build_crl,
    cert_fingerprint,
    cert_from_pem,
    cert_to_pem,
    create_ca,
    generate_signing_key,
    issue_certificate,
    revoked_serials,
    verify_certificate,
)


@pytest.fixture
def ca() -> tuple[object, object]:
    key = generate_signing_key()
    cert = create_ca(key)
    return key, cert


def _issue(ca: tuple, subject_id: str = "coffee_shop", role: str = config.ROLE_MERCHANT):
    key = generate_signing_key()
    cert = issue_certificate(ca[0], ca[1], subject_id, role, key.verify_key)
    return key, cert


def test_ca_is_self_signed(ca: tuple) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    cert = ca[1]
    assert cert.issuer == cert.subject
    public = cert.public_key()
    assert isinstance(public, Ed25519PublicKey)
    public.verify(cert.signature, cert.tbs_certificate_bytes)


def test_leaf_certificate_verifies(ca: tuple) -> None:
    _key, cert = _issue(ca, "coffee_shop", config.ROLE_MERCHANT)
    identity = verify_certificate(cert, ca[1])
    assert identity.subject_id == "coffee_shop"
    assert identity.role == config.ROLE_MERCHANT
    assert identity.not_after > datetime.now(timezone.utc)


def test_certificate_from_foreign_ca_rejected(ca: tuple) -> None:
    other_ca_key = generate_signing_key()
    other_ca_cert = create_ca(other_ca_key)
    _key, cert = _issue((other_ca_key, other_ca_cert), "evil", config.ROLE_MERCHANT)
    with pytest.raises(UntrustedCertificateError):
        verify_certificate(cert, ca[1])


def test_tampered_certificate_rejected(ca: tuple) -> None:
    key, cert = _issue(ca, "coffee_shop")
    rogue_ca = generate_signing_key()
    rogue_cert = create_ca(rogue_ca)
    forged = issue_certificate(
        rogue_ca, rogue_cert, "coffee_shop", config.ROLE_MERCHANT, key.verify_key
    )
    assert forged.serial_number != cert.serial_number
    with pytest.raises(UntrustedCertificateError):
        verify_certificate(forged, ca[1])


def test_expired_certificate_rejected(ca: tuple) -> None:
    now = datetime.now(timezone.utc)
    key = generate_signing_key()
    cert = issue_certificate(
        ca[0],
        ca[1],
        "old_pos",
        config.ROLE_MERCHANT,
        key.verify_key,
        not_before=now - timedelta(days=30),
        not_after=now - timedelta(days=1),
    )
    with pytest.raises(ExpiredCertificateError):
        verify_certificate(cert, ca[1])


def test_future_certificate_rejected(ca: tuple) -> None:
    now = datetime.now(timezone.utc)
    key = generate_signing_key()
    cert = issue_certificate(
        ca[0],
        ca[1],
        "future_pos",
        config.ROLE_MERCHANT,
        key.verify_key,
        not_before=now + timedelta(days=1),
        not_after=now + timedelta(days=30),
    )
    with pytest.raises(ExpiredCertificateError):
        verify_certificate(cert, ca[1])


def test_revoked_certificate_rejected(ca: tuple) -> None:
    _key, cert = _issue(ca, "library", config.ROLE_MERCHANT)
    when = datetime.now(timezone.utc) - timedelta(seconds=1)
    crl = build_crl(ca[0], ca[1], [(cert.serial_number, when)])
    with pytest.raises(RevokedCertificateError):
        verify_certificate(cert, ca[1], crl)


def test_crl_with_wrong_signature_rejected(ca: tuple) -> None:
    _key, cert = _issue(ca, "library")
    when = datetime.now(timezone.utc) - timedelta(seconds=1)
    rogue = generate_signing_key()
    crl = build_crl(rogue, ca[1], [(cert.serial_number, when)])
    with pytest.raises(PKIError):
        verify_certificate(cert, ca[1], crl)


def test_revoked_serials_listing(ca: tuple) -> None:
    _key, cert = _issue(ca)
    when = datetime.now(timezone.utc)
    crl = build_crl(ca[0], ca[1], [(cert.serial_number, when)])
    assert cert.serial_number in revoked_serials(crl)
    assert revoked_serials(None) == set()


def test_pem_roundtrip_and_fingerprint(ca: tuple) -> None:
    _key, cert = _issue(ca, "coffee_shop")
    again = cert_from_pem(cert_to_pem(cert))
    assert again == cert
    assert cert_fingerprint(cert) == cert_fingerprint(again)
    with pytest.raises(PKIError):
        cert_from_pem("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----\n")


def test_serials_are_random(ca: tuple) -> None:
    _k1, cert1 = _issue(ca, "a")
    _k2, cert2 = _issue(ca, "b")
    assert cert1.serial_number != cert2.serial_number
