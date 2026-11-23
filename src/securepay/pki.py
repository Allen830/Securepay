from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from nacl.signing import SigningKey, VerifyKey

from securepay import config
from securepay.errors import (
    BadSignatureError,
    ExpiredCertificateError,
    PKIError,
    RevokedCertificateError,
    UntrustedCertificateError,
)

logger = logging.getLogger(__name__)

__all__ = [
    "KEY_ALGORITHM",
    "CertificateIdentity",
    "build_crl",
    "cert_fingerprint",
    "cert_from_pem",
    "cert_to_pem",
    "create_ca",
    "generate_signing_key",
    "issue_certificate",
    "load_crl",
    "read_cert",
    "revoked_serials",
    "save_pem",
    "sign_bytes",
    "verify_bytes",
    "verify_certificate",
]

KEY_ALGORITHM = "Ed25519"

_ORGANISATION = "MACS902 UOWD"
_CA_COMMON_NAME = "CampusPay Root CA"


@dataclass(frozen=True)
class CertificateIdentity:

    subject_id: str
    role: str
    serial: int
    not_before: datetime
    not_after: datetime
    public_key: bytes


def generate_signing_key() -> SigningKey:
    return SigningKey.generate()


def sign_bytes(signing_key: SigningKey, payload: bytes) -> bytes:
    return bytes(signing_key.sign(payload).signature)


def verify_bytes(verify_key: VerifyKey, payload: bytes, signature: bytes) -> None:
    try:
        verify_key.verify(payload, signature)
    except Exception as exc:
        raise BadSignatureError("Ed25519 signature verification failed") from exc


def _x509_name(common_name: str, organisational_unit: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, _ORGANISATION),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organisational_unit),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _ed25519_private(signing_key: SigningKey) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(signing_key))


def create_ca(
    signing_key: SigningKey,
    *,
    validity_days: int = config.CA_VALIDITY_DAYS,
    now: datetime | None = None,
) -> x509.Certificate:
    now = now or datetime.now(timezone.utc)
    name = _x509_name(_CA_COMMON_NAME, "ca")
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(_ed25519_private(signing_key).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=config.CERT_BACKDATE_SECONDS))
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(_ed25519_private(signing_key), None)
    )


def issue_certificate(
    ca_signing_key: SigningKey,
    ca_cert: x509.Certificate,
    subject_id: str,
    role: str,
    subject_public_key: VerifyKey,
    *,
    validity_days: int = config.CERT_VALIDITY_DAYS,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> x509.Certificate:
    now = datetime.now(timezone.utc)
    start = not_before or (now - timedelta(seconds=config.CERT_BACKDATE_SECONDS))
    end = not_after or (now + timedelta(days=validity_days))
    eku = (
        ExtendedKeyUsageOID.SERVER_AUTH
        if role == config.ROLE_SWITCH
        else ExtendedKeyUsageOID.CLIENT_AUTH
    )
    builder = (
        x509.CertificateBuilder()
        .subject_name(_x509_name(subject_id, role))
        .issuer_name(ca_cert.subject)
        .public_key(Ed25519PublicKey.from_public_bytes(bytes(subject_public_key)))
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
    )
    return builder.sign(_ed25519_private(ca_signing_key), None)


def verify_certificate(
    cert: x509.Certificate,
    ca_cert: x509.Certificate,
    crl: x509.CertificateRevocationList | None = None,
    *,
    at: datetime | None = None,
) -> CertificateIdentity:
    at = at or datetime.now(timezone.utc)
    if cert.issuer != ca_cert.subject:
        raise UntrustedCertificateError("certificate issuer is not the campus CA")
    ca_public = ca_cert.public_key()
    if not isinstance(ca_public, Ed25519PublicKey):
        raise UntrustedCertificateError("CA certificate does not use Ed25519")
    try:
        ca_public.verify(cert.signature, cert.tbs_certificate_bytes)
    except Exception as exc:
        raise UntrustedCertificateError("certificate signature check failed") from exc

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    if not_before is None or not_after is None or not (not_before <= at <= not_after):
        raise ExpiredCertificateError("certificate is outside its validity window")

    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if constraints.value.ca:
            raise UntrustedCertificateError("leaf certificate must not be a CA")
    except x509.ExtensionNotFound as exc:
        raise UntrustedCertificateError("certificate lacks BasicConstraints") from exc

    if crl is not None:
        if not crl.is_signature_valid(ca_public):
            raise PKIError("CRL signature is invalid")
        if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
            raise RevokedCertificateError("certificate has been revoked")

    name_attributes = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    role_attributes = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    if len(name_attributes) != 1 or len(role_attributes) != 1:
        raise UntrustedCertificateError("certificate subject is malformed")
    public = cert.public_key()
    if not isinstance(public, Ed25519PublicKey):
        raise UntrustedCertificateError("certificate public key is not Ed25519")
    raw_public = public.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    if len(raw_public) != 32:
        raise UntrustedCertificateError("certificate public key is not Ed25519")
    identity = CertificateIdentity(
        subject_id=name_attributes[0].value,
        role=role_attributes[0].value,
        serial=cert.serial_number,
        not_before=not_before,
        not_after=not_after,
        public_key=raw_public,
    )
    logger.info(
        "event=certificate_verified subject=%s role=%s serial=%x expires=%s",
        identity.subject_id,
        identity.role,
        identity.serial,
        identity.not_after.date().isoformat(),
    )
    return identity


def build_crl(
    ca_signing_key: SigningKey,
    ca_cert: x509.Certificate,
    revoked: list[tuple[int, datetime]],
) -> x509.CertificateRevocationList:
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=config.CRL_NEXT_UPDATE_DAYS))
    )
    for serial, when in revoked:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(when).build()
        )
    return builder.sign(_ed25519_private(ca_signing_key), None)


def load_crl(path: Path) -> x509.CertificateRevocationList | None:
    if not path.exists():
        return None
    return x509.load_pem_x509_crl(path.read_bytes())


def revoked_serials(crl: x509.CertificateRevocationList | None) -> set[int]:
    if crl is None:
        return set()
    return {entry.serial_number for entry in crl}


def cert_to_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def cert_from_pem(pem: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise PKIError("malformed certificate PEM") from exc


def cert_fingerprint(cert: x509.Certificate) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(cert.public_bytes(Encoding.DER))
    return "sha256:" + base64.b64encode(digest.finalize()[:12]).decode("ascii").rstrip("=")


def save_pem(path: Path, pem: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pem, encoding="ascii")


def read_cert(path: Path) -> x509.Certificate:
    return cert_from_pem(path.read_text(encoding="ascii"))
