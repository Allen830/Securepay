from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from nacl.signing import SigningKey

from securepay import config
from securepay.encoding import b64_encode, mask_pan
from securepay.errors import PKIError
from securepay.keystore import load_vault, save_vault
from securepay.pki import (
    build_crl,
    cert_fingerprint,
    cert_from_pem,
    cert_to_pem,
    create_ca,
    generate_signing_key,
    issue_certificate,
    save_pem,
)
from securepay.ratelimit import generate_passphrase

logger = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_MERCHANTS",
    "DEFAULT_STUDENTS",
    "ProvisionedNetwork",
    "issue_entity_certificate",
    "provision_network",
    "revoke_entity_certificate",
    "write_passphrase_file",
]

DEFAULT_STUDENTS = [
    {"id": "902101", "name": "Sarah Ahmed", "balance": "450.00"},
    {"id": "902102", "name": "Alex Chen", "balance": "320.50"},
    {"id": "902103", "name": "Tariq Al-Mansoor", "balance": "610.00"},
    {"id": "902104", "name": "Fatima Al-Zahra", "balance": "850.25"},
    {"id": "902105", "name": "Rohan Sharma", "balance": "190.00"},
    {"id": "902106", "name": "Maya Lin", "balance": "520.75"},
    {"id": "902107", "name": "Daniel Kovacs", "balance": "310.00"},
    {"id": "902108", "name": "Aisha Mahmoud", "balance": "740.50"},
    {"id": "902109", "name": "Liam O'Connor", "balance": "280.00"},
    {"id": "902110", "name": "Priya Patel", "balance": "930.00"},
    {"id": "902111", "name": "Carlos Gomez", "balance": "415.80"},
    {"id": "902112", "name": "Emma Watson", "balance": "600.00"},
]

DEFAULT_MERCHANTS = [
    {"id": "canteen", "name": "Campus Main Canteen", "balance": "1500.00"},
    {"id": "coffee_shop", "name": "UOWD Espresso Bar", "balance": "2200.00"},
    {"id": "library", "name": "Library Print Services", "balance": "800.00"},
]

_SWITCH_NAME = "Aani Settlement Switch"


@dataclass
class ProvisionedNetwork:

    paths: config.NetworkPaths
    ca_passphrase: str
    passphrases: dict[str, str]
    ca_fingerprint: str
    entities: list[dict[str, object]] = field(default_factory=list)


def _to_minor(amount: str) -> int:
    from securepay.encoding import parse_amount_minor

    return parse_amount_minor(amount)


def _tokenise_card() -> tuple[str, str]:
    import secrets

    pan = "".join(secrets.choice("0123456789") for _ in range(16))
    token = secrets.token_hex(16)
    return token, mask_pan(pan)


def provision_network(
    root: Path,
    *,
    students: list[dict[str, str]] | None = None,
    merchants: list[dict[str, str]] | None = None,
    passphrases: dict[str, str] | None = None,
    ca_passphrase: str | None = None,
    currency: str = config.CURRENCY,
) -> ProvisionedNetwork:
    students = DEFAULT_STUDENTS if students is None else students
    merchants = DEFAULT_MERCHANTS if merchants is None else merchants
    passphrases = dict(passphrases or {})
    paths = config.NetworkPaths(root=root)
    paths.ensure()

    ca_key = generate_signing_key()
    ca_passphrase = ca_passphrase or generate_passphrase()
    save_vault(
        paths.ca_vault,
        ca_passphrase,
        {"id": "ca", "seed": bytes(ca_key).hex()},
        {"kind": "ca", "id": "ca"},
    )
    ca_cert = create_ca(ca_key)
    save_pem(paths.ca_cert, cert_to_pem(ca_cert))

    switch_key = generate_signing_key()
    switch_passphrase = passphrases.setdefault(config.SWITCH_ID, generate_passphrase())
    switch_cert = issue_certificate(
        ca_key, ca_cert, config.SWITCH_ID, config.ROLE_SWITCH, switch_key.verify_key
    )
    save_vault(
        paths.switch_vault,
        switch_passphrase,
        {
            "id": config.SWITCH_ID,
            "seed": bytes(switch_key).hex(),
            "cert_pem": cert_to_pem(switch_cert),
        },
        {"kind": "switch", "id": config.SWITCH_ID},
    )
    save_pem(paths.switch_cert, cert_to_pem(switch_cert))

    entities: list[dict[str, object]] = [
        {
            "id": config.SWITCH_ID,
            "role": config.ROLE_SWITCH,
            "name": _SWITCH_NAME,
            "cert_pem": cert_to_pem(switch_cert),
            "public_key": b64_encode(bytes(switch_key.verify_key)),
            "serial": switch_cert.serial_number,
        }
    ]

    for merchant in merchants:
        merchant_id = merchant["id"]
        key = generate_signing_key()
        passphrase = passphrases.setdefault(merchant_id, generate_passphrase())
        cert = issue_certificate(ca_key, ca_cert, merchant_id, config.ROLE_MERCHANT, key.verify_key)
        save_vault(
            paths.terminal_vault(merchant_id),
            passphrase,
            {
                "id": merchant_id,
                "seed": bytes(key).hex(),
                "cert_pem": cert_to_pem(cert),
            },
            {"kind": "merchant", "id": merchant_id},
        )
        save_pem(paths.terminal_cert(merchant_id), cert_to_pem(cert))
        entities.append(
            {
                "id": merchant_id,
                "role": config.ROLE_MERCHANT,
                "name": merchant["name"],
                "cert_pem": cert_to_pem(cert),
                "public_key": b64_encode(bytes(key.verify_key)),
                "serial": cert.serial_number,
            }
        )

    for student in students:
        student_id = student["id"]
        key = generate_signing_key()
        passphrase = passphrases.setdefault(student_id, generate_passphrase())
        cert = issue_certificate(ca_key, ca_cert, student_id, config.ROLE_STUDENT, key.verify_key)
        card_token, pan_masked = _tokenise_card()
        save_vault(
            paths.wallet_vault(student_id),
            passphrase,
            {
                "id": student_id,
                "seed": bytes(key).hex(),
                "cert_pem": cert_to_pem(cert),
                "card": {"token": card_token, "pan_masked": pan_masked},
                "next_nonce": 1,
            },
            {"kind": "student", "id": student_id},
        )
        save_pem(paths.wallet_cert(student_id), cert_to_pem(cert))
        entities.append(
            {
                "id": student_id,
                "role": config.ROLE_STUDENT,
                "name": student["name"],
                "cert_pem": cert_to_pem(cert),
                "public_key": b64_encode(bytes(key.verify_key)),
                "serial": cert.serial_number,
                "card_token": card_token,
                "pan_masked": pan_masked,
            }
        )

    registry = {
        "v": 1,
        "currency": currency,
        "ca_fingerprint": cert_fingerprint(ca_cert),
        "entities": entities,
    }
    _atomic_write_json(paths.registry, registry)

    from securepay.ledger import Ledger

    ledger = Ledger(paths.ledger, switch_key)
    try:
        for merchant in merchants:
            ledger.create_account(
                merchant["id"],
                config.ROLE_MERCHANT,
                merchant["name"],
                _to_minor(merchant["balance"]),
            )
        for student in students:
            ledger.create_account(
                student["id"], config.ROLE_STUDENT, student["name"], _to_minor(student["balance"])
            )
        ledger.audit_event(
            "network_provisioned",
            {
                "merchants": [m["id"] for m in merchants],
                "students": [s["id"] for s in students],
                "currency": currency,
            },
        )
    finally:
        ledger.close()

    _write_crl(paths, ca_key, ca_cert)

    logger.info("event=network_provisioned root=%s entities=%d", root, len(entities))
    return ProvisionedNetwork(
        paths=paths,
        ca_passphrase=ca_passphrase,
        passphrases=passphrases,
        ca_fingerprint=cert_fingerprint(ca_cert),
        entities=entities,
    )


def _atomic_write_json(path: Path, data: object) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def _load_ca(paths: config.NetworkPaths, ca_passphrase: str) -> tuple[SigningKey, x509.Certificate]:
    vault = load_vault(paths.ca_vault, ca_passphrase, expected_aad={"kind": "ca", "id": "ca"})
    return (
        SigningKey(bytes.fromhex(vault["seed"])),
        cert_from_pem(paths.ca_cert.read_text(encoding="ascii")),
    )


def _load_switch_signer(paths: config.NetworkPaths, switch_passphrase: str) -> SigningKey:
    vault = load_vault(
        paths.switch_vault,
        switch_passphrase,
        expected_aad={"kind": "switch", "id": config.SWITCH_ID},
    )
    return SigningKey(bytes.fromhex(vault["seed"]))


def issue_entity_certificate(
    paths: config.NetworkPaths,
    ca_passphrase: str,
    *,
    role: str,
    entity_id: str,
    name: str,
    opening_balance: str = "0.00",
    passphrase: str | None = None,
    switch_passphrase: str | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> str:
    if role not in (config.ROLE_MERCHANT, config.ROLE_STUDENT):
        raise PKIError(f"cannot issue certificates for role {role!r}")
    ca_key, ca_cert = _load_ca(paths, ca_passphrase)
    switch_signer = (
        _load_switch_signer(paths, switch_passphrase) if switch_passphrase is not None else None
    )
    key = generate_signing_key()
    passphrase = passphrase or generate_passphrase()
    cert = issue_certificate(
        ca_key,
        ca_cert,
        entity_id,
        role,
        key.verify_key,
        not_before=not_before,
        not_after=not_after,
    )

    vault_path = (
        paths.terminal_vault(entity_id)
        if role == config.ROLE_MERCHANT
        else paths.wallet_vault(entity_id)
    )
    cert_path = (
        paths.terminal_cert(entity_id)
        if role == config.ROLE_MERCHANT
        else paths.wallet_cert(entity_id)
    )
    payload: dict[str, object] = {
        "id": entity_id,
        "seed": bytes(key).hex(),
        "cert_pem": cert_to_pem(cert),
    }
    if role == config.ROLE_STUDENT:
        card_token, pan_masked = _tokenise_card()
        payload["card"] = {"token": card_token, "pan_masked": pan_masked}
        payload["next_nonce"] = 1
    kind = "merchant" if role == config.ROLE_MERCHANT else "student"
    save_vault(vault_path, passphrase, payload, {"kind": kind, "id": entity_id})
    save_pem(cert_path, cert_to_pem(cert))

    registry = json.loads(paths.registry.read_text(encoding="utf-8"))
    entity: dict[str, object] = {
        "id": entity_id,
        "role": role,
        "name": name,
        "cert_pem": cert_to_pem(cert),
        "public_key": b64_encode(bytes(key.verify_key)),
        "serial": cert.serial_number,
    }
    if role == config.ROLE_STUDENT:
        entity["card_token"] = payload["card"]["token"]
        entity["pan_masked"] = payload["card"]["pan_masked"]
    registry["entities"].append(entity)
    _atomic_write_json(paths.registry, registry)

    if switch_signer is not None:
        from securepay.ledger import Ledger

        ledger = Ledger(paths.ledger, switch_signer)
        try:
            ledger.enrol_account(
                entity_id,
                role,
                name,
                _to_minor(opening_balance),
                {
                    "serial": f"{cert.serial_number:x}",
                    "public_key": b64_encode(bytes(key.verify_key)),
                },
            )
        finally:
            ledger.close()
    elif opening_balance != "0.00":
        from securepay.ledger import Ledger

        ledger = Ledger(paths.ledger, key)
        try:
            ledger.create_account(entity_id, role, name, _to_minor(opening_balance))
        finally:
            ledger.close()
    return passphrase


def revoke_entity_certificate(
    paths: config.NetworkPaths, ca_passphrase: str, entity_id: str
) -> int:
    ca_key, ca_cert = _load_ca(paths, ca_passphrase)
    registry = json.loads(paths.registry.read_text(encoding="utf-8"))
    entity = next((e for e in registry["entities"] if e["id"] == entity_id), None)
    if entity is None:
        raise PKIError(f"entity {entity_id} is not in the registry")
    entity["revoked"] = True
    _atomic_write_json(paths.registry, registry)

    serials: set[int] = set()
    if paths.ca_revoked_list.exists():
        serials.update(
            int(s) for s in json.loads(paths.ca_revoked_list.read_text(encoding="utf-8"))
        )
    serial = int(entity["serial"])
    serials.add(serial)
    when = datetime.now(timezone.utc) - timedelta(seconds=1)
    _write_crl(paths, ca_key, ca_cert, sorted((s, when) for s in serials))
    paths.ca_revoked_list.write_text(json.dumps(sorted(serials)), encoding="utf-8")
    logger.info("event=certificate_revoked entity=%s serial=%x", entity_id, serial)
    return serial


def _write_crl(
    paths: config.NetworkPaths,
    ca_key: SigningKey,
    ca_cert: x509.Certificate,
    revoked: list[tuple[int, datetime]] | None = None,
) -> None:
    crl = build_crl(ca_key, ca_cert, revoked or [])
    paths.crl.write_bytes(crl.public_bytes(Encoding.PEM))


def write_passphrase_file(path: Path, passphrase: str) -> None:
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(passphrase + "\n")
