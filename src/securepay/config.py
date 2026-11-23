from __future__ import annotations

import contextlib
import logging
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path


PROTOCOL_NAME = "SP1"
PROTOCOL_VERSION = 1

CIPHER_SUITE = "SP1-X25519-Ed25519-ChaCha20Poly1305-HKDF-SHA256"


FRAME_HEADER_BYTES = 4

MAX_FRAME_BYTES = 1 << 20

HANDSHAKE_TIMEOUT = 10.0
IO_TIMEOUT = 15.0


KEY_BYTES = 32
NONCE_BYTES = 12
NONCE_PREFIX_BYTES = 4
NONCE_COUNTER_BYTES = 8
TAG_BYTES = 16

MAX_COUNTER = 1 << 48
MAX_CLOCK_SKEW_SECONDS = 30

REKEY_AFTER_MESSAGES = 1000
REKEY_AFTER_SECONDS = 300.0
REKEY_TIMEOUT = 10.0


ARGON2ID_OPSLIMIT = 3
ARGON2ID_MEMLIMIT = 64 * 1024 * 1024
KDF_SALT_BYTES = 16
KDF_OUTPUT_BYTES = 32

VAULT_FORMAT = "securepay-vault"
VAULT_VERSION = 1

UNLOCK_MAX_FAILURES = 5
UNLOCK_LOCKOUT_SECONDS = 300


SESSION_MESSAGE_BURST = 30
SESSION_MESSAGE_RATE = 10.0

PENDING_TTL_SECONDS = 120


CURRENCY = "AED"
MINOR_UNITS_PER_UNIT = 100
MAX_AMOUNT_MINOR = 10_000_000 * MINOR_UNITS_PER_UNIT


CA_VALIDITY_DAYS = 3650
CERT_VALIDITY_DAYS = 365
CERT_BACKDATE_SECONDS = 300
CRL_NEXT_UPDATE_DAYS = 7

ROLE_SWITCH = "switch"
ROLE_MERCHANT = "merchant"
ROLE_STUDENT = "student"

SWITCH_ID = "switch"


DEFAULT_HOST = "127.0.0.1"
DEFAULT_SWITCH_PORT = 7440

_CA_DIR = "ca"
_SWITCH_DIR = "switch"
_TERMINALS_DIR = "terminals"
_WALLETS_DIR = "wallets"
_RECEIPTS_DIR = "receipts"


@dataclass(frozen=True)
class NetworkPaths:

    root: Path


    @property
    def ca_dir(self) -> Path:
        return self.root / _CA_DIR

    @property
    def ca_vault(self) -> Path:
        return self.ca_dir / "ca.keys"

    @property
    def ca_cert(self) -> Path:
        return self.ca_dir / "ca.crt"

    @property
    def ca_revoked_list(self) -> Path:
        return self.ca_dir / "revoked.json"

    @property
    def crl(self) -> Path:
        return self.ca_dir / "crl.pem"


    @property
    def switch_dir(self) -> Path:
        return self.root / _SWITCH_DIR

    @property
    def switch_vault(self) -> Path:
        return self.switch_dir / "switch.keys"

    @property
    def switch_cert(self) -> Path:
        return self.switch_dir / "switch.crt"


    def terminal_vault(self, merchant_id: str) -> Path:
        return self.root / _TERMINALS_DIR / f"{merchant_id}.keys"

    def terminal_cert(self, merchant_id: str) -> Path:
        return self.root / _TERMINALS_DIR / f"{merchant_id}.crt"

    def wallet_vault(self, student_id: str) -> Path:
        return self.root / _WALLETS_DIR / f"{student_id}.keys"

    def wallet_cert(self, student_id: str) -> Path:
        return self.root / _WALLETS_DIR / f"{student_id}.crt"

    @property
    def wallets_dir(self) -> Path:
        return self.root / _WALLETS_DIR

    @property
    def terminals_dir(self) -> Path:
        return self.root / _TERMINALS_DIR


    @property
    def registry(self) -> Path:
        return self.root / "registry.json"

    @property
    def ledger(self) -> Path:
        return self.root / "ledger.db"

    @property
    def receipts_dir(self) -> Path:
        return self.root / _RECEIPTS_DIR

    def receipt(self, txn_id: str) -> Path:
        return self.receipts_dir / f"{txn_id}.json"

    def lockout(self, vault: Path) -> Path:
        return vault.with_suffix(vault.suffix + ".attempts")

    def ensure(self) -> None:
        for directory in (
            self.root,
            self.ca_dir,
            self.switch_dir,
            self.terminals_dir,
            self.wallets_dir,
            self.receipts_dir,
        ):
            directory.mkdir(parents=True, exist_ok=True)


_OVERRIDABLE = frozenset(
    {
        "ARGON2ID_OPSLIMIT",
        "ARGON2ID_MEMLIMIT",
        "MAX_CLOCK_SKEW_SECONDS",
        "REKEY_AFTER_MESSAGES",
        "REKEY_AFTER_SECONDS",
        "PENDING_TTL_SECONDS",
        "UNLOCK_MAX_FAILURES",
        "UNLOCK_LOCKOUT_SECONDS",
    }
)

_override_lock = threading.Lock()


@contextlib.contextmanager
def temporary(**overrides: object) -> Iterator[None]:
    unknown = set(overrides) - _OVERRIDABLE
    if unknown:
        raise ValueError(f"parameters not overridable: {sorted(unknown)}")
    previous = {name: getattr(_module_self, name) for name in overrides}
    with _override_lock:
        for name, value in overrides.items():
            setattr(_module_self, name, value)
    try:
        yield
    finally:
        with _override_lock:
            for name, value in previous.items():
                setattr(_module_self, name, value)


_module_self = sys.modules[__name__]


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-7s %(name)s %(message)s", "%H:%M:%S")
    )
    root = logging.getLogger("securepay")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    root.propagate = False
