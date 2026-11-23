from __future__ import annotations

__all__ = [
    "AADMismatchError",
    "BadFinishedError",
    "BadPassphraseError",
    "BadSignatureError",
    "ChannelError",
    "CorruptVaultError",
    "CounterExhaustedError",
    "DecryptError",
    "DuplicateTxnError",
    "EpochError",
    "ExpiredCertificateError",
    "FramingError",
    "HandshakeError",
    "InsufficientFundsError",
    "KeystoreError",
    "LedgerError",
    "PKIError",
    "PendingRequestError",
    "ProtocolError",
    "RateLimitError",
    "RekeyError",
    "ReorderError",
    "ReplayError",
    "RevokedCertificateError",
    "SecurePayError",
    "StaleFrameError",
    "StaleNonceError",
    "UnknownAccountError",
    "UnknownIdentityError",
    "UntrustedCertificateError",
    "ValidationError",
    "VersionMismatchError",
]


class SecurePayError(Exception):

    code = "internal_error"

    def __init__(self, message: str = "", *, detail: str | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code
        self.detail = detail


class ProtocolError(SecurePayError):

    code = "protocol_error"


class FramingError(ProtocolError):

    code = "framing_error"


class ValidationError(ProtocolError):

    code = "validation_failed"

    def __init__(
        self,
        message: str = "",
        *,
        field: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(message, detail=detail)
        self.field = field


class HandshakeError(ProtocolError):

    code = "handshake_failed"


class UntrustedCertificateError(HandshakeError):

    code = "untrusted_certificate"


class ExpiredCertificateError(HandshakeError):

    code = "certificate_expired"


class RevokedCertificateError(HandshakeError):

    code = "certificate_revoked"


class UnknownIdentityError(HandshakeError):

    code = "unknown_identity"


class VersionMismatchError(HandshakeError):

    code = "version_mismatch"


class BadSignatureError(HandshakeError):

    code = "bad_signature"


class BadFinishedError(HandshakeError):

    code = "bad_finished"


class ChannelError(ProtocolError):

    code = "channel_error"


class ReplayError(ChannelError):

    code = "replay_detected"


class ReorderError(ChannelError):

    code = "reorder_detected"


class StaleFrameError(ChannelError):

    code = "stale_frame"


class DecryptError(ChannelError):

    code = "decrypt_failed"


class EpochError(ChannelError):

    code = "bad_epoch"


class CounterExhaustedError(ChannelError):

    code = "counter_exhausted"


class RekeyError(ChannelError):

    code = "rekey_failed"


class KeystoreError(SecurePayError):

    code = "vault_error"


class BadPassphraseError(KeystoreError):

    code = "vault_auth_failed"


class CorruptVaultError(KeystoreError):

    code = "vault_corrupt"


class AADMismatchError(KeystoreError):

    code = "vault_aad_mismatch"


class PKIError(SecurePayError):

    code = "pki_error"


class LedgerError(SecurePayError):

    code = "ledger_error"


class InsufficientFundsError(LedgerError):

    code = "insufficient_funds"


class DuplicateTxnError(LedgerError):

    code = "duplicate_txn"


class UnknownAccountError(LedgerError):

    code = "unknown_account"


class StaleNonceError(LedgerError):

    code = "stale_nonce"


class PendingRequestError(LedgerError):

    code = "pending_request_error"


class RateLimitError(SecurePayError):

    code = "rate_limited"
