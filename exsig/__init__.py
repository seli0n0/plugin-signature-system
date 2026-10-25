"""Exteragram plugin signature system — offline SHA-256 + Ed25519 signing."""

from .core import (
    INVALID,
    PERMISSIVE,
    STRICT,
    UNTRUSTED,
    UNSIGNED,
    VALID,
    Result,
    parse_block,
    sha256_hex,
    sign_bytes,
    sign_file,
    strip_signature,
    verify_bytes,
)
from .format import FORMAT, FormatError, read_metadata, split_block
from .keys import (
    CERT_FORMAT,
    Keyring,
    KeyPair,
    fingerprint,
    generate,
    issue_cert,
    keyid_of,
    load_private,
    save_private,
)

__all__ = [
    "FORMAT", "CERT_FORMAT", "FormatError", "Keyring", "KeyPair", "Result", "parse_block",
    "VALID", "INVALID", "UNSIGNED", "UNTRUSTED", "STRICT", "PERMISSIVE",
    "sha256_hex", "sign_bytes", "sign_file", "strip_signature", "verify_bytes",
    "split_block", "read_metadata", "generate", "load_private", "save_private",
    "issue_cert", "keyid_of", "fingerprint",
]
