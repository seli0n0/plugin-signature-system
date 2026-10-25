"""Keys, delegated certificates and the local keyring. No server anywhere.

Three tiers, all offline:
  root key      — the author's identity, kept cold, only ever signs certificates
  plugin key    — signs one plugin id, lives on the build machine, may leak
  keyring.json  — the public half, a plain file you move however you like
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import format as fmt

CERT_FORMAT = "EXTERA-CERT-V1"
KEYID_LEN = 16
TRUSTED, REVOKED = "trusted", "revoked"


def keyid_of(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:KEYID_LEN]


def fingerprint(pub_raw: bytes) -> str:
    full = hashlib.sha256(pub_raw).hexdigest()
    return ":".join(full[i : i + 4] for i in range(0, len(full), 4))


@dataclass(frozen=True)
class KeyPair:
    keyid: str
    private: Ed25519PrivateKey
    public_raw: bytes

    @property
    def public_b64(self) -> str:
        return fmt.b64encode(self.public_raw)

    def sign(self, tbs: bytes) -> bytes:
        return self.private.sign(tbs)


def generate(name: str) -> KeyPair:
    private = Ed25519PrivateKey.generate()
    pub_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return KeyPair(keyid_of(pub_raw), private, pub_raw)


def load_private(path: Path, password: bytes | None = None) -> KeyPair:
    blob = path.read_bytes()
    try:
        private = serialization.load_pem_private_key(blob, password=password)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"cannot read private key {path}: {exc}") from exc
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 key")
    pub_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return KeyPair(keyid_of(pub_raw), private, pub_raw)


def save_private(key: KeyPair, path: Path, name: str, password: bytes | None = None) -> None:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    pem = key.private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    header = f"# exsig keyid {key.keyid} name {name}\n".encode("ascii")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(header + pem)
    _harden(path, read_only=True)
    side = path.with_suffix(".pub.json")
    side.write_text(
        json.dumps(
            {"keyid": key.keyid, "name": name, "pubkey": key.public_b64, "algo": "ed25519"},
            indent=2,
        )
        + "\n",
        "ascii",
    )
    _harden(side, read_only=False)


def _harden(path: Path, read_only: bool) -> None:
    if os.name == "nt":
        return
    path.chmod(stat.S_IRUSR | (0 if read_only else stat.S_IWUSR))


def pub_from_b64(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(fmt.b64decode(value, "pubkey"))


def verify_sig(pub: Ed25519PublicKey, signature: bytes, tbs: bytes) -> bool:
    try:
        pub.verify(signature, tbs)
        return True
    except InvalidSignature:
        return False


def plugin_tbs(manifest_bytes: bytes) -> bytes:
    return b"EXTERA-PLUGIN-V1|" + hashlib.sha256(manifest_bytes).digest()


def cert_tbs(cert_bytes: bytes) -> bytes:
    return b"EXTERA-CERT-V1|" + hashlib.sha256(cert_bytes).digest()


def issue_cert(
    issuer: KeyPair,
    subject_pub_b64: str,
    subject_name: str,
    plugin_ids: list[str],
    years: float = 5.0,
) -> tuple[dict, bytes]:
    """Delegate a plugin key for named plugin ids only, signed by the root key."""
    subject_raw = fmt.b64decode(subject_pub_b64, "pubkey")
    now = int(time.time())
    cert = {
        "format": CERT_FORMAT,
        "subject_keyid": keyid_of(subject_raw),
        "subject_pubkey": subject_pub_b64,
        "subject_name": subject_name,
        "plugin_ids": sorted(plugin_ids),
        "issued_by": issuer.keyid,
        "issued_at": now,
        "expires_at": now + int(years * 365 * 24 * 3600),
    }
    blob = fmt.canonical_json(cert)
    cert["signature"] = fmt.b64encode(issuer.sign(cert_tbs(blob)))
    return cert, fmt.canonical_json(cert)


def check_cert(
    cert: dict, cert_bytes: bytes, ring: "Keyring", at: int | None = None
) -> tuple[bool, str, str]:
    """Validate a certificate; returns (ok, reason, kind).

    kind "unknown" means the chain leads to a root nobody pinned yet, which is a
    prompt to go confirm a fingerprint - not proof of forgery like "invalid".
    """
    bad = lambda reason: (False, reason, "invalid")  # noqa: E731
    if cert.get("format") != CERT_FORMAT:
        return bad(f"unsupported certificate format {cert.get('format')!r}")
    if fmt.canonical_json(cert) != cert_bytes:
        return bad("certificate is not canonically encoded")
    # The issuer signs the certificate without its own signature field.
    unsigned_bytes = fmt.canonical_json({k: v for k, v in cert.items() if k != "signature"})
    issuer_key = ring.get(cert.get("issued_by", ""))
    issuer_key = ring.get(cert.get("issued_by")) if cert.get("issued_by") else None
    if issuer_key is None:
        return False, f"issuer key {cert.get('issued_by')!r} is not in the keyring", "unknown"
    if issuer_key["state"] == REVOKED:
        return bad(f"issuer key {cert.get('issued_by')} is revoked")
    signature = cert.get("signature", "")
    if not isinstance(signature, str):
        return bad("certificate signature is not a string")
    try:
        sig = fmt.b64decode(signature, "certificate signature")
    except fmt.FormatError as exc:
        return bad(str(exc))
    if not verify_sig(pub_from_b64(issuer_key["pubkey"]), sig, cert_tbs(unsigned_bytes)):
        return bad("certificate signature does not verify against the issuer key")
    now = int(time.time()) if at is None else at
    if not isinstance(cert.get("issued_at"), int) or now < cert["issued_at"]:
        return bad("certificate is not valid yet")
    if not isinstance(cert.get("expires_at"), int) or now >= cert["expires_at"]:
        return bad("certificate has expired")
    if not isinstance(cert.get("subject_pubkey"), str):
        return bad("certificate has no subject public key")
    subject_keyid = keyid_of(fmt.b64decode(cert["subject_pubkey"], "subject_pubkey"))
    if subject_keyid != cert.get("subject_keyid"):
        return bad("certificate subject keyid does not match its public key")
    if subject_keyid in ring.revoked_keyids():
        return bad(f"subject key {subject_keyid} is revoked")
    return True, "ok", "certificate"


class Keyring:
    """A JSON file of public keys. Sync it by git, by chat, by USB — no service needed."""

    def __init__(self, path: Path, data: dict | None = None):
        self.path = path
        self.entries: dict[str, dict] = (data or {}).get("keys", {})

    @classmethod
    def load(cls, path: Path) -> "Keyring":
        if not path.exists():
            return cls(path, {"keys": {}})
        try:
            data = json.loads(path.read_text("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"keyring {path} is not valid JSON: {exc}") from exc
        return cls(path, data)

    def save(self) -> None:
        payload = json.dumps({"format": "EXTERA-KEYRING-V1", "keys": self.entries}, indent=2, sort_keys=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(payload + "\n", "ascii")
        os.replace(tmp, self.path)

    def add(self, keyid: str, name: str, pubkey_b64: str, state: str = TRUSTED, note: str = "") -> None:
        if keyid != keyid_of(fmt.b64decode(pubkey_b64, "pubkey")):
            raise ValueError(f"keyid {keyid} does not match the given public key")
        existing = self.entries.get(keyid)
        if existing and existing["pubkey"] != pubkey_b64:
            raise ValueError(f"keyid {keyid} already holds a different public key")
        self.entries[keyid] = {
            "name": name,
            "pubkey": pubkey_b64,
            "state": state,
            "note": note,
            "added_at": (existing or {}).get("added_at", int(time.time())),
            "changed_at": int(time.time()),
        }

    def get(self, keyid: str) -> dict | None:
        return self.entries.get(keyid)

    def set_state(self, keyid: str, state: str, note: str = "") -> None:
        if keyid not in self.entries:
            raise KeyError(keyid)
        self.entries[keyid]["state"] = state
        self.entries[keyid]["changed_at"] = int(time.time())
        if note:
            self.entries[keyid]["note"] = note

    def revoke_keyid(self, keyid: str, note: str = "", name: str = "(revoked)") -> bool:
        """Record a revocation for a key we may never have held.

        A leaked build key is published inside every plugin it signed, so the
        revocation list has to be writable without knowing the public key.
        Returns True when a tombstone had to be created.
        """
        if keyid in self.entries:
            self.set_state(keyid, REVOKED, note)
            return False
        self.entries[keyid] = {
            "name": name,
            "pubkey": "",
            "state": REVOKED,
            "note": note,
            "added_at": int(time.time()),
            "changed_at": int(time.time()),
        }
        return True

    def revoked_keyids(self) -> set[str]:
        return {k for k, v in self.entries.items() if v["state"] == REVOKED}

    def trusted_keyids(self) -> set[str]:
        return {k for k, v in self.entries.items() if v["state"] == TRUSTED}
