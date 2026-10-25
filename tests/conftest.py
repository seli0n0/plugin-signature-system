from __future__ import annotations

import re
from pathlib import Path

import pytest
from exsig import core, keys
from exsig.format import b64encode, canonical_json, encode_block, read_metadata, split_block

CRLF = b"\r\n"

SOURCE = '''__id__ = "demo_plugin"
__name__ = "Demo Plugin"
__author__ = "@demo"
__version__ = "1.2.0"


class DemoPlugin:
    def on_send_message_hook(self, text):
        return text
'''


# --- fixtures --------------------------------------------------------------


@pytest.fixture
def source(tmp_path: Path) -> Path:
    path = tmp_path / "demo_plugin.plugin"
    path.write_bytes(SOURCE.replace("\n", "\r\n").encode("utf-8"))
    return path


@pytest.fixture
def root() -> keys.KeyPair:
    return keys.generate("@author-root")


@pytest.fixture
def builder() -> keys.KeyPair:
    return keys.generate("demo-builder")


@pytest.fixture
def attacker() -> keys.KeyPair:
    return keys.generate("@rival-author")


@pytest.fixture
def ring(tmp_path: Path, root: keys.KeyPair) -> keys.Keyring:
    return root_ring(tmp_path, root)


@pytest.fixture
def cert(root: keys.KeyPair, builder: keys.KeyPair) -> dict:
    issued, _ = keys.issue_cert(root, builder.public_b64, "demo-builder", ["demo_plugin"])
    return issued


@pytest.fixture
def signed(source, builder, cert) -> Path:
    return make_signed(source, builder, cert)


# --- helpers ---------------------------------------------------------------


def make_signed(source: Path, pair: keys.KeyPair, cert: dict | None = None,
                version: str | None = None, out: Path | None = None) -> Path:
    meta = dict(read_metadata(source.read_bytes()))
    if version:
        meta["__version__"] = version
    target = out or source.with_suffix(".signed.plugin")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(core.sign_bytes(source.read_bytes(), pair, meta, source.name, cert))
    return target


def root_ring(tmp_path: Path, root: keys.KeyPair) -> keys.Keyring:
    ring = keys.Keyring(tmp_path / "keyring.json")
    ring.add(root.keyid, "@author-root", root.public_b64, keys.TRUSTED, "author root")
    return ring


def directives_of(raw: bytes) -> dict[str, str]:
    return split_block(raw)[1]


def manifest_of(raw: bytes):
    return core.parse_block(directives_of(raw))


def strip(raw: bytes) -> bytes:
    return core.strip_signature(raw)


def rebuild(payload: bytes, directives: dict[str, str]) -> bytes:
    return payload + CRLF + encode_block(directives) + CRLF


def rewrite(raw: bytes, **changes) -> bytes:
    """Swap directive values while keeping the framing intact."""
    text = raw.decode("utf-8")
    for key, value in changes.items():
        text = re.sub(rf"(# {key}: )[^\r\n]+", rf"\g<1>{value}", text)
    return text.encode("utf-8")


def with_manifest(raw: bytes, **changes) -> bytes:
    """Rewrite the manifest; the copied signature can no longer cover it."""
    manifest, _, _, _ = manifest_of(raw)
    manifest.update(changes)
    return rewrite(raw, manifest=b64encode(canonical_json(manifest)))


def resign_manifest(raw: bytes, key, **changes) -> bytes:
    """Edit the manifest and sign it again with a key the victim already trusts."""
    manifest, _, _, _ = manifest_of(raw)
    manifest.update(changes)
    blob = canonical_json(manifest)
    block = dict(directives_of(raw), manifest=b64encode(blob), sig=b64encode(key.sign(keys.plugin_tbs(blob))))
    return rebuild(strip(raw), block)
