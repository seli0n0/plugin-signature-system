"""Round-trip over the author's real Exteragram plugins, when they are on disk.

These files are not in the repository, so the test skips elsewhere; on the
machine that produced the format spec it exercises every plugin it finds.
"""

from __future__ import annotations

import ast
import os
from pathlib import Path

import pytest
from conftest import CRLF

from exsig import core, keys
from exsig.format import encode_block, read_metadata, split_block

REAL_DIR = Path(os.environ.get(
    "EXTERAGRAM_PLUGIN_DIR", str(Path.home() / "Desktop" / "раб стол" / "plugin")))

pytestmark = pytest.mark.skipif(not REAL_DIR.is_dir(), reason="real plugin folder not present")


def real_plugins(limit: int = 120) -> list[Path]:
    return sorted(p for p in REAL_DIR.glob("*.plugin") if p.stat().st_size < 400_000)[:limit]


def meta_of(path: Path) -> dict:
    meta = dict(read_metadata(path.read_bytes()))
    meta.setdefault("__id__", path.stem.replace(" ", "_").replace("(", "").replace(")", ""))
    return meta


@pytest.fixture(scope="module")
def author_and_ring(tmp_path_factory):
    author = keys.generate("@extera")
    ring = keys.Keyring(tmp_path_factory.mktemp("ring") / "keyring.json")
    ring.add(author.keyid, "@extera", author.public_b64, keys.TRUSTED)
    return author, ring


def test_every_real_plugin_is_python3_and_declares_metadata():
    unparsable = [p.name for p in real_plugins()
                  if not _parses(p)]
    assert not unparsable, f"not valid python3: {unparsable[:5]}"
    no_id = [p.name for p in real_plugins() if "__id__" not in read_metadata(p.read_bytes())]
    assert len(no_id) < len(real_plugins()) / 5, f"plugins without __id__: {no_id[:5]}"


def _parses(path: Path) -> bool:
    try:
        ast.parse(path.read_bytes().decode("utf-8"))
        return True
    except (SyntaxError, UnicodeDecodeError):
        return False


def test_signed_real_plugins_verify_and_still_load(tmp_path, author_and_ring):
    author, ring = author_and_ring
    builder = keys.generate("build-server")
    cert, _ = keys.issue_cert(author, builder.public_b64, "build-server",
                              [meta_of(p)["__id__"] for p in real_plugins()])
    checked = 0
    for path in real_plugins():
        meta = meta_of(path)
        signed = core.sign_bytes(path.read_bytes(), builder, meta, path.name, cert)
        result = core.verify_bytes(signed, ring)
        assert result.status == core.VALID, (path.name, result.summary, result.problems)
        assert result.manifest["plugin_id"] == meta["__id__"]
        ast.parse(signed.decode("utf-8"))
        assert read_metadata(signed) == meta
        checked += 1
    assert checked >= 100


def test_one_flipped_byte_in_any_real_plugin_breaks_verification(author_and_ring):
    author, ring = author_and_ring
    for path in real_plugins(40):
        signed = core.sign_bytes(path.read_bytes(), author, meta_of(path), path.name)
        body, block = split_block(signed)
        broken = body[:-1] + bytes([body[-1] ^ 0x01])
        res = core.verify_bytes(broken + CRLF + encode_block(block) + CRLF, ring)
        assert res.status == core.INVALID and "digest" in res.summary, path.name


def test_real_file_renamed_by_a_chat_still_verifies(tmp_path, author_and_ring):
    """Telegram rewrites download names; a signature keyed on the filename would break."""
    author, ring = author_and_ring
    path = real_plugins(1)[0]
    signed = core.sign_bytes(path.read_bytes(), author, meta_of(path), path.name)
    renamed = tmp_path / "2_5398020107131725147.plugin"
    renamed.write_bytes(signed)
    assert core.verify_bytes(renamed.read_bytes(), ring).status == core.VALID
