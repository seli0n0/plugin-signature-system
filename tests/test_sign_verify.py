"""Happy paths: what a correct signature must do."""

from __future__ import annotations

import ast
from pathlib import Path

from conftest import make_signed, root_ring

from exsig import core, keys
from exsig.format import read_metadata, split_block


def test_signed_file_verifies_through_delegated_certificate(signed, ring, cert, root):
    res = core.verify_bytes(signed.read_bytes(), ring)
    assert res.status == core.VALID, res.problems
    assert res.signer["via"] == "certificate"
    assert res.signer["delegated_by"] == root.keyid
    assert res.exit_code == 0


def test_only_the_root_key_never_leaves_the_author(signed, ring, builder):
    """The plugin key is absent from the keyring, yet verification succeeds."""
    assert ring.get(builder.keyid) is None
    assert core.verify_bytes(signed.read_bytes(), ring).status == core.VALID


def test_signed_plugin_is_still_loadable_python(signed):
    raw = signed.read_bytes()
    tree = ast.parse(raw.decode("utf-8"))
    assigned = {t.id for n in tree.body if isinstance(n, ast.Assign) for t in n.targets}
    classes = {n.name for n in tree.body if isinstance(n, ast.ClassDef)}
    assert "__id__" in assigned and "DemoPlugin" in classes
    meta = read_metadata(raw)
    assert meta["__id__"] == "demo_plugin" and meta["__version__"] == "1.2.0"


def test_signature_survives_a_rename(signed, ring, tmp_path):
    """Exteragram chats rename downloads ('Bot Login (2).plugin'); trust must not break."""
    renamed = tmp_path / "2_5398020107131725147.plugin"
    renamed.write_bytes(signed.read_bytes())
    res = core.verify_bytes(renamed.read_bytes(), ring)
    assert res.status == core.VALID
    assert res.manifest["files"][0]["path"] == "demo_plugin.plugin"  # the author's name, not the download name


def test_unsigned_file_is_not_valid(ring, source):
    res = core.verify_bytes(source.read_bytes(), ring)
    assert res.status == core.UNSIGNED and res.exit_code == 2
    assert core.verify_bytes(source.read_bytes(), ring, policy=core.PERMISSIVE).status == core.VALID


def test_directly_pinned_key_without_certificate(source, root, ring):
    signed = make_signed(source, root, cert=None)
    res = core.verify_bytes(signed.read_bytes(), ring)
    assert res.status == core.VALID and res.signer["via"] == "keyring"


def test_trailing_newlines_are_normalised_not_rejected(source, root, tmp_path):
    padded = tmp_path / "padded.plugin"
    padded.write_bytes(source.read_bytes() + b"\r\n\r\n\r\n")
    signed = make_signed(padded, root, None)
    body, block = split_block(signed.read_bytes())
    assert not body.endswith(b"\r\n")
    assert core.verify_bytes(signed.read_bytes(), root_ring(tmp_path, root)).status == core.VALID


def test_expect_flags_pin_id_version_and_key(signed, ring, builder, root):
    assert core.verify_bytes(signed.read_bytes(), ring, expect_version="1.2.0").status == core.VALID
    assert core.verify_bytes(signed.read_bytes(), ring, expect_version="1.3.0").status == core.INVALID
    assert core.verify_bytes(signed.read_bytes(), ring, expect_id="demo_plugin").status == core.VALID
    assert core.verify_bytes(signed.read_bytes(), ring, expect_id="other_plugin").status == core.INVALID
    assert core.verify_bytes(signed.read_bytes(), ring, expect_keyid=builder.keyid).status == core.VALID
    assert core.verify_bytes(signed.read_bytes(), ring, expect_keyid=root.keyid).status == core.INVALID


def test_unknown_key_is_reported_as_untrusted_not_valid(source, attacker, tmp_path):
    signed = make_signed(source, attacker, None, out=tmp_path / "a.signed.plugin")
    res = core.verify_bytes(signed.read_bytes(), keys.Keyring(tmp_path / "empty.json"))
    assert res.status == core.UNTRUSTED and res.exit_code == 3
    assert "fingerprint" in " ".join(res.notes)


def test_strip_recovers_the_original_payload(signed, source):
    assert core.strip_signature(signed.read_bytes()) == split_block(source.read_bytes())[0]
