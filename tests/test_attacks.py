"""Each test is an attack. The system must reject it, and say why."""

from __future__ import annotations

import json
import time

import pytest
from conftest import CRLF, directives_of, make_signed, manifest_of, rebuild, resign_manifest, rewrite, root_ring, strip, with_manifest

from exsig import core, keys
from exsig.format import END, START, FormatError, b64encode, canonical_json

# --- content tampering -----------------------------------------------------


def test_one_flipped_byte_in_the_code_is_rejected(signed, ring):
    raw = bytearray(signed.read_bytes())
    raw[raw.index(b"on_send_message_hook")] ^= 0x20  # case flip, still valid Python
    res = core.verify_bytes(bytes(raw), ring)
    assert res.status == core.INVALID and res.exit_code == 1
    assert "digest" in res.summary


def test_edited_metadata_claim_is_rejected(signed, ring):
    raw = signed.read_bytes().replace(b'__version__ = "1.2.0"', b'__version__ = "9.9.9"')
    assert core.verify_bytes(raw, ring).status == core.INVALID


def test_attacker_substitutes_his_own_digest(signed, ring):
    """Edit the code, hash the new code honestly, keep the stolen signature."""
    payload = strip(signed.read_bytes()) + CRLF + b"exfil = True"
    manifest, _, _, _ = manifest_of(signed.read_bytes())
    manifest["files"] = [dict(manifest["files"][0], sha256=core.sha256_hex(payload), size=len(payload))]
    block = dict(directives_of(signed.read_bytes()), manifest=b64encode(canonical_json(manifest)))
    res = core.verify_bytes(rebuild(payload, block), ring)
    assert res.status == core.INVALID and "Ed25519" in " ".join(res.problems)


def test_wrong_size_claim_is_rejected_even_when_re_signed(signed, ring, builder):
    """Right digest, truncated size: the manifest must describe the whole payload."""
    entry = manifest_of(signed.read_bytes())[0]["files"][0]
    res = core.verify_bytes(resign_manifest(signed.read_bytes(), builder,
                                            files=[dict(entry, size=entry["size"] - 1)]), ring)
    assert res.status == core.INVALID and "bytes" in " ".join(res.problems)


def test_genuine_signature_moved_onto_different_code(signed, ring):
    evil = b'__id__ = "demo_plugin"' + CRLF + b'__version__ = "1.2.0"' + CRLF + b"import os"
    res = core.verify_bytes(rebuild(evil, directives_of(signed.read_bytes())), ring)
    assert res.status == core.INVALID and "digest" in res.summary


def test_non_canonical_manifest_is_rejected(signed, ring, builder):
    """Same content, extra whitespace: two parsers could disagree about what was signed."""
    manifest, blob = manifest_of(signed.read_bytes())[:2]
    loose = json.dumps(manifest, sort_keys=True, separators=(",", ": ")).encode("ascii")
    block = dict(directives_of(signed.read_bytes()), manifest=b64encode(loose),
                 sig=b64encode(builder.sign(keys.plugin_tbs(blob))))
    res = core.verify_bytes(rebuild(strip(signed.read_bytes()), block), ring)
    assert res.status == core.INVALID and "canonical" in " ".join(res.problems)


# --- framing attacks -------------------------------------------------------


def test_nested_marker_smuggling_is_rejected(signed, ring):
    """Attacker appends a second block after the real one, hoping the first gets ignored."""
    raw = signed.read_bytes()
    forged = raw[: raw.rindex(START)] + START + CRLF + raw
    with pytest.raises(FormatError, match="nested"):
        core.verify_bytes(forged, ring)


def test_marker_hiding_inside_a_line_is_rejected(signed, ring):
    joined = strip(signed.read_bytes()) + CRLF + b"x = 1 " + START + CRLF
    with pytest.raises(FormatError, match="not at the start"):
        core.verify_bytes(joined, ring)


def test_unclosed_block_is_rejected(signed, ring):
    raw = signed.read_bytes()
    with pytest.raises(FormatError, match="not closed"):
        core.verify_bytes(raw[: raw.rindex(END)], ring)


def test_bytes_after_the_block_are_rejected(signed, ring):
    with pytest.raises(FormatError, match="trailing bytes"):
        core.verify_bytes(signed.read_bytes() + CRLF + b"print('hi')", ring)


def test_executable_line_inside_the_block_is_rejected(signed, ring):
    """A dropped line here would be code the hash never covered."""
    raw = signed.read_bytes().replace(END, b"__import__('os')" + CRLF + END)
    with pytest.raises(FormatError, match="unprotected line"):
        core.verify_bytes(raw, ring)


def test_comment_line_inside_the_block_is_rejected(signed, ring):
    raw = signed.read_bytes().replace(END, b"# note: trust me" + CRLF + END)
    with pytest.raises(FormatError, match="unknown directive"):
        core.verify_bytes(raw, ring)


def test_duplicate_directive_is_rejected(signed, ring):
    block = dict(directives_of(signed.read_bytes()))
    block["sig"] = block["sig"] + "\r\n# sig: " + block["sig"]
# sig: " + block["sig"]
    with pytest.raises(FormatError, match="duplicate"):
        core.verify_bytes(rebuild(strip(signed.read_bytes()), block), ring)


def test_unpinned_root_is_a_prompt_not_a_verdict(builder, root, source, tmp_path):
    """Unknown author != forgery: the host must ask for a fingerprint, not accuse."""
    forged, _ = keys.issue_cert(keys.generate("mallory"), builder.public_b64, "demo-builder", ["demo_plugin"])
    signed = make_signed(source, builder, forged, out=tmp_path / "x.signed.plugin")
    res = core.verify_bytes(signed.read_bytes(), root_ring(tmp_path, root))
    assert res.status == core.UNTRUSTED and res.exit_code == 3
    assert "unpinned root" in " ".join(res.notes)


def test_forged_author_signature_is_untrusted_not_valid(attacker, source, ring, tmp_path):
    """A rival signs their own code with their own key: the math works, the trust does not."""
    forged = make_signed(source, attacker, None, out=tmp_path / "forged.signed.plugin")
    res = core.verify_bytes(forged.read_bytes(), ring)
    assert res.status == core.UNTRUSTED and res.exit_code == 3
    assert "keyring" in " ".join(res.notes)


def test_empty_keyring_verifies_nothing(signed, tmp_path):
    assert core.verify_bytes(signed.read_bytes(), keys.Keyring(tmp_path / "none.json")).status == core.UNTRUSTED


def test_stripping_the_certificate_downgrades_to_untrusted(signed, tmp_path):
    block = {k: v for k, v in directives_of(signed.read_bytes()).items() if k != "cert"}
    res = core.verify_bytes(rebuild(strip(signed.read_bytes()), block), keys.Keyring(tmp_path / "empty.json"))
    assert res.status == core.UNTRUSTED


def test_keyid_swap_is_rejected(signed, ring, root):
    """Point the block at the pinned root key while keeping the builder's signature."""
    res = core.verify_bytes(rewrite(signed.read_bytes(), keyid=root.keyid), ring)
    assert res.status == core.INVALID and "keyid" in " ".join(res.problems)


def test_certificate_signature_cannot_be_reused_as_plugin_signature(signed, ring):
    """Domain separation: a certificate signature is not a plugin signature."""
    _, _, cert, _ = manifest_of(signed.read_bytes())
    res = core.verify_bytes(rewrite(signed.read_bytes(), sig=cert["signature"]), ring)
    assert res.status == core.INVALID and "Ed25519" in " ".join(res.problems)


def test_plugin_signature_cannot_be_reused_as_certificate_signature(signed, ring):
    _, _, cert, _ = manifest_of(signed.read_bytes())
    forged = dict(cert, signature=directives_of(signed.read_bytes())["sig"])
    res = core.verify_bytes(rewrite(signed.read_bytes(), cert=b64encode(canonical_json(forged))), ring)
    assert res.status == core.INVALID and "certificate" in " ".join(res.problems)


def test_revoked_plugin_key_kills_a_still_valid_signature(signed, ring, builder):
    ring.add(builder.keyid, "demo-builder", builder.public_b64, keys.TRUSTED)
    assert core.verify_bytes(signed.read_bytes(), ring).status == core.VALID
    ring.set_state(builder.keyid, keys.REVOKED, "key leaked off the build machine")
    res = core.verify_bytes(signed.read_bytes(), ring)
    assert res.status == core.INVALID and "revoked" in " ".join(res.problems)


def test_revoked_root_key_kills_the_whole_chain(signed, ring, root):
    ring.set_state(root.keyid, keys.REVOKED, "author compromised")
    res = core.verify_bytes(signed.read_bytes(), ring)
    assert res.status == core.INVALID and "revoked" in " ".join(res.problems)


def test_certificate_cannot_authorise_a_different_plugin(builder, root, source, cert, tmp_path):
    evil = tmp_path / "evil.plugin"
    evil.write_bytes(b'__id__ = "evil_plugin"' + CRLF + b'__version__ = "1.0.0"')
    signed = make_signed(evil, builder, cert, out=tmp_path / "evil.signed.plugin")
    res = core.verify_bytes(signed.read_bytes(), root_ring(tmp_path, root))
    assert res.status == core.INVALID and "covers" in " ".join(res.problems)


def test_edited_certificate_is_rejected(signed, ring):
    _, _, cert, _ = manifest_of(signed.read_bytes())
    widened = dict(cert, plugin_ids=sorted(cert["plugin_ids"] + ["any_plugin"]))
    res = core.verify_bytes(rewrite(signed.read_bytes(), cert=b64encode(canonical_json(widened))), ring)
    assert res.status == core.INVALID and "certificate" in " ".join(res.problems)


def test_certificate_subject_keyid_must_hash_to_its_own_key(root, builder, ring):
    cert, _ = keys.issue_cert(root, builder.public_b64, "demo-builder", ["demo_plugin"])
    mallory = keys.generate("mallory")
    swapped = dict(cert, subject_keyid=mallory.keyid)
    body = canonical_json({k: v for k, v in swapped.items() if k != "signature"})
    swapped["signature"] = b64encode(root.sign(keys.cert_tbs(body)))
    ok, reason, _ = keys.check_cert(swapped, canonical_json(swapped), ring)
    assert not ok and "subject keyid" in reason


def test_keyring_refuses_a_pubkey_that_does_not_match_its_keyid(ring, attacker, builder):
    with pytest.raises(ValueError, match="does not match"):
        ring.add(attacker.keyid, "sneaky", builder.public_b64)


def test_expired_certificate_is_rejected(root, builder, source, tmp_path):
    expired, _ = keys.issue_cert(root, builder.public_b64, "demo-builder", ["demo_plugin"], years=0.00001)
    signed = make_signed(source, builder, expired, out=tmp_path / "e.signed.plugin")
    ring = root_ring(tmp_path, root)
    later = int(time.time()) + 7 * 24 * 3600
    assert core.verify_bytes(signed.read_bytes(), ring).status == core.VALID
    assert core.verify_bytes(signed.read_bytes(), ring, at=later).status == core.INVALID


# --- replay / downgrade ----------------------------------------------------


def test_genuine_old_build_cannot_pass_as_the_new_one(source, builder, root, cert, tmp_path):
    old = make_signed(source, builder, cert, version="1.1.9", out=tmp_path / "old.signed.plugin")
    ring = root_ring(tmp_path, root)
    assert core.verify_bytes(old.read_bytes(), ring).status == core.VALID
    res = core.verify_bytes(old.read_bytes(), ring, expect_version="1.2.0")
    assert res.status == core.INVALID and "1.1.9" in res.summary


def test_backdated_sealed_at_breaks_the_signature(signed, ring):
    res = core.verify_bytes(with_manifest(signed.read_bytes(), sealed_at=int(time.time()) + 10 * 3600), ring)
    assert res.status == core.INVALID and "Ed25519" in " ".join(res.problems)
