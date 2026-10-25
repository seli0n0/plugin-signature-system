""".eaf bundles: packing, entry-level signing, and the attacks a folder invites."""

from __future__ import annotations

import io
import os
import stat
import zipfile
from pathlib import Path

import pytest
from conftest import SOURCE
from exsig import archive, core, keys
from exsig.format import b64encode, canonical_json, encode_block, split_block

_DESKTOP = Path.home() / "Desktop" / "раб стол"
REAL_DIRS = [Path(p) for p in os.environ.get(
    "EXTERAGRAM_EAF_DIR",
    str(_DESKTOP / "coremanager") + os.pathsep + str(_DESKTOP / "elyxbuild")).split(os.pathsep) if p]

HELP = "# helper\n"


@pytest.fixture
def bundle_dir(tmp_path: Path) -> Path:
    folder = tmp_path / "demo"
    (folder / "src").mkdir(parents=True)
    (folder / "locales").mkdir()
    (folder / "src" / "main.py").write_bytes(SOURCE.replace("\n", "\r\n").encode("utf-8"))
    (folder / "locales" / "en.yml").write_bytes(HELP.encode("utf-8"))
    return folder


@pytest.fixture
def bundle(bundle_dir: Path, tmp_path: Path) -> Path:
    out = tmp_path / "demo.eaf"
    archive.pack(bundle_dir, out)
    return out


@pytest.fixture
def signed_bundle(bundle: Path, builder, cert) -> Path:
    out = bundle.with_name("demo.signed.eaf")
    core.sign_file(bundle, builder, out, cert=cert)
    return out


def paths_of(raw: bytes) -> list[str]:
    return [entry["path"] for entry in archive.entry_digests(raw)]


def comment_block(raw: bytes) -> dict[str, str] | None:
    return split_block(archive.read_comment(raw))[1]


def manifest_of_bundle(raw: bytes):
    return core.parse_block(comment_block(raw))


def repack(raw: bytes, add: dict[str, bytes] | None = None, drop: set[str] = frozenset(),
           replace: dict[str, bytes] | None = None) -> bytes:
    """Rebuild an archive the way a careless extraction tool would, keeping the old signature."""
    source = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            if info.filename in drop:
                continue
            data = (replace or {}).get(info.filename)
            target.writestr(info, source.read(info) if data is None else data)
        for name, data in (add or {}).items():
            target.writestr(name, data)
        target.comment = source.comment
    return out.getvalue()


def hostile(entries: list[tuple[str, bytes, int]]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as archive_file:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive_file.writestr(info, data)
    return out.getvalue()


# --- packing ----------------------------------------------------------------


def test_pack_produces_the_layout_the_host_reads(bundle: Path):
    entries = set(paths_of(bundle.read_bytes()))
    assert entries == {"plugin/src/main.py", "plugin/meta.yml", "plugin/locales/en.yml", "refmap.yml"}
    refmap = zipfile.ZipFile(bundle).read("refmap.yml").decode()
    assert "metainfo: plugin/meta.yml" in refmap and "main: plugin/src/main.py" in refmap
    assert "assets:" not in refmap and "strings: plugin/locales" in refmap


def test_pack_of_a_bare_plugin_carries_its_declared_identity(source: Path, tmp_path: Path):
    out = tmp_path / "demo.eaf"
    archive.pack(source, out)
    meta = archive.bundle_identity(archive.entry_digests(out.read_bytes()), out.read_bytes())
    assert meta["id"] == "demo_plugin" and meta["version"] == "1.2.0"
    assert paths_of(out.read_bytes()) == ["plugin/meta.yml", "plugin/src/main.py", "refmap.yml"]


def test_packing_the_same_folder_twice_gives_the_same_bytes(bundle_dir: Path, tmp_path: Path):
    first, second = tmp_path / "a.eaf", tmp_path / "b.eaf"
    archive.pack(bundle_dir, first)
    archive.pack(bundle_dir, second)
    assert first.read_bytes() == second.read_bytes()


def test_pack_refuses_a_folder_without_an_entry_point(tmp_path: Path):
    empty = tmp_path / "nothing"
    empty.mkdir()
    (empty / "README.md").write_text("hi")
    with pytest.raises(archive.ArchiveError, match="entry point"):
        archive.pack(empty, tmp_path / "x.eaf")


# --- the honest round trip ---------------------------------------------------


def test_a_signed_bundle_verifies_and_unpacks_to_the_signed_bytes(signed_bundle: Path, ring, tmp_path):
    result = core.verify_bytes(signed_bundle.read_bytes(), ring)
    assert result.status == core.VALID and result.exit_code == 0, result.problems
    assert result.manifest["container"] == "eaf"
    signed = {entry["path"]: entry["sha256"] for entry in result.manifest["files"]}
    written = archive.unpack(signed_bundle.read_bytes(), tmp_path / "tree")
    for path in written:
        relative = path.relative_to(tmp_path / "tree").as_posix()
        assert core.sha256_hex(path.read_bytes()) == signed[relative]


def test_a_bundle_renamed_by_a_chat_still_verifies(signed_bundle: Path, ring, tmp_path):
    renamed = tmp_path / "2_5246703779318901442.eaf"
    renamed.write_bytes(signed_bundle.read_bytes())
    assert core.verify_bytes(renamed.read_bytes(), ring).status == core.VALID


def test_unsigned_bundle_is_unsigned_not_forged(bundle: Path, ring):
    result = core.verify_bytes(bundle.read_bytes(), ring)
    assert result.status == core.UNSIGNED and result.exit_code == 2


def test_bundle_signed_by_an_unknown_author_is_untrusted(bundle: Path, attacker, tmp_path):
    out = bundle.with_name("x.signed.eaf")
    core.sign_file(bundle, attacker, out)
    result = core.verify_bytes(out.read_bytes(), keys.Keyring(tmp_path / "empty.json"))
    assert result.status == core.UNTRUSTED and result.exit_code == 3


def test_certificate_must_cover_the_id_the_bundle_declares(bundle: Path, root, builder, tmp_path):
    """meta.yml says demo_plugin; a certificate for someone else cannot lend it authority."""
    wrong, _ = keys.issue_cert(root, builder.public_b64, "demo-builder", ["other_plugin"])
    out = bundle.with_name("w.signed.eaf")
    core.sign_file(bundle, builder, out, cert=wrong)
    ring = keys.Keyring(tmp_path / "k.json")
    ring.add(root.keyid, "@author-root", root.public_b64, keys.TRUSTED)
    result = core.verify_bytes(out.read_bytes(), ring)
    assert result.status == core.INVALID and "certificate covers" in " ".join(result.problems)


def test_bundle_version_downgrade_is_caught_by_expect_version(signed_bundle: Path, ring):
    assert core.verify_bytes(signed_bundle.read_bytes(), ring, expect_version="1.2.0").status == core.VALID
    result = core.verify_bytes(signed_bundle.read_bytes(), ring, expect_version="1.3.0")
    assert result.status == core.INVALID and "version" in result.summary


# --- attacks on the archive --------------------------------------------------


def test_edited_entry_is_rejected(signed_bundle: Path, ring):
    evil = (SOURCE + "\nimport os\n").replace("\n", "\r\n").encode("utf-8")
    tampered = repack(signed_bundle.read_bytes(), replace={"plugin/src/main.py": evil})
    result = core.verify_bytes(tampered, ring)
    assert result.status == core.INVALID and "plugin/src/main.py" in " ".join(result.problems)


def test_injected_entry_is_rejected(signed_bundle: Path, ring):
    tampered = repack(signed_bundle.read_bytes(), add={"plugin/src/exfil.py": b"import os"})
    result = core.verify_bytes(tampered, ring)
    assert result.status == core.INVALID and "not covered by the signature" in " ".join(result.problems)


def test_dropped_entry_is_rejected(signed_bundle: Path, ring):
    tampered = repack(signed_bundle.read_bytes(), drop={"plugin/locales/en.yml"})
    result = core.verify_bytes(tampered, ring)
    assert result.status == core.INVALID and "missing from the archive" in " ".join(result.problems)


def test_two_entries_with_one_name_are_refused(signed_bundle: Path, ring):
    """zipfile reads the first, other extractors the last: the signed bytes need not be the executed ones."""
    doubled = repack(signed_bundle.read_bytes(), add={"plugin/src/main.py": b"import os"})
    result = core.verify_bytes(doubled, ring)
    assert result.status == core.INVALID and "duplicate entry" in " ".join(result.problems)


def test_path_traversal_entry_is_refused(ring, tmp_path):
    escaping = hostile([("../evil.py", b"import os", 0o100644), ("refmap.yml", b"", 0o100644)])
    result = core.verify_bytes(escaping, ring)
    assert result.status == core.INVALID and "unsafe entry name" in " ".join(result.problems)
    with pytest.raises(archive.ArchiveError, match="unsafe entry name"):
        archive.unpack(escaping, tmp_path / "tree")
    assert not (tmp_path / "evil.py").exists()


def test_symlink_entry_is_refused(ring, tmp_path):
    link = hostile([("plugin/link", b"/etc/passwd", stat.S_IFLNK | 0o777)])
    assert core.verify_bytes(link, ring).status == core.INVALID
    with pytest.raises(archive.ArchiveError, match="symlink"):
        archive.unpack(link, tmp_path / "tree")


def test_bombs_are_refused_by_the_limits(tmp_path):
    many = io.BytesIO()
    with zipfile.ZipFile(many, "w") as target:
        for index in range(20):
            target.writestr(f"plugin/src/f{index}.py", HELP.encode())
    raw = many.getvalue()
    assert len(archive.entry_digests(raw)) == 20
    with pytest.raises(archive.ArchiveError, match="exceeds the limit"):
        archive.entry_digests(raw, max_entries=8)
    with pytest.raises(archive.ArchiveError, match="uncompressed size"):
        archive.entry_digests(raw, max_bytes=40)


def test_single_file_signature_moved_onto_a_bundle_is_rejected(signed, ring, bundle: Path):
    """A block signed for a .plugin cannot vouch for a folder of files."""
    _, block = split_block(signed.read_bytes())
    swapped = archive.write_comment(bundle.read_bytes(), encode_block(block))
    result = core.verify_bytes(swapped, ring)
    assert result.status == core.INVALID and "container" in " ".join(result.problems)


def test_bundle_signature_moved_onto_a_plain_file_is_rejected(signed_bundle: Path, ring, source: Path):
    tampered = source.read_bytes() + b"\r\n" + encode_block(comment_block(signed_bundle.read_bytes())) + b"\r\n"
    result = core.verify_bytes(tampered, ring)
    assert result.status == core.INVALID and "bundle" in " ".join(result.problems)


def test_comment_replaced_with_a_forged_manifest_is_rejected(signed_bundle: Path, ring, builder):
    """Re-sign the manifest with the trusted key, but describe different bytes."""
    manifest, _, _, _ = manifest_of_bundle(signed_bundle.read_bytes())
    manifest["files"] = [dict(entry, sha256="0" * 64) for entry in manifest["files"]]
    blob = canonical_json(manifest)
    block = dict(comment_block(signed_bundle.read_bytes()), manifest=b64encode(blob),
                 sig=b64encode(builder.sign(keys.plugin_tbs(blob))))
    forged = archive.write_comment(signed_bundle.read_bytes(), encode_block(block))
    result = core.verify_bytes(forged, ring)
    assert result.status == core.INVALID and "hashes to" in " ".join(result.problems)


def test_signature_block_larger_than_the_zip_comment_is_refused(bundle: Path, builder):
    with pytest.raises(archive.ArchiveError, match="at most"):
        archive.write_comment(bundle.read_bytes(), b"x" * (archive.MAX_COMMENT + 1))
    with pytest.raises(ValueError, match="sign_bundle"):
        core.sign_bytes(bundle.read_bytes(), builder, {}, "demo.eaf")


def test_strip_removes_the_block_and_keeps_the_content(signed_bundle: Path, bundle: Path, ring):
    stripped = core.strip_signature(signed_bundle.read_bytes())
    assert comment_block(stripped) is None
    assert paths_of(stripped) == paths_of(bundle.read_bytes())
    assert core.verify_bytes(stripped, ring).status == core.UNSIGNED


# --- the real archives -------------------------------------------------------


def real_bundles() -> list[Path]:
    found = [p for folder in REAL_DIRS if folder.is_dir() for p in sorted(folder.glob("*.eaf"))]
    return found


@pytest.mark.parametrize("path", real_bundles() or [Path("none")], ids=lambda p: p.name)
def test_every_real_bundle_signs_verifies_and_unpacks(path: Path, tmp_path, builder):
    """The signature must survive a real pack -> sign -> unpack -> repack cycle."""
    if not path.is_file():
        pytest.skip("no real .eaf archives on this machine")
    raw = path.read_bytes()
    entries = archive.entry_digests(raw)
    identity = archive.bundle_identity(entries, raw)
    ring = keys.Keyring(tmp_path / "keyring.json")
    ring.add(builder.keyid, "demo-builder", builder.public_b64, keys.TRUSTED)
    out = tmp_path / "signed.eaf"
    core.sign_file(path, builder, out, plugin_id=identity.get("id") or None)
    result = core.verify_bytes(out.read_bytes(), ring)
    assert result.status == core.VALID, (path.name, result.summary, result.problems)

    written = archive.unpack(out.read_bytes(), tmp_path / "tree")
    signed = {entry["path"]: entry["sha256"] for entry in result.manifest["files"]}
    assert len(written) == len(signed)
    for file in written:
        relative = file.relative_to(tmp_path / "tree").as_posix()
        assert core.sha256_hex(file.read_bytes()) == signed[relative]

    tampered = repack(out.read_bytes(), add={"plugin/src/payload.py": b"import os"})
    assert core.verify_bytes(tampered, ring).status == core.INVALID


def test_real_bundle_entry_names_stay_inside_the_root():
    for path in real_bundles():
        for entry in archive.entry_digests(path.read_bytes()):
            assert not entry["path"].startswith("/")
            assert archive.check_entry_name(entry["path"]).parts
