"""The command line is what the host will shell out to, so its exit codes are the contract."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from conftest import SOURCE

from exsig import cli

UNSIGNED_SOURCE = SOURCE.replace("\n", "\r\n").encode("utf-8")


@pytest.fixture
def workspace(tmp_path: Path):
    plugin = tmp_path / "demo_plugin.plugin"
    plugin.write_bytes(UNSIGNED_SOURCE)
    keys_dir = tmp_path / "keys"
    ring = tmp_path / "keyring.json"
    args = ["--keyring", str(ring)]
    assert cli.main([*args, "keygen", "--name", "@extera", "--out", str(keys_dir)]) == 0
    assert cli.main([*args, "keygen", "--name", "demo-builder", "--out", str(keys_dir)]) == 0
    root = keys_dir / "@extera.key"
    builder = keys_dir / "demo-builder.key"
    assert cli.main([*args, "cert-issue", "--root", str(root),
                     "--subject-pub", str(builder.with_suffix(".pub.json")),
                     "--plugin-id", "demo_plugin", "--out", str(tmp_path / "cert.json")]) == 0
    assert cli.main([*args, "keyring", "add", "--pub", str(root.with_suffix(".pub.json")),
                     "--note", "author root"]) == 0
    return {"args": args, "plugin": plugin, "root": root, "builder": builder,
            "cert": tmp_path / "cert.json", "ring": ring, "out": tmp_path / "demo_plugin.signed.plugin"}


def run(*argv) -> int:
    return cli.main(list(argv))


def test_full_author_to_host_pipeline(workspace, capsys):
    args, out = workspace["args"], workspace["out"]
    assert run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
               "--cert", str(workspace["cert"]), "--out", str(out)) == 0
    assert run(*args, "verify", str(out)) == 0
    printed = capsys.readouterr().out
    assert "[OK]" in printed and "delegated by" in printed

    assert run(*args, "verify", str(out), "--json") == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "valid" and payload["plugin_id"] == "demo_plugin"
    assert payload["signer"]["via"] == "certificate"


def test_verify_exit_codes_tell_the_host_what_to_do(workspace):
    args = workspace["args"]
    assert run(*args, "verify", str(workspace["plugin"])) == 2  # unsigned
    assert run(*args, "verify", str(workspace["plugin"]), "--policy", "permissive") == 0
    assert run(*args, "keyring", "revoke", "--keyid", json.loads(
        workspace["root"].with_suffix(".pub.json").read_text())["keyid"]) == 0
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--cert", str(workspace["cert"]), "--out", str(workspace["out"]))
    assert run(*args, "verify", str(workspace["out"])) == 1  # revoked chain


def test_a_leaked_build_key_is_revoked_without_ever_having_been_pinned(workspace, capsys):
    """The whole no-server story hinges on this: revoke by keyid alone."""
    args = workspace["args"]
    build_keyid = json.loads(workspace["builder"].with_suffix(".pub.json").read_text())["keyid"]
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--cert", str(workspace["cert"]), "--out", str(workspace["out"]))
    assert run(*args, "verify", str(workspace["out"])) == 0
    assert run(*args, "keyring", "revoke", "--keyid", build_keyid, "--note", "build server compromised") == 0
    assert "tombstone" in capsys.readouterr().out
    assert run(*args, "verify", str(workspace["out"])) == 1
    assert "revoked" in capsys.readouterr().out


def test_verify_fails_a_tampered_signed_file(workspace, capsys):
    args, out = workspace["args"], workspace["out"]
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--cert", str(workspace["cert"]), "--out", str(out))
    raw = bytearray(out.read_bytes())
    raw[raw.index(b"on_send_message_hook")] ^= 0x20
    out.write_bytes(bytes(raw))
    assert run(*args, "verify", str(out)) == 1
    assert "digest" in capsys.readouterr().out


def test_sign_writes_a_copy_unless_told_otherwise(workspace):
    args = workspace["args"]
    before = workspace["plugin"].read_bytes()
    assert run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"])) == 0
    assert workspace["plugin"].read_bytes() == before, "the author's source file must stay untouched"


def test_signing_twice_without_strip_is_refused(workspace):
    args = workspace["args"]
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--out", str(workspace["out"]))
    assert run(*args, "sign", str(workspace["out"]), "--key", str(workspace["builder"]),
               "--out", str(workspace["out"])) == 1


def test_strip_then_resign_roundtrip(workspace):
    args, out = workspace["args"], workspace["out"]
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--cert", str(workspace["cert"]), "--out", str(out))
    stripped = workspace["plugin"].with_name("restored.plugin")
    assert run(*args, "strip", str(out), "--out", str(stripped)) == 0
    assert run(*args, "verify", str(stripped)) == 2
    assert run(*args, "sign", str(stripped), "--key", str(workspace["builder"]),
               "--cert", str(workspace["cert"]), "--out", str(out)) == 0


def test_info_decodes_without_a_keyring(workspace, capsys, tmp_path):
    args, out = workspace["args"], workspace["out"]
    run(*args, "sign", str(workspace["plugin"]), "--key", str(workspace["builder"]),
        "--cert", str(workspace["cert"]), "--out", str(out))
    assert run("--keyring", str(tmp_path / "nope.json"), "info", str(out)) == 0
    text = capsys.readouterr().out
    assert '"plugin_id": "demo_plugin"' in text and "certificate" in text


def test_keyring_list_and_export_keep_only_public_halves(workspace, capsys):
    args = workspace["args"]
    assert run(*args, "keyring", "list") == 0
    assert "@extera" in capsys.readouterr().out
    exported = workspace["ring"].with_name("shared.json")
    assert run(*args, "keyring", "export", "--out", str(exported)) == 0
    assert "PRIVATE KEY" not in exported.read_text()
    assert json.loads(exported.read_text())["keys"]


def test_passphrase_protected_root_key_signs_and_verifies(workspace, tmp_path):
    args = workspace["args"]
    keys_dir = tmp_path / "locked"
    assert run(*args, "keygen", "--name", "@vault", "--out", str(keys_dir),
               "--password", "hunter2") == 0
    pem = (keys_dir / "@vault.key").read_text()
    assert "ENCRYPTED" in pem, "the private half must not sit on disk in the clear"
    assert run(*args, "sign", str(workspace["plugin"]), "--key", str(keys_dir / "@vault.key"),
               "--out", str(tmp_path / "vault.signed.plugin")) == 1  # no password given
    assert run(*args, "sign", str(workspace["plugin"]), "--key", str(keys_dir / "@vault.key"),
               "--password", "hunter2", "--out", str(tmp_path / "vault.signed.plugin")) == 0
    assert run(*args, "keyring", "add", "--pub", str(keys_dir / "@vault.pub.json")) == 0
    assert run(*args, "verify", str(tmp_path / "vault.signed.plugin")) == 0


# --- .eaf bundles through the CLI --------------------------------------------


@pytest.fixture
def bundle_folder(tmp_path: Path) -> Path:
    folder = tmp_path / "demo"
    (folder / "src").mkdir(parents=True)
    (folder / "src" / "main.py").write_bytes(UNSIGNED_SOURCE)
    return folder


def test_pack_sign_verify_unpack_pipeline(workspace, bundle_folder, tmp_path, capsys):
    args = workspace["args"]
    bundle = tmp_path / "demo.eaf"
    assert run(*args, "pack", str(bundle_folder), "--out", str(bundle)) == 0
    listing = capsys.readouterr().out
    assert "plugin/src/main.py" in listing and "refmap.yml" in listing

    signed = tmp_path / "demo.signed.eaf"
    assert run(*args, "sign", str(bundle), "--key", str(workspace["builder"]),
               "--cert", str(workspace["cert"]), "--out", str(signed)) == 0
    assert "container       eaf" in capsys.readouterr().out

    assert run(*args, "verify", str(signed)) == 0
    assert "entries=3" in capsys.readouterr().out
    assert run(*args, "info", str(signed)) == 0
    assert "tree sha256" in capsys.readouterr().out

    dest = tmp_path / "installed"
    assert run(*args, "unpack", str(signed), "--dest", str(dest)) == 0
    assert (dest / "plugin" / "src" / "main.py").read_bytes() == UNSIGNED_SOURCE


def test_pack_turns_a_bare_plugin_into_an_unsigned_bundle(workspace, tmp_path):
    bundle = tmp_path / "demo.eaf"
    assert run(*workspace["args"], "pack", str(workspace["plugin"]), "--out", str(bundle)) == 0
    assert run(*workspace["args"], "verify", str(bundle)) == 2


def test_pack_refuses_to_overwrite(workspace, bundle_folder, tmp_path):
    bundle = tmp_path / "demo.eaf"
    args = workspace["args"]
    assert run(*args, "pack", str(bundle_folder), "--out", str(bundle)) == 0
    assert run(*args, "pack", str(bundle_folder), "--out", str(bundle)) == 1
    assert run(*args, "pack", str(bundle_folder), "--out", str(bundle), "--force") == 0


def test_unpack_refuses_an_entry_that_escapes_the_dest(workspace, tmp_path, capsys):
    evil = tmp_path / "evil.eaf"
    with zipfile.ZipFile(evil, "w") as archive_file:
        archive_file.writestr("../escape.py", b"import os")
    assert run(*workspace["args"], "unpack", str(evil), "--dest", str(tmp_path / "out")) == 1
    assert "unsafe entry name" in capsys.readouterr().err
    assert not (tmp_path / "escape.py").exists()
    assert run(*workspace["args"], "verify", str(evil)) == 1
