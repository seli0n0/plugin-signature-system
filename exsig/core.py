"""Signing and verification of Exteragram plugins: single .plugin files and .eaf bundles."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import archive, format as fmt
from .keys import (
    REVOKED,
    TRUSTED,
    KeyPair,
    Keyring,
    check_cert,
    keyid_of,
    plugin_tbs,
    pub_from_b64,
    verify_sig,
)

ALGO = "ed25519"
CONTAINER = "plugin"
VALID, INVALID, UNSIGNED, UNTRUSTED = "valid", "invalid", "unsigned", "untrusted"
STRICT, PERMISSIVE = "strict", "permissive"
Policies = ("strict", "permissive")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_tree_sha256(entries: list[dict]) -> str:
    """Fingerprint of a bundle's whole content: one hash over the signed entry list."""
    return sha256_hex(fmt.canonical_json(entries))


def build_manifest(payload: bytes, source_name: str, meta: dict[str, str], keyid: str) -> dict:
    """Bind the file digest *and* the advertised identity into what gets signed.

    The digest alone is not enough: a signed old build could otherwise be
    re-published and read by the host as the new version. __id__/__version__
    therefore become part of the signed record.
    """
    return {
        "format": fmt.FORMAT,
        "algo": ALGO,
        "keyid": keyid,
        "container": CONTAINER,
        "sealed_at": int(time.time()),
        "plugin_id": meta.get("__id__", ""),
        "plugin_name": meta.get("__name__", ""),
        "plugin_version": meta.get("__version__", ""),
        "plugin_author": meta.get("__author__", ""),
        "files": [{"path": source_name, "sha256": sha256_hex(payload), "size": len(payload)}],
    }


def build_bundle_manifest(entries: list[dict], meta: dict[str, str], keyid: str) -> dict:
    """A bundle is signed entry by entry: the host executes files, not the archive."""
    return {
        "format": fmt.FORMAT,
        "algo": ALGO,
        "keyid": keyid,
        "container": archive.CONTAINER,
        "sealed_at": int(time.time()),
        "plugin_id": meta.get("id", ""),
        "plugin_name": meta.get("name", ""),
        "plugin_version": meta.get("version", ""),
        "plugin_author": meta.get("author", ""),
        "files": entries,
    }


def parse_block(block: dict[str, str]) -> tuple[dict, bytes, dict | None, bytes | None]:
    manifest, manifest_bytes = fmt.decode_canonical(block["manifest"], "manifest")
    for required in ("format", "algo", "keyid", "sealed_at", "files"):
        if required not in manifest:
            raise fmt.FormatError(f"manifest is missing {required!r}")
    if "cert" not in block:
        return manifest, manifest_bytes, None, None
    cert, cert_bytes = fmt.decode_canonical(block["cert"], "certificate")
    return manifest, manifest_bytes, cert, cert_bytes


def sign_bytes(payload: bytes, key: KeyPair, meta: dict[str, str], source_name: str,
               cert: dict | None = None) -> bytes:
    if archive.is_archive(payload):
        raise ValueError("this is a .eaf bundle; sign it with sign_bundle")
    body, existing = fmt.split_block(payload)
    if existing is not None:
        raise ValueError("file already carries a signature block; verify it or strip it first")
    if not meta.get("__id__"):
        raise ValueError("plugin declares no __id__; pass --plugin-id")

    directives = _directives(build_manifest(body, source_name, meta, key.keyid), key, cert)
    return body + b"\r\n" + fmt.encode_block(directives) + b"\r\n"


def sign_bundle(raw: bytes, key: KeyPair, meta: dict[str, str], cert: dict | None = None) -> bytes:
    """Write the signature block into the archive comment, covering every entry."""
    if fmt.split_block(archive.read_comment(raw))[1] is not None:
        raise ValueError("archive already carries a signature block; verify it or strip it first")
    if not meta.get("id"):
        raise ValueError("bundle declares no id in meta.yml; pass --plugin-id")
    entries = archive.entry_digests(raw)
    if not entries:
        raise ValueError("archive holds no files to sign")

    directives = _directives(build_bundle_manifest(entries, meta, key.keyid), key, cert)
    return archive.write_comment(raw, fmt.encode_block(directives))


def _directives(manifest: dict, key: KeyPair, cert: dict | None) -> dict[str, str]:
    manifest_bytes = fmt.canonical_json(manifest)
    directives = {
        "algo": ALGO,
        "keyid": key.keyid,
        "manifest": fmt.b64encode(manifest_bytes),
        "sig": fmt.b64encode(key.sign(plugin_tbs(manifest_bytes))),
    }
    if cert is not None:
        directives["cert"] = fmt.b64encode(fmt.canonical_json(cert))
    return directives


def strip_signature(payload: bytes) -> bytes:
    if archive.is_archive(payload):
        return archive.write_comment(payload, b"")
    body, _ = fmt.split_block(payload)
    return body


def sign_file(src: Path, key: KeyPair, out: Path, plugin_id: str | None = None,
              version: str | None = None, author: str | None = None,
              cert: dict | None = None) -> dict:
    payload = src.read_bytes()
    if archive.is_archive(payload):
        return sign_bundle_file(src, key, out, plugin_id, version, author, cert)

    meta = dict(fmt.read_metadata(payload))
    for field_name, value in (("__id__", plugin_id), ("__version__", version), ("__author__", author)):
        if value:
            meta[field_name] = value
    signed = sign_bytes(payload, key, meta, src.name, cert)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(signed)
    body, _ = fmt.split_block(signed)
    return {
        "source": str(src),
        "output": str(out),
        "container": CONTAINER,
        "payload_sha256": sha256_hex(body),
        "file_sha256": sha256_hex(signed),
        "plugin_id": meta.get("__id__", ""),
        "plugin_version": meta.get("__version__", ""),
        "keyid": key.keyid,
        "bytes": len(signed),
        "delegated": cert is not None,
    }


def sign_bundle_file(src: Path, key: KeyPair, out: Path, plugin_id: str | None = None,
                     version: str | None = None, author: str | None = None,
                     cert: dict | None = None) -> dict:
    raw = src.read_bytes()
    meta = dict(archive.bundle_identity(archive.entry_digests(raw), raw))
    for name, value in (("id", plugin_id), ("version", version), ("author", author)):
        if value:
            meta[name] = value
    signed = sign_bundle(raw, key, meta, cert)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(signed)
    entries = archive.entry_digests(signed)
    return {
        "source": str(src),
        "output": str(out),
        "container": archive.CONTAINER,
        "entries": len(entries),
        "tree_sha256": bundle_tree_sha256(entries),
        "file_sha256": sha256_hex(signed),
        "plugin_id": meta.get("id", ""),
        "plugin_version": meta.get("version", ""),
        "keyid": key.keyid,
        "bytes": len(signed),
        "delegated": cert is not None,
    }


@dataclass
class Result:
    status: str
    summary: str
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    manifest: dict | None = None
    signer: dict | None = None
    payload_sha256: str = ""

    @property
    def exit_code(self) -> int:
        return {VALID: 0, INVALID: 1, UNSIGNED: 2, UNTRUSTED: 3}[self.status]

    def as_dict(self) -> dict:
        manifest = self.manifest or {}
        return {
            "status": self.status,
            "summary": self.summary,
            "problems": self.problems,
            "notes": self.notes,
            "signer": self.signer,
            "container": manifest.get("container", CONTAINER),
            "payload_sha256": self.payload_sha256,
            "entries": len(manifest["files"]) if manifest.get("files") else None,
            "plugin_id": manifest.get("plugin_id", ""),
            "plugin_version": manifest.get("plugin_version", ""),
            "sealed_at": manifest.get("sealed_at"),
        }


def verify_bytes(payload: bytes, ring: Keyring, policy: str = STRICT, expect_id: str | None = None,
                 expect_version: str | None = None, expect_keyid: str | None = None,
                 at: int | None = None) -> Result:
    """Verify any signed artifact; the bytes say whether this is a bundle or a plugin."""
    if archive.is_archive(payload):
        return verify_bundle(payload, ring, policy, expect_id, expect_version, expect_keyid, at)

    body, block = fmt.split_block(payload)
    sha = sha256_hex(body)
    if block is None:
        if policy == PERMISSIVE:
            return Result(VALID, "unsigned, allowed by policy", payload_sha256=sha)
        return Result(UNSIGNED, "no signature block",
                      ["apply the host's unsigned-plugin policy (reject by default)"],
                      payload_sha256=sha)

    final, parsed = _decode_block(block, sha)
    if final is not None:
        return final
    res, manifest, signed_manifest, cert, cert_bytes = parsed
    if _check_envelope(manifest, block, res):
        return res
    if manifest.get("container") == archive.CONTAINER:
        res.problems.append("manifest declares a .eaf bundle, but the file is a single plugin")
        return res

    files = manifest["files"]
    if not isinstance(files, list) or len(files) != 1:
        res.problems.append("a plugin manifest must describe exactly one file")
        return res
    entry = files[0]
    digest = entry.get("sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        res.problems.append("manifest carries a malformed file digest")
        return res
    if digest != sha:
        res.summary = "content does not match the signed digest"
        res.problems.append(f"payload hashes to {sha}, the signature covers {digest}")
        return res
    if entry.get("size") != len(body):
        res.problems.append(f"payload is {len(body)} bytes, the signature covers {entry.get('size')}")
        return res
    path = str(entry.get("path", ""))
    if path != Path(path).name:
        res.problems.append("manifest path is not a bare file name")
        return res

    return _check_signer(res, manifest, signed_manifest, block, cert, cert_bytes, ring, policy, at,
                         {"id": expect_id, "version": expect_version, "keyid": expect_keyid})


def verify_bundle(raw: bytes, ring: Keyring, policy: str = STRICT, expect_id: str | None = None,
                  expect_version: str | None = None, expect_keyid: str | None = None,
                  at: int | None = None) -> Result:
    """A bundle is checked entry by entry: extraction rewrites bytes, executed files do not lie."""
    try:
        entries = archive.entry_digests(raw)
        comment = archive.read_comment(raw)
    except archive.ArchiveError as exc:
        return Result(INVALID, "archive is not safely readable", [str(exc)])

    tree = bundle_tree_sha256(entries)
    _, block = fmt.split_block(comment)
    if block is None:
        if policy == PERMISSIVE:
            return Result(VALID, "unsigned, allowed by policy", payload_sha256=tree)
        return Result(UNSIGNED, "no signature block in the archive comment",
                      ["apply the host's unsigned-plugin policy (reject by default)"],
                      payload_sha256=tree)

    final, parsed = _decode_block(block, tree)
    if final is not None:
        return final
    res, manifest, signed_manifest, cert, cert_bytes = parsed
    if _check_envelope(manifest, block, res):
        return res
    if manifest.get("container") != archive.CONTAINER:
        res.problems.append(
            f"manifest declares container {manifest.get('container')!r}, but the file is a .eaf bundle")
        return res
    if not entries:
        res.problems.append("the archive holds no files, so there is nothing the signature could cover")
        return res

    _compare_entries(manifest["files"], entries, res)
    if res.problems:
        res.summary = "archive content does not match the signed entry list"
        return res

    return _check_signer(res, manifest, signed_manifest, block, cert, cert_bytes, ring, policy, at,
                         {"id": expect_id, "version": expect_version, "keyid": expect_keyid})


def _compare_entries(signed_files: list, entries: list[dict], res: Result) -> None:
    """Exact set equality between the signed entry list and the archive on disk."""
    if not isinstance(signed_files, list):
        res.problems.append("manifest files is not a list")
        return
    signed: dict[str, dict] = {}
    for item in signed_files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            res.problems.append(f"malformed entry record: {str(item)[:60]}")
            return
        if item["path"] in signed:
            res.problems.append(f"manifest lists {item['path']!r} twice")
            return
        signed[item["path"]] = item
    actual = {entry["path"]: entry for entry in entries}

    for path in sorted(set(actual) - set(signed)):
        res.problems.append(f"entry {path!r} is not covered by the signature")
    for path in sorted(set(signed) - set(actual)):
        res.problems.append(f"signed entry {path!r} is missing from the archive")
    for path in sorted(set(signed) & set(actual)):
        want, got = signed[path], actual[path]
        if want.get("sha256") != got["sha256"]:
            res.problems.append(
                f"entry {path!r} hashes to {got['sha256'][:16]}..., the signature covers {str(want.get('sha256'))[:16]}...")
        elif want.get("size") != got["size"]:
            res.problems.append(
                f"entry {path!r} is {got['size']} bytes, the signature covers {want.get('size')}")


def _decode_block(block: dict[str, str], sha: str):
    """Return (final_result, parsed_tuple); exactly one of them is not None."""
    try:
        parsed = parse_block(block)
    except fmt.FormatError as exc:
        return Result(INVALID, "malformed signature block", [str(exc)], payload_sha256=sha), None
    stub = Result(INVALID, "", payload_sha256=sha, manifest=parsed[0])
    return None, (stub,) + parsed


def _check_envelope(manifest: dict, block: dict[str, str], res: Result) -> bool:
    """Cheap structural checks that run before any hashing of keys or certificates."""
    if manifest["format"] != fmt.FORMAT:
        res.problems.append(f"unsupported manifest format {manifest['format']!r}")
        return True
    if manifest["algo"] != ALGO:
        res.problems.append(f"unsupported algorithm {manifest['algo']!r}")
        return True
    if manifest["keyid"] != block["keyid"]:
        res.problems.append(
            f"block declares keyid {block['keyid']}, the signed manifest says {manifest['keyid']}")
        return True
    if manifest.get("container", CONTAINER) not in (CONTAINER, archive.CONTAINER):
        res.problems.append(f"unsupported container {manifest['container']!r}")
        return True
    return False


def _check_signer(res: Result, manifest: dict, manifest_bytes: bytes, block: dict[str, str],
                  cert: dict | None, cert_bytes: bytes | None, ring: Keyring, policy: str,
                  at: int | None, expect: dict[str, str | None]) -> Result:
    key, via, why = _resolve_key(manifest, block, cert, cert_bytes, ring, at)
    if why == "invalid":
        res.problems.extend(via)
        res.summary = "key or certificate is not usable"
        return res
    if why == "unknown":
        res.status = UNTRUSTED if policy != PERMISSIVE else VALID
        res.signer = {"keyid": manifest["keyid"], "name": "(unknown)", "via": "unknown"}
        res.summary = "cryptographically sound, but no pinned key establishes who this is"
        res.notes.extend(via)
        res.notes.append(
            "confirm the author's fingerprint out of band, then `exsig keyring add --pub <their .pub.json>` "
            "and verify again"
        )
        return res

    if not verify_sig(pub_from_b64(key["pubkey"]), fmt.b64decode(block["sig"], "signature"),
                      plugin_tbs(manifest_bytes)):
        res.summary = "signature does not verify against the key it claims"
        res.problems.append("Ed25519 verification failed")
        return res

    res.signer = {"keyid": manifest["keyid"], "name": key["name"], "via": why}
    if why == "certificate":
        res.signer["delegated_by"] = cert["issued_by"]

    if expect["keyid"] and manifest["keyid"] != expect["keyid"]:
        res.summary = f"signed by key {manifest['keyid']}, expected {expect['keyid']}"
        return res
    if expect["id"] and manifest["plugin_id"] != expect["id"]:
        res.summary = f"signed plugin id is {manifest['plugin_id']!r}, expected {expect['id']!r}"
        return res
    if expect["version"] and manifest["plugin_version"] != expect["version"]:
        res.summary = f"signed version is {manifest['plugin_version']!r}, expected {expect['version']!r}"
        res.notes.append("this is how a signed older build replayed as a newer one gets caught")
        return res

    now = int(time.time()) if at is None else at
    if manifest["sealed_at"] > now + 3600:
        res.notes.append(f"sealed_at {manifest['sealed_at']} is in the future")

    res.status = VALID
    res.summary = f"signed by {key['name']} (keyid {manifest['keyid']})"
    if why == "certificate":
        res.summary += f" via certificate delegated by {cert['issued_by']}"
    return res


def _resolve_key(manifest, block, cert, cert_bytes, ring: Keyring, at):
    """Locate the verifying key: (entry, reasons, via).

    via is 'keyring' | 'certificate' | 'unknown' | 'invalid'.
    """
    keyid = manifest["keyid"]
    if cert:
        ok, reason, kind = check_cert(cert, cert_bytes, ring, at)
        if not ok:
            if kind == "unknown":
                return None, [f"certificate chain reaches an unpinned root: {reason}"], "unknown"
            return None, [f"certificate rejected: {reason}"], "invalid"
        subject = cert["subject_keyid"]
        if subject != keyid:
            return None, ["certificate subject does not match the signing keyid"], "invalid"
        if manifest["plugin_id"] not in cert["plugin_ids"]:
            return None, [
                f"certificate covers {cert['plugin_ids']}, not plugin id {manifest['plugin_id']!r}"
            ], "invalid"
        entry = ring.get(subject)
        if entry and entry["pubkey"] != cert["subject_pubkey"]:
            return None, [f"keyring holds a different public key for {subject}"], "invalid"
        if entry:
            if entry["state"] == REVOKED:
                return None, [f"subject key {subject} is revoked: {entry.get('note', '')}".strip()], "invalid"
            return entry, [], "certificate"
        issuer = ring.get(cert["issued_by"])
        name = f"{issuer['name']} -> {cert['subject_name']}" if issuer else cert["subject_name"]
        return {"pubkey": cert["subject_pubkey"], "name": name, "state": TRUSTED}, [], "certificate"

    entry = ring.get(keyid)
    if entry is None:
        return None, [], "unknown"
    if entry["state"] == REVOKED:
        return None, [f"key {keyid} is revoked: {entry.get('note', '')}".strip()], "invalid"
    if keyid_of(fmt.b64decode(entry["pubkey"], "pubkey")) != keyid:
        return None, [f"keyring entry for {keyid} does not hash to that keyid"], "invalid"
    return entry, [], "keyring"
