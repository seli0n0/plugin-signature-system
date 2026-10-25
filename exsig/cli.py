"""exsig - command line front end. Every operation is local; nothing talks to a network."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import archive, core, format as fmt, keys
from .core import PERMISSIVE, STRICT

DEFAULT_KEYRING = Path(os.environ.get("EXSIG_KEYRING", Path.home() / ".exsig" / "keyring.json"))


def _ring(args) -> keys.Keyring:
    return keys.Keyring.load(Path(args.keyring))


def _fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 1


def cmd_keygen(args) -> int:
    out = Path(args.out)
    pair = keys.generate(args.name)
    password = args.password.encode() if args.password else None
    key_path = out / f"{args.name}.key"
    if key_path.exists() and not args.force:
        return _fail(f"{key_path} exists; pass --force to overwrite")
    keys.save_private(pair, key_path, args.name, password)
    enc = "passphrase-encrypted" if password else "PLAINTEXT - keep this file offline"
    print(f"keyid      {pair.keyid}")
    print(f"fingerprint {keys.fingerprint(pair.public_raw)}")
    print(f"private    {key_path}  ({enc})")
    print(f"public     {key_path.with_suffix('.pub.json')}")
    print("share the .pub.json however you like (channel, repo, USB) - no server needed")
    return 0


def cmd_cert_issue(args) -> int:
    root = keys.load_private(Path(args.root), args.password.encode() if args.password else None)
    pub = json.loads(Path(args.subject_pub).read_text("utf-8"))
    cert, _ = keys.issue_cert(root, pub["pubkey"], pub.get("name", args.subject_pub),
                              args.plugin_id, years=args.years)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cert, indent=2, sort_keys=True) + "\n", "utf-8")
    print(f"certificate for {cert['subject_keyid']} covering {cert['plugin_ids']}")
    print(f"issued by {root.keyid} -> {out}")
    return 0


def cmd_sign(args) -> int:
    src = Path(args.plugin)
    pair = keys.load_private(Path(args.key), args.password.encode() if args.password else None)
    cert = None
    if args.cert:
        cert = json.loads(Path(args.cert).read_text("utf-8"))
        subject = cert.get("subject_keyid")
        if subject != pair.keyid:
            return _fail(f"certificate is for key {subject}, but --key is {pair.keyid}")
    bundle = archive.is_archive(src.read_bytes())
    suffix = ".signed.eaf" if bundle else ".signed.plugin"
    out = src if args.in_place else src.with_name(f"{src.stem}{suffix}")
    if args.out:
        out = Path(args.out)
    if out == src and not args.in_place:
        return _fail("refusing to overwrite the input; pass --in-place explicitly")
    info = core.sign_file(src, pair, out, args.plugin_id, args.version, args.author, cert)
    for key, value in info.items():
        print(f"{key:<16}{value}")
    return 0


def cmd_verify(args) -> int:
    payload = Path(args.plugin).read_bytes()
    result = core.verify_bytes(
        payload, _ring(args), policy=args.policy, expect_id=args.expect_id,
        expect_version=args.expect_version, expect_keyid=args.expect_keyid)
    if args.json:
        print(json.dumps(result.as_dict(), ensure_ascii=False, indent=2))
    else:
        mark = {"valid": "OK", "invalid": "REJECT", "unsigned": "UNSIGNED", "untrusted": "UNKNOWN"}
        print(f"[{mark[result.status]}] {args.plugin} -> {result.summary}")
        m = result.manifest or {}
        if m:
            entries = f" entries={len(m['files'])}" if m.get("container") == archive.CONTAINER else ""
            print(f"       id={m.get('plugin_id', '')} version={m.get('plugin_version', '')} "
                  f"author={m.get('plugin_author', '')}{entries} content={result.payload_sha256[:16]}...")
        for problem in result.problems:
            print(f"       ! {problem}")
        for note in result.notes:
            print(f"       note: {note}")
    return result.exit_code


def cmd_info(args) -> int:
    raw = Path(args.plugin).read_bytes()
    print(f"file          {args.plugin}")
    print(f"bytes         {len(raw)}")
    if archive.is_archive(raw):
        entries = archive.entry_digests(raw)
        print(f"container     {archive.CONTAINER}")
        print(f"entries       {len(entries)} ({sum(entry['size'] for entry in entries)} bytes of content)")
        print(f"tree sha256   {core.bundle_tree_sha256(entries)}")
        print("identity      " + json.dumps(archive.bundle_identity(entries, raw), ensure_ascii=False))
        for entry in entries:
            print(f"  {entry['sha256'][:16]}... {entry['size']:>9}  {entry['path']}")
        block = fmt.split_block(archive.read_comment(raw))[1]
    else:
        body, block = fmt.split_block(raw)
        print("container     plugin")
        print(f"payload sha256{core.sha256_hex(body)}")
        print(f"python sha256 {core.sha256_hex(raw)}")
        print("metadata      " + json.dumps(fmt.read_metadata(body), ensure_ascii=False))
    if block is None:
        print("signature     none")
        return 0
    print(f"keyid         {block['keyid']}")
    print(f"algo          {block['algo']}")
    manifest, _, cert, _ = core.parse_block(block)
    print("manifest      " + json.dumps(manifest, ensure_ascii=False, sort_keys=True))
    if cert:
        print("certificate   " + json.dumps(cert, ensure_ascii=False, sort_keys=True))
    return 0


def cmd_strip(args) -> int:
    raw = Path(args.plugin).read_bytes()
    body = core.strip_signature(raw)
    suffix = ".unsigned.eaf" if archive.is_archive(raw) else ".unsigned.plugin"
    out = Path(args.out) if args.out else Path(args.plugin).with_name(f"{Path(args.plugin).stem}{suffix}")
    out.write_bytes(body)
    digest = core.sha256_hex(body)
    print(f"{len(body)} bytes -> {out} (sha256 {digest[:16]}...)")
    return 0


def cmd_pack(args) -> int:
    source = Path(args.source)
    out = Path(args.out) if args.out else source.with_suffix(".eaf")
    if out.exists() and not args.force:
        return _fail(f"{out} exists; pass --force to overwrite")
    info = archive.pack(source, out, args.root)
    print(f"output        {info['output']}")
    print(f"root          {info['root']}")
    print(f"entries       {info['entries']} ({info['bytes']} bytes)")
    for name in info["files"]:
        print(f"  {name}")
    print("now sign it:  exsig sign " + str(out) + " --key <build.key> --cert <cert.json>")
    return 0


def cmd_unpack(args) -> int:
    raw = Path(args.bundle).read_bytes()
    if not archive.is_archive(raw):
        return _fail(f"{args.bundle} is not a .eaf archive")
    written = archive.unpack(raw, Path(args.dest), args.max_entries, args.max_bytes)
    dest = Path(args.dest)
    print(f"{len(written)} files -> {dest}")
    for path in written:
        print(f"  {path.relative_to(dest).as_posix()}")
    return 0


def cmd_keyring(args) -> int:
    ring = _ring(args)
    action = args.action
    if action == "list":
        if not ring.entries:
            print(f"{args.keyring} is empty")
        for keyid, entry in sorted(ring.entries.items()):
            print(f"{keyid}  {entry['state']:<8} {entry['name']}")
        return 0
    if action == "add":
        if args.pub:
            data = json.loads(Path(args.pub).read_text("utf-8"))
            keyid, name, pubkey = data["keyid"], args.name or data["name"], data["pubkey"]
        else:
            if not (args.keyid and args.pubkey):
                return _fail("give --pub FILE or both --keyid and --pubkey")
            keyid, name, pubkey = args.keyid, args.name or keyid, args.pubkey
        if keyid != keys.keyid_of(fmt.b64decode(pubkey, "pubkey")):
            return _fail("the public key does not hash to the given keyid")
        try:
            ring.add(keyid, name, pubkey, keys.TRUSTED, args.note)
        except ValueError as exc:
            return _fail(str(exc))
        ring.save()
        print(f"trusted {keyid} as {name} in {args.keyring}")
        if args.show_fingerprint:
            print("fingerprint " + keys.fingerprint(fmt.b64decode(pubkey, "pubkey")))
        return 0
    if action in ("trust", "revoke"):
        if action == "revoke":
            created = ring.revoke_keyid(args.keyid, args.note or "revoked")
            ring.save()
            print(f"{args.keyid} -> revoked"
                  + (" (tombstone: the public key was never on record)" if created else ""))
            return 0
        try:
            ring.set_state(args.keyid, keys.TRUSTED, args.note or "")
        except KeyError:
            return _fail(f"{args.keyid} is not in the keyring; add it with `keyring add` first")
        ring.save()
        print(f"{args.keyid} -> trusted")
        return 0
    if action == "export":
        out = Path(args.out) if args.out else Path(str(args.keyring) + ".pub-only.json")
        public = {k: {kk: v[kk] for kk in ("name", "pubkey", "state")} for k, v in sorted(ring.entries.items())}
        out.write_text(json.dumps({"format": "EXTERA-KEYRING-V1", "keys": public}, indent=2, sort_keys=True) + "\n", "utf-8")
        print(f"{len(public)} keys -> {out}")
        return 0
    return _fail(f"unknown keyring action {action}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="exsig", description=__doc__)
    p.add_argument("--keyring", default=str(DEFAULT_KEYRING),
                   help=f"public key ring file (default {DEFAULT_KEYRING})")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("keygen", help="create an author or plugin key pair")
    s.add_argument("--name", required=True)
    s.add_argument("--out", default="keys")
    s.add_argument("--password")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("cert-issue", help="delegate a plugin key with the root key")
    s.add_argument("--root", required=True, help="root .key file")
    s.add_argument("--subject-pub", required=True, help="the plugin key's .pub.json")
    s.add_argument("--plugin-id", action="append", required=True)
    s.add_argument("--years", type=float, default=5.0)
    s.add_argument("--password")
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_cert_issue)

    s = sub.add_parser("pack", help="build a .eaf bundle from a plugin folder or a bare .plugin")
    s.add_argument("source")
    s.add_argument("--out")
    s.add_argument("--root", default=archive.ROOT_DEFAULT, help="top folder inside the archive")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_pack)

    s = sub.add_parser("unpack", help="extract a .eaf bundle, refusing unsafe entry names")
    s.add_argument("bundle")
    s.add_argument("--dest", required=True)
    s.add_argument("--max-entries", type=int, default=archive.DEFAULT_MAX_ENTRIES)
    s.add_argument("--max-bytes", type=int, default=archive.DEFAULT_MAX_BYTES)
    s.set_defaults(func=cmd_unpack)

    s = sub.add_parser("sign", help="sign a .plugin file or a .eaf bundle")
    s.add_argument("plugin")
    s.add_argument("--key", required=True)
    s.add_argument("--password")
    s.add_argument("--cert", help="certificate.json from cert-issue")
    s.add_argument("--out")
    s.add_argument("--in-place", action="store_true")
    s.add_argument("--plugin-id")
    s.add_argument("--version")
    s.add_argument("--author")
    s.set_defaults(func=cmd_sign)

    s = sub.add_parser("verify", help="check a signed .plugin or .eaf")
    s.add_argument("plugin")
    s.add_argument("--policy", choices=(STRICT, PERMISSIVE), default=STRICT,
                   help="strict rejects anything not signed by a pinned key; permissive lets the host decide")
    s.add_argument("--expect-id")
    s.add_argument("--expect-version")
    s.add_argument("--expect-keyid")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("info", help="decode the signature block without verifying")
    s.add_argument("plugin")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("strip", help="remove a signature block (payload only)")
    s.add_argument("plugin")
    s.add_argument("--out")
    s.set_defaults(func=cmd_strip)

    s = sub.add_parser("keyring", help="manage pinned public keys")
    s.add_argument("action", choices=("list", "add", "trust", "revoke", "export"))
    s.add_argument("--keyid")
    s.add_argument("--pub", help="author-supplied .pub.json")
    s.add_argument("--pubkey", help="raw base64 public key")
    s.add_argument("--name")
    s.add_argument("--note")
    s.add_argument("--out")
    s.add_argument("--show-fingerprint", action="store_true")
    s.set_defaults(func=cmd_keyring)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        # Plugin names carry Cyrillic and emoji; a cp866 console must not abort a verify run.
        if stream.encoding and stream.encoding.lower() not in ("utf-8", "utf8"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        return _fail(str(exc.filename or exc))
    except json.JSONDecodeError as exc:
        return _fail(f"bad JSON: {exc}")
    except (fmt.FormatError, archive.ArchiveError, ValueError, KeyError) as exc:
        return _fail(str(exc) or exc.__class__.__name__)


if __name__ == "__main__":
    raise SystemExit(main())
