"""Wire format: the signature block embedded in a .plugin file.

Every block line is a Python comment, so a signed plugin stays loadable by
Exteragram without touching the plugin loader.
"""

from __future__ import annotations

import ast
import base64
import json
import re

FORMAT = "EXTERA-SIG-V1"
START = f"# ---{FORMAT}---".encode("ascii")
END = f"# ---{FORMAT}-END---".encode("ascii")
B64 = re.compile(r"^[A-Za-z0-9+/=]+$")
DIRECTIVES = ("algo", "keyid", "manifest", "cert", "sig")
META_FIELDS = ("__id__", "__name__", "__version__", "__author__", "__min_version__")


class FormatError(Exception):
    """The bytes are not a well-formed signed artifact."""


def normalize_payload(raw: bytes) -> bytes:
    """Drop trailing newlines only; they carry no meaning in Python source."""
    return raw.rstrip(b"\r\n")


def encode_block(directives: dict[str, str]) -> bytes:
    lines = [START]
    for key in DIRECTIVES:
        if key in directives:
            lines += [f"# {key}: {directives[key]}".encode("ascii")]
    lines.append(END)
    return b"\r\n".join(lines)


def split_block(raw: bytes) -> tuple[bytes, dict[str, str] | None]:
    """Return (payload, directives) — directives is None for an unsigned file.

    The *last* START marker wins, and a START marker still present in the
    payload is rejected outright: that is how a two-block smuggling attack
    (real block first, attacker block last) gets caught.
    """
    idx = raw.rfind(START)
    if idx == -1:
        return normalize_payload(raw), None
    if idx != 0 and raw[idx - 1] not in (0x0A, 0x0D):
        raise FormatError("signature marker is not at the start of a line")

    payload = normalize_payload(raw[:idx])
    if START in payload:
        raise FormatError("nested signature marker in payload")

    end = raw.find(END, idx)
    if end == -1:
        raise FormatError("signature block is not closed")
    if raw[end + len(END):].strip(b"\r\n \t"):
        raise FormatError("trailing bytes after the signature block")

    directives: dict[str, str] = {}
    for line in raw[idx + len(START): end].split(b"\r\n" if b"\r\n" in raw[idx:end] else b"\n"):
        text = line.decode("utf-8", "replace").strip()
        if not text:
            continue
        if not text.startswith("# "):
            raise FormatError(f"unprotected line inside the signature block: {text[:40]!r}")
        body = text[2:]
        if body.endswith("\r"):
            body = body[:-1]
        key, sep, value = body.partition(": ")
        if not sep or key not in DIRECTIVES:
            raise FormatError(f"unknown directive in signature block: {body[:40]!r}")
        if key in directives:
            raise FormatError(f"duplicate directive: {key}")
        directives[key] = value.strip()
    for required in ("algo", "keyid", "manifest", "sig"):
        if required not in directives:
            raise FormatError(f"signature block is missing {required!r}")
    return payload, directives


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(text: str, what: str) -> bytes:
    if not B64.match(text):
        raise FormatError(f"{what} is not valid base64")
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # noqa: BLE001 - surface as a format error
        raise FormatError(f"{what} is not valid base64") from exc


def canonical_json(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode_canonical(value: str, what: str) -> tuple[dict, bytes]:
    """Decode a base64 JSON record and require it to already be canonical.

    A non-canonical encoding means two parsers could disagree about the signed
    content, so it is refused instead of normalised.
    """
    blob = b64decode(value, what)
    try:
        obj = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FormatError(f"{what} is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise FormatError(f"{what} is not a JSON object")
    if canonical_json(obj) != blob:
        raise FormatError(f"{what} is not canonically encoded")
    return obj, blob


def read_metadata(payload: bytes) -> dict[str, str]:
    """Pull __id__/__version__/... out of the plugin source without executing it."""
    found: dict[str, str] = {}
    try:
        tree = ast.parse(payload.decode("utf-8", "replace"))
    except SyntaxError:
        return found
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id in META_FIELDS:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    found[target.id] = node.value.value
    return found
