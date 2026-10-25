"""The .eaf container: a ZIP of a plugin folder, signed through its archive comment.

Real .eaf files (made by `plugin2eaf`) look like this, so we match it:

    plugin/                  directory entry
    plugin/src/              directory entry
    plugin/meta.yml          id / name / author / version / icon / min_version
    plugin/src/main.py       the code
    refmap.yml               logical -> path map, read by the host

A whole archive cannot be hashed like a single .plugin: extraction tools rewrite
bytes, and the host ultimately executes *entry contents*. So the signed manifest
carries one SHA-256 per entry, and the signature itself rides in the ZIP archive
comment - the one place that adds no foreign file to the tree being unpacked.
"""

from __future__ import annotations

import hashlib
import io
import stat
import time
import zipfile
from pathlib import Path, PurePosixPath

CONTAINER = "eaf"
ROOT_DEFAULT = "plugin"
MAX_COMMENT = 0xFFFF  # the ZIP end-of-central-directory field is 16 bits
SUPPORTED_METHODS = (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
REFMAP_VERSION = "exsig/1.0"

DEFAULT_MAX_ENTRIES = 512
DEFAULT_MAX_BYTES = 256 * 1024 * 1024


class ArchiveError(Exception):
    """The archive is malformed, hostile, or beyond a safety limit."""


def is_archive(raw: bytes) -> bool:
    return raw[:4] == b"PK\x03\x04" or raw[:4] == b"PK\x05\x06"


def _open(raw: bytes) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise ArchiveError(f"not a readable zip archive: {exc}") from exc


def read_meta_yml(text: str) -> dict[str, str]:
    """Parse the flat `key: "value"` map of meta.yml without a YAML dependency."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#") or line[:1].isspace():
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        value = value.strip()
        if value[:1] in "\"'" and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1].replace("\\n", "\n").replace('\\"', '"')
        elif value:
            value = value.split(" #")[0].strip()
        out[key.strip()] = value
    return out


def write_meta_yml(meta: dict[str, str]) -> bytes:
    def quote(value: str) -> str:
        return '"' + value.replace('"', '\\"').replace("\n", "\\n") + '"'

    lines = [f'{key}: {quote(value)}' for key, value in meta.items()]
    return ("\n".join(lines) + "\n").encode("utf-8")


def build_refmap(root: str, present: set[str]) -> bytes:
    lines = [f"metainfo: {root}/meta.yml", f"main: {root}/src/main.py"]
    if any(p.startswith(f"{root}/res/") for p in present):
        lines.append(f"assets: {root}/res")
    if any(p.startswith(f"{root}/locales/") for p in present):
        lines.append(f"strings: {root}/locales")
    lines.append(f"plugin2eaf: {REFMAP_VERSION}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def check_entry_name(name: str) -> PurePosixPath:
    """Reject every path that could escape the extraction directory."""
    if not name or name.startswith("/") or "\\" in name:
        raise ArchiveError(f"unsafe entry name: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or path.drive:
        raise ArchiveError(f"unsafe entry name: {name!r}")
    parts = path.parts
    if not parts or ".." in parts or parts[0].startswith("/") or ":" in parts[0]:
        raise ArchiveError(f"unsafe entry name: {name!r}")
    return path


def entry_digests(raw: bytes, max_entries: int = DEFAULT_MAX_ENTRIES,
                  max_bytes: int = DEFAULT_MAX_BYTES) -> list[dict]:
    """Hash every non-directory entry, in archive order, with hostile cases refused."""
    archive = _open(raw)
    infos = archive.infolist()
    if len(infos) > max_entries:
        raise ArchiveError(f"{len(infos)} entries exceeds the limit of {max_entries}")
    seen: set[str] = set()
    total = 0
    out: list[dict] = []
    for info in infos:
        name = check_entry_name(info.filename)
        key = str(name)
        if info.flag_bits & 0x1:
            raise ArchiveError(f"entry {key!r} is encrypted; signing it would be guessing")
        if info.compress_type not in SUPPORTED_METHODS:
            raise ArchiveError(f"entry {key!r} uses unsupported compression {info.compress_type}")
        mode = info.external_attr >> 16
        kind = stat.S_IFMT(mode)
        if kind == stat.S_IFLNK:
            raise ArchiveError(f"entry {key!r} is a symlink; it could point outside the plugin folder")
        if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
            # plugin2eaf stores bare permission bits, so "no type bits" is the normal case.
            raise ArchiveError(f"entry {key!r} is not a regular file")
        if info.is_dir():
            if key in seen:
                raise ArchiveError(f"duplicate entry {key!r}")
            seen.add(key)
            continue
        if key in seen:
            # Two entries with one name: zipfile.read() returns the first, other
            # extractors the last, so the signed bytes need not be the executed ones.
            raise ArchiveError(f"duplicate entry {key!r}")
        seen.add(key)
        with archive.open(info) as handle:  # open by ZipInfo, never by name
            data = handle.read(max_bytes + 1)
        total += len(data)
        if total > max_bytes:
            raise ArchiveError(f"uncompressed size exceeds {max_bytes} bytes")
        out.append({"path": key, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    out.sort(key=lambda item: item["path"])
    return out


def bundle_identity(entries: list[dict], raw: bytes) -> dict[str, str]:
    """Pull id/name/version/author out of the bundle's meta.yml, via refmap.yml."""
    paths = {entry["path"] for entry in entries}
    meta_path = None
    if "refmap.yml" in paths:
        for line in _read(raw, "refmap.yml").decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() == "metainfo":
                meta_path = value.strip()
    if meta_path is None:
        meta_path = next((p for p in sorted(paths) if p == "meta.yml" or p.endswith("/meta.yml")), None)
    if meta_path not in paths:
        return {}
    return read_meta_yml(_read(raw, meta_path).decode("utf-8", "replace"))


def _read(raw: bytes, name: str) -> bytes:
    archive = _open(raw)
    for info in archive.infolist():
        if info.filename == name and not info.is_dir():
            with archive.open(info) as handle:
                return handle.read()
    raise ArchiveError(f"entry {name!r} is missing")


def read_comment(raw: bytes) -> bytes:
    return _open(raw).comment or b""


def write_comment(raw: bytes, comment: bytes) -> bytes:
    """Rewrite the archive with `comment` in its end-of-central-directory record."""
    if len(comment) > MAX_COMMENT:
        raise ArchiveError(f"signature block is {len(comment)} bytes; the ZIP comment holds at most {MAX_COMMENT}")
    source = _open(raw)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            with source.open(info) as handle:
                target.writestr(info, handle.read())
        target.comment = comment
    return out.getvalue()


def pack(source: Path, out: Path, root: str = ROOT_DEFAULT, timestamp: tuple | None = None) -> dict:
    """Build a canonical .eaf from a plugin folder or a bare .plugin file."""
    check_entry_name(root)
    files: dict[str, bytes] = {}
    if source.is_file():
        main = f"{root}/src/main.py"
        files[main] = source.read_bytes()
        files[f"{root}/meta.yml"] = _meta_from_source(source)
    elif source.is_dir():
        for path in sorted(source.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(source).as_posix()
            check_entry_name(relative)
            files[f"{root}/{relative}"] = path.read_bytes()
        if f"{root}/src/main.py" not in files:
            raise ArchiveError(f"{source} has no src/main.py; a bundle needs an entry point")
        if f"{root}/meta.yml" not in files:
            files[f"{root}/meta.yml"] = _meta_from_source(source / "src" / "main.py")
    else:
        raise FileNotFoundError(str(source))

    files["refmap.yml"] = build_refmap(root, set(files))
    stamp = timestamp or _stamp_of(source)
    body = _write_zip(files, root, stamp)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(body)
    return {"output": str(out), "bytes": len(body), "entries": len(files),
            "root": root, "files": sorted(files), "timestamp": stamp}


def _write_zip(files: dict[str, bytes], root: str, stamp: tuple) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        dirs = set()
        for name in sorted(files):
            parent = PurePosixPath(name).parent
            while str(parent) not in ("", "."):
                dirs.add(str(parent))
                parent = parent.parent
        for name in sorted(dirs):
            info = zipfile.ZipInfo(name + "/", date_time=stamp)
            info.external_attr = (0o40755 << 16) | 0x10
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 0
            archive.writestr(info, b"")
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=stamp)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            archive.writestr(info, files[name])
    return out.getvalue()


def _stamp_of(source: Path) -> tuple:
    """Latest input mtime, so the same folder packs to the same bytes."""
    inputs = [source] if source.is_file() else [p for p in source.rglob("*") if p.is_file()]
    moments = [p.stat().st_mtime for p in inputs if p.is_file()]
    if not moments:
        return (1980, 1, 1, 0, 0, 0)
    return time.localtime(int(max(moments)))[:6]


def _meta_from_source(path: Path) -> bytes:
    """Derive a bundle's meta.yml from a bare .plugin's own declarations."""
    from .format import read_metadata

    main = path if path.is_file() else path / "src" / "main.py"
    meta = read_metadata(main.read_bytes()) if main.suffix in (".plugin", ".py") else {}
    fallback = path.name if path.is_dir() else main.stem
    return write_meta_yml({
        "id": meta.get("__id__", fallback),
        "name": meta.get("__name__", fallback),
        "description": meta.get("__description__", ""),
        "author": meta.get("__author__", ""),
        "version": meta.get("__version__", "0.0.0"),
        "min_version": meta.get("__min_version__", ""),
    })


def unpack(raw: bytes, dest: Path, max_entries: int = DEFAULT_MAX_ENTRIES,
           max_bytes: int = DEFAULT_MAX_BYTES) -> list[Path]:
    """Extract an archive, refusing anything that could land outside `dest`."""
    entries = entry_digests(raw, max_entries, max_bytes)
    archive = _open(raw)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    lookup = {entry["path"]: entry["sha256"] for entry in entries}
    for info in archive.infolist():
        name = check_entry_name(info.filename)
        target = dest.joinpath(*name.parts)
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        with archive.open(info) as handle:
            data = handle.read()
        if hashlib.sha256(data).hexdigest() != lookup[str(name)]:
            raise ArchiveError(f"entry {str(name)!r} changed while extracting")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o644)
        written.append(target)
    return written
