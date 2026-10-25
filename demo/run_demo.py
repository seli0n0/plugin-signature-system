"""Run the whole no-server signing story end to end and print the transcript.

    python demo/run_demo.py            # uses the first real .plugin it can find
    python demo/run_demo.py my.plugin

Covers both containers: the single-file `.plugin` and the folder packed into a
signed `.eaf` bundle. Writes demo/transcript.txt. Nothing touches the network, no
source plugin is overwritten, and every key stays under demo/.work - the real
~/.exsig is never used.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from exsig import cli  # noqa: E402

WORK = ROOT / "demo" / ".work"
RING = ["--keyring", str(WORK / "keyring.json")]
REAL_DIR = Path(os.environ.get(
    "EXTERAGRAM_PLUGIN_DIR", str(Path.home() / "Desktop" / "раб стол" / "plugin")))

SAMPLE = '''__id__ = "extera_demo"
__name__ = "Demo Plugin"
__author__ = "@extera"
__version__ = "1.0.0"


class DemoPlugin:
    def on_send_message_hook(self, text):
        return text
'''


def step(label: str, *argv: str) -> str:
    out = io.StringIO()
    with redirect_stdout(out), redirect_stderr(out):
        code = cli.main(RING + list(argv))
    return f"$ {label}\n{out.getvalue().rstrip()}\n[exit {code}]\n"


def _shorten(text: str) -> str:
    """Keep the transcript free of the machine it was produced on."""
    return (text.replace(str(WORK), "demo/.work")
                .replace(str(ROOT), ".")
                .replace(str(Path.home()), "~")
                .replace("demo/.work\\", "demo/.work/"))


def pick_plugin() -> tuple[Path, bool]:
    if len(sys.argv) > 1:
        return Path(sys.argv[1]), False
    if REAL_DIR.is_dir():
        for candidate in sorted(REAL_DIR.glob("*.plugin")):
            head = candidate.read_bytes()[:2000]
            if b"__id__" in head and b"__version__" in head and candidate.stat().st_size < 100_000:
                return candidate, True
    WORK.mkdir(parents=True, exist_ok=True)
    fallback = WORK / "sample.plugin"
    fallback.write_text(SAMPLE, "utf-8")
    return fallback, False


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    for stale in sorted(WORK.rglob("*"), reverse=True):
        if stale.is_file():
            stale.unlink()
    plugin, genuine = pick_plugin()
    keys_dir = WORK / "keys"
    author_key = keys_dir / "@author.key"
    builder_key = keys_dir / "build-server.key"
    builder_cert = WORK / "cert.json"
    signed = WORK / f"{plugin.stem}.signed.plugin"

    lines = [
        f"plugin under test: {plugin} ({plugin.stat().st_size} bytes)  <- "
        + ("a genuine Exteragram plugin from the author's folder" if genuine else "generated sample"),
        "",
    ]
    lines.append(step("exsig keygen --name @author --out demo/.work/keys          # cold root key",
                      "keygen", "--name", "@author", "--out", str(keys_dir)))
    lines.append(step("exsig keygen --name build-server --out demo/.work/keys     # key that touches code",
                      "keygen", "--name", "build-server", "--out", str(keys_dir)))

    found = re.search(rb'^__id__\s*=\s*["\']([^"\']+)', plugin.read_bytes(), re.M)
    plugin_id = found.group(1).decode() if found else plugin.stem
    lines.append(step(
        f"exsig cert-issue --root @author.key --subject-pub build-server.pub.json --plugin-id {plugin_id}",
        "cert-issue", "--root", str(author_key), "--subject-pub", str(builder_key.with_suffix(".pub.json")),
        "--plugin-id", plugin_id, "--out", str(builder_cert)))
    lines.append(step("exsig keyring add --pub @author.pub.json        # pin only the root's public half",
                      "keyring", "add", "--pub", str(author_key.with_suffix(".pub.json")),
                      "--note", "author root", "--show-fingerprint"))

    lines.append(step(f"exsig sign {plugin.name} --key build-server.key --cert cert.json",
                      "sign", str(plugin), "--key", str(builder_key), "--cert", str(builder_cert),
                      "--out", str(signed)))

    lines.append("--- what the host sees ---")
    lines.append(step(f"exsig verify {signed.name}", "verify", str(signed)))
    lines.append(step(f"exsig verify {plugin.name}                    # the author's own unsigned file",
                      "verify", str(plugin)))

    raw = bytearray(signed.read_bytes())
    cut = raw.find(b"__version__")
    raw[cut + 6 if cut != -1 else len(raw) // 2] ^= 0x20
    tampered = WORK / "tampered.plugin"
    tampered.write_bytes(bytes(raw))
    lines.append(step("exsig verify tampered.plugin             # one byte of the code rewritten",
                      "verify", str(tampered)))
    lines.append(step("exsig verify ...signed.plugin --expect-version 9.9.9   # old build sold as new",
                      "verify", str(signed), "--expect-version", "9.9.9"))

    lines.append("--- the same author ships a .eaf bundle ---")
    src_folder = WORK / "bundle_src"
    (src_folder / "src").mkdir(parents=True, exist_ok=True)
    (src_folder / "src" / "main.py").write_bytes(plugin.read_bytes())
    bundle = WORK / f"{plugin.stem}.eaf"
    lines.append(step(f"exsig pack {src_folder.name} --out {bundle.name}",
                      "pack", str(src_folder), "--out", str(bundle)))
    signed_bundle = WORK / f"{plugin.stem}.signed.eaf"
    lines.append(step(f"exsig sign {bundle.name} --key build-server.key --cert cert.json",
                      "sign", str(bundle), "--key", str(builder_key), "--cert", str(builder_cert),
                      "--out", str(signed_bundle)))
    lines.append(step(f"exsig verify {signed_bundle.name}          # every entry hash is checked",
                      "verify", str(signed_bundle)))
    lines.append(step(f"exsig unpack {signed_bundle.name} --dest demo/.work/installed",
                      "unpack", str(signed_bundle), "--dest", str(WORK / "installed")))

    injected = WORK / "injected.eaf"
    with zipfile.ZipFile(signed_bundle) as source, zipfile.ZipFile(injected, "w", zipfile.ZIP_DEFLATED) as sink:
        for item in source.infolist():
            sink.writestr(item, source.read(item))
        sink.writestr("plugin/src/exfil.py", b"import os")
        sink.comment = source.comment
    lines.append(step("exsig verify injected.eaf           # a file added inside a signed bundle",
                      "verify", str(injected)))

    escaping = WORK / "escape.eaf"
    with zipfile.ZipFile(escaping, "w") as sink:
        sink.writestr("../evil.py", b"import os")
    lines.append(step("exsig unpack escape.eaf --dest demo/.work/installed   # path traversal entry",
                      "unpack", str(escaping), "--dest", str(WORK / "installed")))
    assert not (WORK / "evil.py").exists(), "unpack must not write outside the destination"

    keyid = json.loads(builder_key.with_suffix(".pub.json").read_text())["keyid"]
    lines.append(step(f"exsig keyring revoke --keyid {keyid}     # build server compromised, key never pinned",
                      "keyring", "revoke", "--keyid", keyid, "--note", "build server compromised"))
    lines.append(step("exsig verify ...signed.plugin            # after the revocation",
                      "verify", str(signed)))
    lines.append(step("exsig verify ...signed.eaf               # one revocation, both containers dead",
                      "verify", str(signed_bundle)))

    text = _shorten("\n".join(lines))
    (ROOT / "demo" / "transcript.txt").write_text(text, "utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
