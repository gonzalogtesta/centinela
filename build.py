#!/usr/bin/env python3
"""Build dist/centinela (single-file zipapp), a .deb of it, and SHA256SUMS.

Standard library only: the .deb is assembled directly (ar + tar.gz), so no dpkg
or Debian machine is needed to build it. Output is reproducible for the same
sources and toolchain: fixed timestamps, sorted entries, root ownership
(set SOURCE_DATE_EPOCH to change the stamp).

Usage: python3 build.py [--out dist]
"""
import argparse
import gzip
import hashlib
import io
import os
import sys
import tarfile
import time
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEBIAN = ROOT / "packaging" / "debian"
STAMP = int(os.environ.get("SOURCE_DATE_EPOCH", 315532800))  # 1980-01-01
SHEBANG = b"#!/usr/bin/env python3\n"
MAIN = '''import sys

if sys.version_info < (3, 11):
    sys.exit("centinela needs Python 3.11+ (found %d.%d)" % sys.version_info[:2])
from centinela.cli import main

sys.exit(main())
'''
STANDALONE_BIN = "/usr/local/bin/centinela"  # path written in the bundled unit file
DEB_BIN = "/usr/bin/centinela"
DESCRIPTION = """read-only server health digest sent to Telegram
 Runs a set of check modules (apt updates, needrestart, nginx advisories,
 docker, certbot expiry, disk, failed units, fail2ban, ufw, debsecan) and
 sends one Telegram message only when something needs action, one line per
 finding with the command to run. Never changes the system."""


def project():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    if '__version__ = "%s"' % meta["version"] not in (ROOT / "centinela" / "__init__.py").read_text():
        sys.exit("version in pyproject.toml and centinela/__init__.py differ")
    author = meta["authors"][0]
    return meta["version"], "%s <%s>" % (author["name"], author["email"])


def build_zipapp(target):
    stamp = time.gmtime(STAMP)[:6]
    entries = [("__main__.py", MAIN.encode())]
    for path in sorted((ROOT / "centinela").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            entries.append((path.relative_to(ROOT).as_posix(), path.read_bytes()))
    with open(target, "wb") as fh:
        fh.write(SHEBANG)
        with zipfile.ZipFile(fh, "w") as zf:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=stamp)
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o644 << 16
                zf.writestr(info, data)
    target.chmod(0o755)


def tar_gz(entries):
    """entries: (name, mode, data); data None = directory. Owned by root:root."""
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="", compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tf:
            for name, mode, data in entries:
                info = tarfile.TarInfo(name)
                info.mtime, info.mode = STAMP, mode
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                if data is None:
                    info.type = tarfile.DIRTYPE
                    tf.addfile(info)
                else:
                    info.size = len(data)
                    tf.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def ar(members):
    out = b"!<arch>\n"
    for name, data in members:
        out += b"%-16s%-12d%-6d%-6d%-8s%-10d`\n" % (name.encode(), STAMP, 0, 0, b"100644", len(data))
        out += data + (b"\n" if len(data) % 2 else b"")
    return out


def build_deb(target, version, maintainer, exe):
    data_dir = ROOT / "centinela" / "data"
    unit = (data_dir / "centinela@.service").read_text()
    if STANDALONE_BIN not in unit:
        sys.exit("unit file no longer references %s" % STANDALONE_BIN)
    files = [
        ("usr/bin/centinela", 0o755, exe),
        ("lib/systemd/system/centinela@.service", 0o644, unit.replace(STANDALONE_BIN, DEB_BIN).encode()),
        ("lib/systemd/system/centinela-daily.timer", 0o644, (data_dir / "centinela-daily.timer").read_bytes()),
        ("lib/systemd/system/centinela-weekly.timer", 0o644, (data_dir / "centinela-weekly.timer").read_bytes()),
        ("etc/centinela/centinela.toml", 0o644, (data_dir / "centinela.toml.example").read_bytes()),
        ("usr/share/doc/centinela/README.md", 0o644, (ROOT / "README.md").read_bytes()),
        ("usr/share/doc/centinela/copyright", 0o644, (DEBIAN / "copyright").read_bytes()),
    ]
    dirs = {"."}
    for name, _, _ in files:
        parts = name.split("/")[:-1]
        dirs.update("/".join(parts[: i + 1]) for i in range(len(parts)))
    dirs.add("etc/centinela/checks.d")  # for your own check modules
    dirs.add("etc/centinela/centinela.d")  # drop-in config; `centinela setup` writes 10-wizard.toml here

    data = tar_gz(
        [("./" if d == "." else "./%s/" % d, 0o755, None) for d in sorted(dirs)]
        + [("./" + n, m, d) for n, m, d in files]
    )
    conffiles = {"etc/centinela/centinela.toml"}  # dpkg keeps your edits on upgrade
    md5sums = "".join("%s  %s\n" % (hashlib.md5(d).hexdigest(), n) for n, _, d in files if n not in conffiles)
    size_kib = -(-sum(len(d) for _, _, d in files) // 1024)
    control = (
        "Package: centinela\nVersion: %s\nArchitecture: all\nMaintainer: %s\n"
        "Installed-Size: %d\nDepends: python3 (>= 3.11)\nRecommends: needrestart, debsecan\nConflicts: centinel\n"
        "Section: admin\nPriority: optional\nDescription: %s\n" % (version, maintainer, size_kib, DESCRIPTION)
    )
    ctl = [("./", 0o755, None), ("./control", 0o644, control.encode()),
           ("./md5sums", 0o644, md5sums.encode()),
           ("./conffiles", 0o644, "".join("/%s\n" % c for c in sorted(conffiles)).encode())]
    ctl += [("./" + s, 0o755, (DEBIAN / s).read_bytes()) for s in ("postinst", "prerm", "postrm")]
    target.write_bytes(ar([("debian-binary", b"2.0\n"), ("control.tar.gz", tar_gz(ctl)), ("data.tar.gz", data)]))


def build(out_dir):
    version, maintainer = project()
    out_dir.mkdir(parents=True, exist_ok=True)
    exe = out_dir / "centinela"
    deb = out_dir / ("centinela_%s_all.deb" % version)
    build_zipapp(exe)
    build_deb(deb, version, maintainer, exe.read_bytes())
    sums = "".join("%s  %s\n" % (hashlib.sha256(p.read_bytes()).hexdigest(), p.name) for p in (deb, exe))
    (out_dir / "SHA256SUMS").write_text(sums)
    return [exe, deb], sums


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(ROOT / "dist"))
    paths, sums = build(Path(ap.parse_args().out))
    print("built %s\n%s" % (", ".join(str(p) for p in paths), sums), end="")
