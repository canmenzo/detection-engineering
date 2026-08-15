"""Install the pinned Hayabusa release, verified against its recorded checksum.

CI used to do this with curl, unzip and a `find` that guessed at the binary name.
When that guess came back empty the harness degraded to "skipped" and the build
went green having tested nothing. One pinned, hash-verified installer, used by
both CI and a local checkout, removes that whole class of failure.

Prints `HAYABUSA_BIN=<path>` so CI can append it straight to $GITHUB_ENV.
"""
from __future__ import annotations

import hashlib
import os
import platform
import stat
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import yaml

from detkit.paths import HAYABUSA_VERSION_FILE, REPO

INSTALL_DIR = REPO / "hayabusa"
RELEASE_URL = "https://github.com/Yamato-Security/hayabusa/releases/download/v{version}/{asset}"


class HayabusaError(Exception):
    """The pinned Hayabusa release could not be installed."""


def _pin() -> dict[str, Any]:
    try:
        doc = yaml.safe_load(HAYABUSA_VERSION_FILE.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise HayabusaError(f"{HAYABUSA_VERSION_FILE}: unreadable: {exc}") from exc
    if not isinstance(doc, dict) or "version" not in doc or "archives" not in doc:
        raise HayabusaError(f"{HAYABUSA_VERSION_FILE}: expected 'version' and 'archives'")
    return doc


def _platform_key() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    if system == "Windows":
        return "windows"
    raise HayabusaError(
        f"no pinned Hayabusa archive for {system}. Add one to "
        f"{HAYABUSA_VERSION_FILE.name} with its sha256, or set HAYABUSA_BIN yourself."
    )


def _find_binary() -> Path | None:
    """The extracted binary, whatever the release happens to call it."""
    if not INSTALL_DIR.is_dir():
        return None
    pattern = "hayabusa-*.exe" if platform.system() == "Windows" else "hayabusa-*"
    for candidate in sorted(INSTALL_DIR.glob(pattern)):
        if candidate.is_file() and candidate.suffix != ".zip":
            return candidate
    return None


def install() -> Path:
    pin = _pin()
    version = str(pin["version"])
    archives = pin["archives"]
    key = _platform_key()
    if key not in archives:
        raise HayabusaError(f"{HAYABUSA_VERSION_FILE.name} has no '{key}' archive")

    asset = str(archives[key]["asset"])
    expected = str(archives[key]["sha256"]).lower()

    existing = _find_binary()
    if existing is not None:
        return existing

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    archive = INSTALL_DIR / asset
    if not archive.is_file() or _sha256(archive) != expected:
        url = RELEASE_URL.format(version=version, asset=asset)
        print(f"downloading {url}", file=sys.stderr)
        try:
            with urllib.request.urlopen(url, timeout=300) as resp:
                archive.write_bytes(resp.read())
        except OSError as exc:
            raise HayabusaError(f"download failed: {exc}") from exc

    actual = _sha256(archive)
    if actual != expected:
        archive.unlink(missing_ok=True)
        raise HayabusaError(
            f"checksum mismatch for {asset}\n  expected {expected}\n  got      {actual}\n"
            f"Refusing to run an unverified binary."
        )

    with zipfile.ZipFile(archive) as zf:
        zf.extractall(INSTALL_DIR)

    binary = _find_binary()
    if binary is None:
        raise HayabusaError(f"no hayabusa binary found in {asset} after extraction")
    if platform.system() != "Windows":
        binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run() -> int:
    binary = install()
    # Hayabusa resolves its bundled rules/config relative to the binary, so the
    # harness runs from this directory. Emit the path in $GITHUB_ENV syntax.
    print(f"HAYABUSA_BIN={binary}")
    if os.environ.get("GITHUB_ENV"):
        print(f"installed {binary}", file=sys.stderr)
    return 0
