"""Unit tests for the pinned Hayabusa installer."""
from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

import pytest

from detkit import hayabusa as hb
from detkit.hayabusa import HayabusaError

PIN = """\
version: 3.9.0
archives:
  linux:
    asset: hayabusa-3.9.0-lin-x64-gnu.zip
    sha256: {sha}
  windows:
    asset: hayabusa-3.9.0-win-x64.zip
    sha256: {sha}
"""


def _fake_release(tmp_path: Path, name: str) -> tuple[Path, str]:
    """A zip containing a stand-in binary, plus its sha256."""
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(name, "#!/bin/sh\necho hayabusa\n")
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


def test_reads_the_real_pin_file() -> None:
    """The committed pin must stay parseable and complete."""
    pin = hb._pin()
    assert pin["version"]
    for key in ("linux", "windows"):
        assert len(pin["archives"][key]["sha256"]) == 64
        assert pin["archives"][key]["asset"].endswith(".zip")


def test_rejects_a_malformed_pin(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bad = tmp_path / ".hayabusa-version"
    bad.write_text("3.9.0\n", encoding="utf-8")
    monkeypatch.setattr(hb, "HAYABUSA_VERSION_FILE", bad)
    with pytest.raises(HayabusaError, match="expected 'version' and 'archives'"):
        hb._pin()


def test_installs_from_a_verified_archive(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    name = "hayabusa-3.9.0-win-x64.exe"
    archive, sha = _fake_release(tmp_path, name)

    pin = tmp_path / ".hayabusa-version"
    pin.write_text(PIN.format(sha=sha), encoding="utf-8")
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    # Pre-stage the archive under the expected name so no download is attempted.
    (install_dir / "hayabusa-3.9.0-win-x64.zip").write_bytes(archive.read_bytes())
    (install_dir / "hayabusa-3.9.0-lin-x64-gnu.zip").write_bytes(archive.read_bytes())

    monkeypatch.setattr(hb, "HAYABUSA_VERSION_FILE", pin)
    monkeypatch.setattr(hb, "INSTALL_DIR", install_dir)

    binary = hb.install()
    assert binary.exists()
    assert binary.name.startswith("hayabusa-")


def test_refuses_an_archive_whose_checksum_does_not_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unverified binary must never be executed."""
    name = "hayabusa-3.9.0-win-x64.exe"
    archive, _ = _fake_release(tmp_path, name)

    pin = tmp_path / ".hayabusa-version"
    pin.write_text(PIN.format(sha="0" * 64), encoding="utf-8")
    install_dir = tmp_path / "install"
    install_dir.mkdir()
    (install_dir / "hayabusa-3.9.0-win-x64.zip").write_bytes(archive.read_bytes())
    (install_dir / "hayabusa-3.9.0-lin-x64-gnu.zip").write_bytes(archive.read_bytes())

    monkeypatch.setattr(hb, "HAYABUSA_VERSION_FILE", pin)
    monkeypatch.setattr(hb, "INSTALL_DIR", install_dir)

    # A staged archive that fails the hash is re-fetched once; serve the same
    # bad bytes so the second verification is the one under test.
    class _FakeResponse:
        def __init__(self, data: bytes) -> None:
            self._data = data

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

        def read(self) -> bytes:
            return self._data

    payload = archive.read_bytes()
    monkeypatch.setattr(
        "urllib.request.urlopen", lambda *a, **k: _FakeResponse(payload)
    )

    with pytest.raises(HayabusaError, match="checksum mismatch"):
        hb.install()
