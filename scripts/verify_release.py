"""Verify a Sealed Release without importing the application source."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(root: Path) -> dict[str, object]:
    root = root.resolve()
    checksums = root / "checksums.sha256"
    for line in checksums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        path = (root / relative).resolve()
        if root not in path.parents or sha256(path) != expected:
            raise ValueError(f"checksum verification failed: {relative}")
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    return {"status": "verified", "release_version": manifest.get("release_version"), "file_count": len(manifest.get("files", []))}


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a Still Alive Sealed Release")
    parser.add_argument("release_dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.release_dir), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
