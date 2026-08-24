"""Offline Python restore helper shipped inside a Sealed Release.

It verifies the bundle, unwraps runtime secrets in memory, and starts the
copied application without contacting Git, PyPI, or any external service.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CONTEXT = b"still-alive/recovery-key/v1"


def unwrap(path: Path, recovery_key: str, purpose: str) -> bytes:
    data = json.loads(path.read_text(encoding="utf-8"))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=CONTEXT + b"/" + purpose.encode("ascii")).derive("".join(recovery_key.split()).encode("utf-8"))
    return AESGCM(key).decrypt(base64.b64decode(data["nonce"], validate=True), base64.b64decode(data["ciphertext"], validate=True), CONTEXT + b"/" + purpose.encode("ascii"))


def verify_bundle(root: Path) -> None:
    checksums = root / "checksums.sha256"
    for line in checksums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"checksum verification failed: {relative}")


def prepare_python(root: Path) -> Path:
    """Create an isolated runtime from local wheels when a strict bundle has one."""

    wheelhouse = root / "runtime/wheelhouse"
    requirements = wheelhouse / "requirements.lock"
    wheels = list(wheelhouse.glob("*.whl"))
    if not requirements.is_file() or not wheels:
        return Path(sys.executable)
    runtime_dir = root / "restored-data/runtime"
    python_path = runtime_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    if not python_path.is_file():
        runtime_dir.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call([sys.executable, "-m", "venv", str(runtime_dir)])
        subprocess.check_call([str(python_path), "-m", "pip", "install", "--no-index", "--find-links", str(wheelhouse), "--require-hashes", "-r", str(requirements)])
    return python_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Restore Still Alive from an offline Sealed Release")
    parser.add_argument("release_dir", type=Path)
    recovery_key_group = parser.add_mutually_exclusive_group(required=True)
    recovery_key_group.add_argument("--recovery-key")
    recovery_key_group.add_argument("--recovery-key-file", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="8000")
    args = parser.parse_args()
    root = args.release_dir.resolve()
    verify_bundle(root)
    recovery_key = args.recovery_key
    if args.recovery_key_file is not None:
        recovery_key = "".join(args.recovery_key_file.read_text(encoding="utf-8").split())
    assert recovery_key is not None

    master_key = unwrap(root / "recovery/master-key.wrap", recovery_key, "master-key-recovery")
    answer_pepper = unwrap(root / "recovery/answer-pepper.wrap", recovery_key, "answer-pepper-recovery")
    session_secret = unwrap(root / "recovery/session-secret.wrap", recovery_key, "session-secret-recovery")
    admin_auth_secret = unwrap(root / "recovery/admin-auth-secret.wrap", recovery_key, "admin-auth-secret-recovery")
    data_dir = root / "restored-data"
    data_dir.mkdir(exist_ok=True)
    database = data_dir / "app.db"
    database.write_bytes((root / "data/database.snapshot.sqlite").read_bytes())
    vault = data_dir / "vault"
    vault.mkdir(exist_ok=True)
    for source in (root / "data/vault").glob("*"):
        (vault / source.name).write_bytes(source.read_bytes())
    runtime_python = prepare_python(root)
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "production",
            "RELEASE_RUNTIME_MODE": "strict",
            "DATABASE_URL": f"sqlite:///{database}",
            "MASTER_KEY": base64.b64encode(master_key).decode("ascii"),
            "ANSWER_PEPPER": answer_pepper.decode("utf-8"),
            "SESSION_SECRET": session_secret.decode("utf-8"),
            "ADMIN_AUTH_SECRET": admin_auth_secret.decode("utf-8"),
            "VAULT_PATH": str(vault),
            "RELEASE_PATH": str(root / "releases"),
            "PUBLIC_BASE_URL": f"http://{args.host}:{args.port}",
            "RATE_LIMIT_ENABLED": "true",
        }
    )
    source = root / "source"
    return subprocess.call([str(runtime_python), "-m", "uvicorn", "app.main:app", "--app-dir", str(source), "--host", args.host, "--port", str(args.port)], env=environment, cwd=source)


if __name__ == "__main__":
    raise SystemExit(main())
