"""Create a temporary OCI restore environment from a separately held key."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


CONTEXT = b"still-alive/recovery-key/v1"


def unwrap(path: Path, recovery_key: str, purpose: str) -> bytes:
    wrapper = json.loads(path.read_text(encoding="utf-8"))
    info = CONTEXT + b"/" + purpose.encode("ascii")
    derived = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(recovery_key.encode("utf-8"))
    return AESGCM(derived).decrypt(base64.b64decode(wrapper["nonce"], validate=True), base64.b64decode(wrapper["ciphertext"], validate=True), info)


def main() -> int:
    parser = argparse.ArgumentParser(description="Write a temporary OCI env file")
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("recovery_key_file", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = args.release_dir.resolve()
    recovery_key = "".join(args.recovery_key_file.read_text(encoding="utf-8").split())
    values = {
        "APP_ENV": "production",
        "RELEASE_RUNTIME_MODE": "strict",
        "MASTER_KEY": base64.b64encode(unwrap(root / "recovery/master-key.wrap", recovery_key, "master-key-recovery")).decode("ascii"),
        "ANSWER_PEPPER": unwrap(root / "recovery/answer-pepper.wrap", recovery_key, "answer-pepper-recovery").decode("utf-8"),
        "SESSION_SECRET": unwrap(root / "recovery/session-secret.wrap", recovery_key, "session-secret-recovery").decode("utf-8"),
        "ADMIN_AUTH_SECRET": unwrap(root / "recovery/admin-auth-secret.wrap", recovery_key, "admin-auth-secret-recovery").decode("utf-8"),
        "DATABASE_URL": "sqlite:////app/data/app.db",
        "VAULT_PATH": "/app/data/vault",
        "RELEASE_PATH": "/app/data/releases",
        "PUBLIC_BASE_URL": "http://127.0.0.1:8000",
        "RATE_LIMIT_ENABLED": "true",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(f"{key}={value}\n" for key, value in values.items()), encoding="utf-8")
    if os.name != "nt":
        args.output.chmod(0o600)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
