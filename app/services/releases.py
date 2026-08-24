"""Sealed Release gates, immutable bundle construction, and validation."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from sqlalchemy import func, select
from sqlalchemy.engine import Engine, make_url
from sqlalchemy.orm import Session

from app.config import Settings
from app.models.asset import Asset
from app.models.identity import Person
from app.models.integrity import IdentityIntegritySnapshot
from app.models.release import RecoveryKeyRecord, SealedRelease
from app.models.verification import VerificationAnswerDigest, VerificationChallenge
from app.services.assets import decrypt_asset
from app.services.audit import record_audit
from app.services.recovery import verify_recovery_key, wrap_recovery_secret


VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class GateResult:
    key: str
    label: str
    passed: bool
    detail: str

    def as_dict(self) -> dict[str, object]:
        return {"key": self.key, "label": self.label, "passed": self.passed, "detail": self.detail}


class ReleaseGateError(HTTPException):
    def __init__(self, gates: list[GateResult]) -> None:
        self.gates = gates
        super().__init__(status_code=409, detail="sealed release gate failed")


def _latest_snapshot(db: Session) -> IdentityIntegritySnapshot | None:
    return db.scalar(select(IdentityIntegritySnapshot).order_by(IdentityIntegritySnapshot.created_at.desc()).limit(1))


def _migration_state(engine: Engine) -> tuple[bool, str]:
    try:
        with engine.connect() as connection:
            current = MigrationContext.configure(connection).get_current_revision()
        config = Config(str(ROOT / "alembic.ini"))
        heads = ScriptDirectory.from_config(config).get_heads()
        return current in heads and len(heads) == 1, f"current={current or 'none'} head={','.join(heads)}"
    except Exception:
        return False, "migration state unavailable"


def _active_challenge_counts(db: Session) -> dict[str, int]:
    rows = db.execute(select(VerificationChallenge.person_id, func.count(VerificationChallenge.id)).where(VerificationChallenge.active.is_(True)).group_by(VerificationChallenge.person_id)).all()
    return {person_id: int(count) for person_id, count in rows}


def evaluate_gates(db: Session, engine: Engine, settings: Settings, *, recovery_key: str | None = None) -> list[GateResult]:
    snapshot = _latest_snapshot(db)
    integrity_ok = snapshot is not None and snapshot.mode in {"full", "seal"} and snapshot.status == "pass" and snapshot.blocking_pair_count == 0 and snapshot.warning_pair_count == 0
    gates = [GateResult("integrity", "Identity Integrity FULL/SEAL PASS、无 Blocking/Warning Pair", integrity_ok, "无可用 PASS snapshot" if snapshot is None else f"snapshot={snapshot.id}, status={snapshot.status}, mode={snapshot.mode}")]

    people = db.scalars(select(Person).where(Person.status == "active")).all()
    challenge_counts = _active_challenge_counts(db)
    missing_people = [person.id for person in people if challenge_counts.get(person.id, 0) < 1]
    gates.append(GateResult("active_person_challenges", "每个 Active Person 至少一个 Active Verification Challenge", not missing_people, f"missing={len(missing_people)}"))

    active_challenges = db.scalars(select(VerificationChallenge).where(VerificationChallenge.active.is_(True))).all()
    digest_counts = {challenge_id: int(count) for challenge_id, count in db.execute(select(VerificationAnswerDigest.challenge_id, func.count(VerificationAnswerDigest.id)).group_by(VerificationAnswerDigest.challenge_id)).all()}
    missing_digests = [challenge.id for challenge in active_challenges if digest_counts.get(challenge.id, 0) < 1]
    gates.append(GateResult("verification_digests", "Verification digest 自检", not missing_digests, f"missing={len(missing_digests)}"))

    active_assets = db.scalars(select(Asset).where(Asset.active.is_(True))).all()
    asset_errors: list[str] = []
    for asset in active_assets:
        try:
            decrypt_asset(asset, settings)
        except Exception as exc:
            asset_errors.append(f"{asset.id}:{type(exc).__name__}")
    gates.append(GateResult("asset_roundtrip", "Active Asset decrypt roundtrip 与 ciphertext checksum", not asset_errors, f"checked={len(active_assets)}, errors={len(asset_errors)}"))
    gates.append(GateResult("vault", "Vault 基础访问", settings.vault_path.exists() and settings.vault_path.is_dir(), str(settings.vault_path)))

    try:
        settings.master_key_bytes
        pepper_loaded = settings.answer_pepper is not None and bool(settings.answer_pepper.get_secret_value())
        secrets_ok = pepper_loaded
    except Exception:
        secrets_ok = False
    gates.append(GateResult("runtime_secrets", "Master Key 与 Answer Pepper 已加载", secrets_ok, "loaded" if secrets_ok else "missing"))

    recovery_record = db.scalar(select(RecoveryKeyRecord).where(RecoveryKeyRecord.rotated_at.is_(None)).limit(1))
    recovery_ok = recovery_record is not None
    if recovery_key is not None and recovery_ok:
        try:
            verify_recovery_key(db, settings, recovery_key)
        except HTTPException:
            recovery_ok = False
    gates.append(GateResult("recovery_key", "Recovery Key configured and verified", recovery_ok, recovery_record.key_id if recovery_record else "not configured"))

    migration_ok, migration_detail = _migration_state(engine)
    gates.append(GateResult("migration", "DB migration state clean", migration_ok, migration_detail))
    lock_path = ROOT / "requirements.lock"
    dependency_ok = lock_path.is_file() and bool(lock_path.read_text(encoding="utf-8").strip()) and (ROOT / "pyproject.toml").is_file()
    gates.append(GateResult("dependencies", "dependency lock 完整", dependency_ok, str(lock_path)))
    runtime_inputs_ok = all((ROOT / name).is_file() for name in ("Dockerfile", "compose.yaml", "scripts/restore_offline.py", "scripts/restore-oci.sh", "scripts/verify_release.py", "scripts/verify-release.sh", "scripts/write_oci_env.py"))
    docker_available = False
    if shutil.which("docker") is not None:
        try:
            docker_available = subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, timeout=30).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            docker_available = False
    runtime_ok = runtime_inputs_ok and (settings.release_runtime_mode == "source_fallback" or docker_available)
    runtime_detail = "source Python fallback explicitly enabled" if settings.release_runtime_mode == "source_fallback" else ("Docker daemon available" if docker_available else "strict mode requires a reachable Docker daemon")
    gates.append(GateResult("offline_runtime", "offline runtime artifact 可构建", runtime_ok, runtime_detail if runtime_inputs_ok else "runtime input missing"))
    return gates


def _safe_version(version: str) -> str:
    value = version.strip()
    if not VERSION_PATTERN.fullmatch(value):
        raise HTTPException(status_code=422, detail="invalid release version")
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def _copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def _snapshot_database(settings: Settings, destination: Path) -> None:
    url = make_url(settings.database_url)
    if url.get_backend_name() != "sqlite" or url.database in (None, ":memory:"):
        raise RuntimeError("Phase 10 snapshot currently requires a file-backed SQLite database")
    source = Path(url.database)
    if not source.is_absolute():
        source = (ROOT / source).resolve()
    if not source.is_file():
        raise RuntimeError("database file not found")
    source_connection = sqlite3.connect(str(source))
    destination_connection = sqlite3.connect(str(destination))
    try:
        source_connection.backup(destination_connection)
    finally:
        destination_connection.close()
        source_connection.close()


def _wheelhouse_lock(wheelhouse: Path) -> None:
    from email.parser import Parser
    from zipfile import ZipFile

    requirements: list[str] = []
    for wheel in sorted(wheelhouse.glob("*.whl")):
        with ZipFile(wheel) as archive:
            metadata_name = next((name for name in archive.namelist() if name.endswith(".dist-info/METADATA")), None)
            if metadata_name is None:
                raise RuntimeError(f"wheel metadata missing: {wheel.name}")
            metadata = Parser().parsestr(archive.read(metadata_name).decode("utf-8"))
        name = metadata.get("Name")
        version = metadata.get("Version")
        if not name or not version:
            raise RuntimeError(f"wheel metadata incomplete: {wheel.name}")
        requirements.append(f"{name}=={version} --hash=sha256:{_sha256(wheel)}")
    if not requirements:
        raise RuntimeError("wheelhouse is empty")
    (wheelhouse / "requirements.lock").write_text("\n".join(requirements) + "\n", encoding="utf-8")


def _write_runtime_bundle(root: Path, version: str, settings: Settings) -> Path | None:
    _copy_tree(ROOT / "app", root / "source/app")
    _copy_tree(ROOT / "migrations", root / "source/migrations")
    for filename in ("alembic.ini", "pyproject.toml", "requirements.lock", "Dockerfile", "compose.yaml"):
        shutil.copy2(ROOT / filename, root / f"source/{filename}")
    shutil.copy2(ROOT / "scripts/restore_offline.py", root / "scripts/restore_offline.py")
    shutil.copy2(ROOT / "scripts/restore-oci.sh", root / "scripts/restore-oci.sh")
    shutil.copy2(ROOT / "scripts/verify_release.py", root / "scripts/verify_release.py")
    shutil.copy2(ROOT / "scripts/verify-release.sh", root / "scripts/verify-release.sh")
    shutil.copy2(ROOT / "scripts/write_oci_env.py", root / "scripts/write_oci_env.py")
    shutil.copy2(ROOT / "scripts/restore-linux.sh", root / "scripts/restore-linux.sh")
    shutil.copy2(ROOT / "compose.yaml", root / "container/compose.yaml")
    (root / ".dockerignore").write_text("data\nrecovery\nrestored-data\n*.zip\ncontainer/*.tar\n", encoding="utf-8")
    (root / "runtime/python/README.txt").write_text("Use a supported offline Python 3.12 runtime and install only from runtime/wheelhouse.\n", encoding="utf-8")
    wheelhouse = root / "runtime/wheelhouse"
    if settings.release_runtime_mode == "strict":
        subprocess.run([sys.executable, "-m", "pip", "download", "--only-binary=:all:", "--require-hashes", "--platform", "manylinux_2_17_x86_64", "--python-version", "3.12", "--implementation", "cp", "--abi", "cp312", "--dest", str(wheelhouse), "-r", str(root / "source/requirements.lock")], check=True, timeout=600)
        _wheelhouse_lock(wheelhouse)
        offline_dockerfile = root / "container/Dockerfile.offline"
        offline_dockerfile.write_text(
            "FROM python:3.12-slim\n"
            "COPY runtime/wheelhouse /wheelhouse\n"
            "RUN python -m pip install --no-index --find-links=/wheelhouse --require-hashes -r /wheelhouse/requirements.lock\n"
            "WORKDIR /app/source\n"
            "COPY source/pyproject.toml ./\nCOPY source/app ./app\nCOPY source/migrations ./migrations\nCOPY source/alembic.ini ./\nCOPY scripts /app/scripts\n"
            "EXPOSE 8000\nCMD [\"sh\", \"-c\", \"alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000\"]\n",
            encoding="utf-8",
        )
        (root / "container/compose.yaml").write_text(
            f"services:\n  still-alive:\n    image: still-alive:offline-{version}\n    env_file:\n      - ${{STILL_ALIVE_ENV_FILE}}\n    ports:\n      - '${{STILL_ALIVE_HOST_PORT:-8000}}:8000'\n    volumes:\n      - ${{STILL_ALIVE_DATA_DIR}}:/app/data\n    restart: unless-stopped\n",
            encoding="utf-8",
        )
        tag = f"still-alive:offline-{version}"
        subprocess.run(["docker", "build", "--tag", tag, "--file", "container/Dockerfile.offline", "."], cwd=root, check=True, timeout=1200)
        image_path = root / "container/still-alive-image.tar"
        subprocess.run(["docker", "save", "--output", str(image_path), tag], cwd=root, check=True, timeout=600)
        subprocess.run(["docker", "load", "--input", str(image_path)], check=True, stdout=subprocess.DEVNULL, timeout=600)
        subprocess.run(["docker", "image", "inspect", tag], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        return image_path

    (wheelhouse / "README.txt").write_text("Source fallback mode: use the supported Python environment. Strict release mode populates this directory with hashed wheels.\n", encoding="utf-8")
    context_path = root / "container/still-alive-build-context.tar"
    with tarfile.open(context_path, "w") as archive:
        for name in ("Dockerfile", "compose.yaml", "pyproject.toml", "requirements.lock"):
            archive.add(root / f"source/{name}", arcname=name)
        archive.add(root / "source/app", arcname="app")
        archive.add(root / "source/migrations", arcname="migrations")
    (root / "container/BUILD-CONTEXT-NOT-IMAGE.txt").write_text("This is a source build context, not an OCI image. Use RELEASE_RUNTIME_MODE=strict on a machine with Docker to create still-alive-image.tar.\n", encoding="utf-8")
    return None


def _write_readme(root: Path, runtime_mode: str) -> None:
    (root / "README-FIRST.txt").write_text(
        "Still Alive Sealed Release\n\n"
        "This package is an offline recovery copy of the private Still Alive delivery system.\n"
        "Keep the entire package, especially data/, recovery/, source/, and scripts/.\n"
        "Never put the Recovery Key, Master Key, or Answer Pepper inside this package or Git.\n"
        "Verify checksums.sha256, then use scripts/restore_offline.py with the separately stored Recovery Key.\n"
        f"Runtime mode for this bundle: {runtime_mode}; strict wheelhouse target is Linux x86_64 / CPython 3.12. With the image tar, run scripts/restore-oci.sh <release-dir> <recovery-key-file>; otherwise run scripts/restore-linux.sh <release-dir> --recovery-key-file <key-file>. Browse to http://127.0.0.1:8000/.\n"
        "Recovery does not require Git, PyPI, Docker Hub, an author, a heartbeat, or a waiting countdown.\n"
        "Do not upload this package or any recovery material to a third-party website.\n"
        "It contains private encrypted metadata and should be handled according to applicable privacy and legal obligations.\n",
        encoding="utf-8",
    )
    (root / "docs/RECOVERY.md").write_text("OCI path: scripts/restore-oci.sh <release-directory> <recovery-key-file>\nPython path: scripts/restore-linux.sh <release-directory> --recovery-key-file <key-file>\n\nStore the key separately from the release archive.\n", encoding="utf-8")
    (root / "docs/SECURITY.md").write_text("The release contains encrypted metadata and Vault ciphertext. The Recovery Key is intentionally excluded.\n", encoding="utf-8")


def _write_vault(root: Path, settings: Settings) -> tuple[str, list[dict[str, object]]]:
    destination = root / "data/vault"
    manifest: list[dict[str, object]] = []
    source_root = settings.vault_path.resolve()
    if source_root.exists():
        for source in sorted(path for path in source_root.iterdir() if path.is_file()):
            target = destination / source.name
            shutil.copy2(source, target)
            manifest.append({"path": source.name, "sha256": _sha256(target), "size": target.stat().st_size})
    manifest_path = root / "data/vault-manifest.json"
    manifest_path.write_text(json.dumps({"version": "v1", "files": manifest}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _relative(root, manifest_path), manifest


def _write_checksums(root: Path, *, metadata: dict[str, object] | None = None) -> tuple[str, str]:
    manifest_path = root / "manifest.json"
    files: list[dict[str, object]] = []
    for path in sorted(path for path in root.rglob("*") if path.is_file() and path.name not in {"manifest.json", "checksums.sha256"}):
        files.append({"path": _relative(root, path), "sha256": _sha256(path), "size": path.stat().st_size})
    manifest_path.write_text(json.dumps({"version": "v1", "app_version": "0.1.0", **(metadata or {}), "files": files}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_digest = _sha256(manifest_path)
    checksum_lines = [f"{manifest_digest}  manifest.json"] + [f"{item['sha256']}  {item['path']}" for item in files]
    checksums_path = root / "checksums.sha256"
    checksums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    return _relative(root, manifest_path), manifest_digest


def _validate_bundle(root: Path, recovery_key: str, settings: Settings) -> str:
    for line in (root / "checksums.sha256").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        expected, relative = line.split("  ", 1)
        if _sha256(root / relative) != expected:
            raise RuntimeError(f"checksum mismatch: {relative}")
    wrappers = {
        "master-key.wrap": ("master-key-recovery", None),
        "answer-pepper.wrap": ("answer-pepper-recovery", None),
        "session-secret.wrap": ("session-secret-recovery", None),
        "admin-auth-secret.wrap": ("admin-auth-secret-recovery", None),
    }
    from app.services.recovery import unwrap_recovery_secret

    for filename, (purpose, _) in wrappers.items():
        unwrap_recovery_secret((root / f"recovery/{filename}").read_bytes(), recovery_key, purpose=purpose)
    database = root / "data/database.snapshot.sqlite"
    with sqlite3.connect(str(database)) as connection:
        revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        if revision is None or not revision[0]:
            raise RuntimeError("database migration revision missing")
    vault_manifest = json.loads((root / "data/vault-manifest.json").read_text(encoding="utf-8"))
    for item in vault_manifest.get("files", []):
        vault_file = (root / "data/vault" / item["path"]).resolve()
        if root not in vault_file.parents or _sha256(vault_file) != item["sha256"]:
            raise RuntimeError("Vault manifest verification failed")
    if settings.release_runtime_mode == "strict" and not (root / "container/still-alive-image.tar").is_file():
        raise RuntimeError("strict release has no OCI image tar")
    if recovery_key.encode("utf-8") in b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file()):
        raise RuntimeError("recovery key leaked into release bundle")
    return _sha256(root / "manifest.json")


def build_release(engine: Engine, settings: Settings, *, version: str, recovery_key: str, actor_id: str | None = None) -> SealedRelease:
    version = _safe_version(version)
    release_root = (settings.release_path / version).resolve()
    release_base = settings.release_path.resolve()
    if release_root.parent != release_base or release_root.exists():
        raise HTTPException(status_code=409, detail="release version already exists or path is invalid")
    with Session(engine) as db:
        gates = evaluate_gates(db, engine, settings, recovery_key=recovery_key)
        if not all(gate.passed for gate in gates):
            raise ReleaseGateError(gates)
        record = verify_recovery_key(db, settings, recovery_key)
        snapshot = _latest_snapshot(db)
        recovery_key_id = record.key_id
        integrity_snapshot_id = snapshot.id if snapshot else None
        release = SealedRelease(version=version, status="building", integrity_snapshot_id=integrity_snapshot_id, recovery_key_id=recovery_key_id)
        db.add(release)
        db.flush()
        record_audit(db, actor_type="admin", event_type="sealed_release.build.started", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"version": version})
        db.commit()
        release_id = release.id
    try:
        release_root.mkdir(parents=True)
        for directory in ("data/vault", "recovery", "runtime/python", "runtime/wheelhouse", "container", "scripts", "docs"):
            (release_root / directory).mkdir(parents=True, exist_ok=True)
        _snapshot_database(settings, release_root / "data/database.snapshot.sqlite")
        with Session(engine) as db:
            vault_manifest, _ = _write_vault(release_root, settings)
        runtime_artifact = _write_runtime_bundle(release_root, version, settings)
        _write_readme(release_root, settings.release_runtime_mode)
        (release_root / "recovery/recovery-key-id.txt").write_text(recovery_key_id + "\n", encoding="utf-8")
        recovery_files = {
            "master-key.wrap": (settings.master_key_bytes, "master-key-recovery"),
            "answer-pepper.wrap": (settings.answer_pepper.get_secret_value().encode("utf-8"), "answer-pepper-recovery"),
            "session-secret.wrap": (settings.session_secret.get_secret_value().encode("utf-8"), "session-secret-recovery"),
            "admin-auth-secret.wrap": (settings.admin_auth_secret.get_secret_value().encode("utf-8"), "admin-auth-secret-recovery"),
        }
        for filename, (secret, purpose) in recovery_files.items():
            (release_root / "recovery" / filename).write_bytes(wrap_recovery_secret(secret, recovery_key, purpose=purpose))
        manifest_path, manifest_digest = _write_checksums(release_root, metadata={"release_version": version, "integrity_snapshot_id": integrity_snapshot_id, "runtime_mode": settings.release_runtime_mode})
        archive_path = release_base / f"{version}.zip"
        shutil.make_archive(str(archive_path.with_suffix("")), "zip", root_dir=release_root.parent, base_dir=release_root.name)
        _validate_bundle(release_root, recovery_key, settings)
        with Session(engine) as db:
            release = db.get(SealedRelease, release_id)
            assert release is not None
            release.status = "ready"
            release.validated_at = datetime.now(timezone.utc)
            release.database_snapshot_path = _relative(release_base, release_root / "data/database.snapshot.sqlite")
            release.vault_manifest_path = _relative(release_base, release_root / vault_manifest)
            release.oci_image_path = _relative(release_base, runtime_artifact) if runtime_artifact is not None else None
            release.wheelhouse_path = _relative(release_base, release_root / "runtime/wheelhouse")
            release.recovery_wrapped_master_key_path = _relative(release_base, release_root / "recovery/master-key.wrap")
            release.recovery_wrapped_answer_pepper_path = _relative(release_base, release_root / "recovery/answer-pepper.wrap")
            release.manifest_sha256 = manifest_digest
            release.archive_path = str(archive_path)
            record_audit(db, actor_type="admin", event_type="sealed_release.validation.completed", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"version": release.version, "manifest_sha256": manifest_digest})
            record_audit(db, actor_type="admin", event_type="sealed_release.build.completed", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"version": release.version})
            db.commit()
            db.refresh(release)
            return release
    except Exception as exc:
        shutil.rmtree(release_root, ignore_errors=True)
        archive_path = release_base / f"{version}.zip"
        if archive_path.exists():
            archive_path.unlink()
        with Session(engine) as db:
            release = db.get(SealedRelease, release_id)
            if release is not None:
                release.status = "failed"
                release.error_message = "release build failed"
                record_audit(db, actor_type="admin", event_type="sealed_release.validation.failed", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"version": version, "error_type": type(exc).__name__})
                db.commit()
        raise HTTPException(status_code=500, detail="sealed release build failed") from exc


def validate_existing_release(engine: Engine, settings: Settings, *, release_id: str, recovery_key: str, actor_id: str | None = None) -> SealedRelease:
    with Session(engine) as db:
        release = db.get(SealedRelease, release_id)
        if release is None:
            raise HTTPException(status_code=404, detail="Release not found")
        if release.status == "revoked":
            raise HTTPException(status_code=409, detail="revoked release cannot be validated")
        verify_recovery_key(db, settings, recovery_key)
        release_root = (settings.release_path / release.version).resolve()
        release_base = settings.release_path.resolve()
        if release_root.parent != release_base or not release_root.is_dir():
            raise HTTPException(status_code=404, detail="release files not found")
        try:
            manifest_digest = _validate_bundle(release_root, recovery_key, settings)
        except Exception as exc:
            release.status = "failed"
            release.error_message = "release validation failed"
            record_audit(db, actor_type="admin", event_type="sealed_release.validation.failed", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"error_type": type(exc).__name__})
            db.commit()
            raise HTTPException(status_code=409, detail="release validation failed") from exc
        release.status = "ready"
        release.manifest_sha256 = manifest_digest
        release.validated_at = datetime.now(timezone.utc)
        record_audit(db, actor_type="admin", event_type="sealed_release.validation.completed", actor_id=actor_id, target_type="release", target_id=release.id, metadata={"manifest_sha256": manifest_digest})
        db.commit()
        db.refresh(release)
        return release
