import asyncio
import concurrent.futures
import os
import subprocess
import sys
from pathlib import Path

import jwt
import pytest
from sqlalchemy import text

from resource_api.auth import JwksVerifier, TokenRejected
from temis_sso.config import settings
from temis_sso.keyring import KeyRing
from temis_sso.persistence import session_scope
from temis_sso.tokens import RingTokenCodec


def test_key_rotation_publish_activate_retire(tmp_path: Path) -> None:
    now = [0.0]
    ring = KeyRing(tmp_path, clock=lambda: now[0], overlap_seconds=960)
    old = ring.publish()
    assert (tmp_path / f"{old}.private.pem").stat().st_mode & 0o777 == 0o600
    ring.activate(old)
    token = ring.sign("user-1", "https://auth.lab.invalid", "temis-lab")
    new = ring.publish()
    assert {key["kid"] for key in ring.jwks()["keys"]} == {old, new}
    now[0] = 10
    ring.activate(new)
    assert (
        jwt.get_unverified_header(ring.sign("user-1", "https://auth.lab.invalid", "temis-lab"))[
            "kid"
        ]
        == new
    )
    with pytest.raises(ValueError, match="overlap"):
        ring.retire(old)
    now[0] = 969
    with pytest.raises(ValueError, match="overlap"):
        ring.retire(old)
    now[0] = 970
    ring.retire(old)
    assert {key["kid"] for key in ring.jwks()["keys"]} == {new}
    with pytest.raises(ValueError):
        ring.retire(new)
    assert jwt.get_unverified_header(token)["kid"] == old


def test_expand_contract_and_restore_runbook_are_safe() -> None:
    expand = Path("migrations/versions/0002_expand_authz_version.py").read_text()
    contract = Path("migrations/versions/0003_contract_authz_version.py").read_text()
    restore = Path("scripts/restore-isolated.sh").read_text()
    assert "nullable=True" in expand and "nullable=False" in contract
    assert "sha256sum --check" in restore and "refusing to restore" in restore
    assert "RESTORE_LIBPQ_URL" in restore and "RESTORE_ASYNC_DATABASE_URL" in restore
    assert "EXPECTED_RESTORE_DATABASE|t" in restore


def test_secret_boundary_assigns_private_keys_only_to_signer() -> None:
    boundary = Path("ops/SECRET-BOUNDARY.md").read_text()
    assert "SSO signer alone reads private signing keys" in boundary
    assert "Resource API receives only public JWKS" in boundary


def test_restore_script_executes_only_against_propagated_isolated_url(tmp_path: Path) -> None:
    archive = tmp_path / "backup.dump"
    archive.write_text("validated backup")
    checksum = subprocess.run(
        ["sha256sum", str(archive)], capture_output=True, text=True, check=True
    ).stdout
    Path(f"{archive}.sha256").write_text(checksum)
    tools = tmp_path / "bin"
    tools.mkdir()
    marker = tmp_path / "calls"
    for name in ["alembic", "pytest"]:
        executable = tools / name
        executable.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"echo {name}:$TEMIS_LAB_DATABASE_URL >> {marker}\n"
        )
        executable.chmod(0o755)
    psql = tools / "psql"
    psql.write_text(
        "#!/usr/bin/env bash\nprintf '%s\\n' \"${PSQL_IDENTITY:-isolated_restore|t}\"\n"
    )
    psql.chmod(0o755)
    pg_restore = tools / "pg_restore"
    pg_restore.write_text(
        f"#!/usr/bin/env bash\nset -euo pipefail\necho pg_restore:$* >> {marker}\n"
    )
    pg_restore.chmod(0o755)
    verifier = tools / "verify-python"
    verifier.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"echo verifier:$RESTORE_ASYNC_DATABASE_URL >> {marker}\n"
    )
    verifier.chmod(0o755)
    libpq = "postgresql://lab@127.0.0.1:55439/isolated_restore"
    async_url = "postgresql+asyncpg://lab@127.0.0.1:55439/isolated_restore"
    environment = {
        **os.environ,
        "PATH": f"{tools}:{os.environ['PATH']}",
        "ARCHIVE": str(archive),
        "RESTORE_LIBPQ_URL": libpq,
        "RESTORE_ASYNC_DATABASE_URL": async_url,
        "EXPECTED_RESTORE_DATABASE": "isolated_restore",
        "PYTHON_BIN": str(verifier),
    }
    subprocess.run(["bash", "scripts/restore-isolated.sh"], env=environment, check=True)
    calls = marker.read_text()
    assert f"pg_restore:--exit-on-error --clean --if-exists --dbname {libpq}" in calls
    assert calls.count(async_url) == 3
    for production in [
        {"PRODUCTION_LIBPQ_URL": libpq},
        {"PRODUCTION_ASYNC_DATABASE_URL": async_url},
    ]:
        refused = subprocess.run(
            ["bash", "scripts/restore-isolated.sh"],
            env={**environment, **production},
            capture_output=True,
            text=True,
            check=False,
        )
        assert refused.returncode == 2 and "refusing" in refused.stderr

    before = marker.read_text()
    wrong_target = subprocess.run(
        ["bash", "scripts/restore-isolated.sh"],
        env={**environment, "PSQL_IDENTITY": "production|f"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert wrong_target.returncode == 3 and marker.read_text() == before

    archive.write_text("tampered")
    bad_checksum = subprocess.run(
        ["bash", "scripts/restore-isolated.sh"],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad_checksum.returncode != 0 and marker.read_text() == before


def test_packaged_compose_has_persistence_and_health_contract() -> None:
    result = subprocess.run(
        ["docker", "compose", "-f", "compose.yaml", "config"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "postgres-data" in result.stdout and "redis-data" in result.stdout
    assert result.stdout.count("healthcheck:") == 2


@pytest.mark.asyncio
async def test_async_restore_verifier_queries_live_identity_and_marker() -> None:
    async with session_scope() as session:
        await session.execute(text("create table if not exists temis_restore_target(id integer)"))
    expected = settings.database_url.rsplit("/", 1)[-1]
    verified = await asyncio.create_subprocess_exec(
        sys.executable,
        "scripts/verify-restore-target.py",
        env={
            **os.environ,
            "RESTORE_ASYNC_DATABASE_URL": settings.database_url,
            "EXPECTED_RESTORE_DATABASE": expected,
        },
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, verified_stderr = await verified.communicate()
    assert verified.returncode == 0, verified_stderr.decode()
    rejected = await asyncio.create_subprocess_exec(
        sys.executable,
        "scripts/verify-restore-target.py",
        env={
            **os.environ,
            "RESTORE_ASYNC_DATABASE_URL": settings.database_url,
            "EXPECTED_RESTORE_DATABASE": "production",
        },
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, rejected_stderr = await rejected.communicate()
    assert rejected.returncode != 0 and b"refusing" in rejected_stderr


def test_expand_contract_rollback_guard_is_reversible_on_live_database() -> None:
    environment = {**os.environ, "TEMIS_LAB_DATABASE_URL": settings.database_url}
    subprocess.run(
        [sys.executable, "-m", "alembic", "downgrade", "0002_expand_authz_version"],
        env=environment,
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        env=environment,
        check=True,
    )


@pytest.mark.asyncio
async def test_actual_codec_jwks_overlap_then_retirement(tmp_path: Path) -> None:
    now = [0.0]
    ring = KeyRing(tmp_path, clock=lambda: now[0], overlap_seconds=960)
    old = ring.publish()
    ring.activate(old)
    codec = RingTokenCodec(ring)
    old_token = codec.issue_access(
        "user-1", roles=["temis:user"], scopes=["reports:read"], authz_version=1
    )
    new = ring.publish()

    async def status(subject: str, version: int) -> bool:
        return subject == "user-1" and version == 1

    async def fetch() -> dict[str, object]:
        return ring.jwks()

    verifier = JwksVerifier(
        fetch,
        status,
        issuer="https://auth.lab.invalid",
        audience="temis-lab",
        authorized_party="temis-web",
        jwks_ttl=0,
    )
    assert (await verifier.authenticate(old_token)).subject == "user-1"
    now[0] = 10
    ring.activate(new)
    new_token = codec.issue_access(
        "user-1", roles=["temis:user"], scopes=["reports:read"], authz_version=1
    )
    assert (await verifier.authenticate(old_token)).subject == "user-1"
    assert (await verifier.authenticate(new_token)).subject == "user-1"
    with pytest.raises(ValueError, match="overlap"):
        ring.retire(old)
    now[0] = 970
    ring.retire(old)
    retired_verifier = JwksVerifier(
        fetch,
        status,
        issuer="https://auth.lab.invalid",
        audience="temis-lab",
        authorized_party="temis-web",
    )
    with pytest.raises(TokenRejected):
        await retired_verifier.authenticate(old_token)


def test_concurrent_process_publishers_do_not_lose_records(tmp_path: Path) -> None:
    code = (
        "import sys; from pathlib import Path; "
        "from temis_sso.keyring import KeyRing; KeyRing(Path(sys.argv[1])).publish()"
    )

    def publish(_: int) -> None:
        subprocess.run([sys.executable, "-c", code, str(tmp_path)], check=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(publish, range(8)))
    assert len(KeyRing(tmp_path).jwks()["keys"]) == 8
