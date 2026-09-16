#!/usr/bin/env bash
set -euo pipefail
: "${ARCHIVE:?set the archive path}"
: "${RESTORE_LIBPQ_URL:?set an isolated libpq restore URL}"
: "${RESTORE_ASYNC_DATABASE_URL:?set the matching async SQLAlchemy URL}"
: "${EXPECTED_RESTORE_DATABASE:?set the exact isolated database name}"
if [[ -n "${PRODUCTION_LIBPQ_URL:-}" && "$RESTORE_LIBPQ_URL" == "$PRODUCTION_LIBPQ_URL" ]]; then
  echo "refusing to restore into the production libpq URL" >&2
  exit 2
fi
if [[ -n "${PRODUCTION_ASYNC_DATABASE_URL:-}" && "$RESTORE_ASYNC_DATABASE_URL" == "$PRODUCTION_ASYNC_DATABASE_URL" ]]; then
  echo "refusing to restore into the production async URL" >&2
  exit 2
fi
export TEMIS_LAB_DATABASE_URL="$RESTORE_ASYNC_DATABASE_URL"
python_bin="${PYTHON_BIN:-python3}"
sha256sum --check "$ARCHIVE.sha256"
identity="$(psql "$RESTORE_LIBPQ_URL" -AtF '|' -c "select current_database(), to_regclass('public.temis_restore_target') is not null")"
if [[ "$identity" != "$EXPECTED_RESTORE_DATABASE|t" ]]; then
  echo "refusing to restore: target identity or isolated marker mismatch" >&2
  exit 3
fi
"$python_bin" scripts/verify-restore-target.py
pg_restore --exit-on-error --clean --if-exists --dbname "$RESTORE_LIBPQ_URL" "$ARCHIVE"
alembic upgrade head
pytest -q tests/test_system.py tests/test_auth_data.py
