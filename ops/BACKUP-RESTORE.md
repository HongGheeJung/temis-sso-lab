# PostgreSQL backup and isolated restore drill

Create a custom-format archive with `pg_dump --format=custom --file "$archive" "$LAB_DATABASE_URL"`, then create its checksum with `sha256sum "$archive" > "$archive.sha256"`.

For a drill, provision a new empty database that is not used by any service and create an explicit `public.temis_restore_target` marker table. Set `RESTORE_LIBPQ_URL` for `psql`/`pg_restore`, the matching `RESTORE_ASYNC_DATABASE_URL` for Alembic and application tests, and the exact `EXPECTED_RESTORE_DATABASE` name. The restore script verifies the checksum, queries the live database identity and marker through both drivers, and only then permits `pg_restore --clean`.

Record row counts, migration revision, checksum, start/end timestamps, and the operator. Destroy the drill database after evidence is retained. A backup is not accepted until this restore succeeds.
