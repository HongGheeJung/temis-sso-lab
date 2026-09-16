# Expand and contract migration

1. Back up and checksum the database.
2. Apply revision `0002_expand_authz_version`; old and new application versions can both run.
3. Deploy writers, backfill rows in bounded batches, then deploy readers.
4. Verify no null values and exercise login, refresh, role change, and Resource API checks.
5. Apply revision `0003_contract_authz_version` only after every running version reads the new column.
6. Roll back the application before the schema while both versions remain compatible.

Never combine destructive contraction with the first application deployment.
