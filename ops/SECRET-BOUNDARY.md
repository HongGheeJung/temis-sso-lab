# Secret boundary

The loopback-only Compose file uses PostgreSQL trust authentication for a disposable learning host. It is not a production credential pattern.

In a deployed environment, inject database passwords, Redis credentials, OAuth client secrets, and private signing keys from the platform secret store. Mount each value as a read-only file, grant it only to the service that consumes it, and never bake it into an image, archive, log, source file, or browser response. Public keys and JWKS are not secrets.

The BFF may read OAuth client credentials and session encryption material. The Resource API receives only public JWKS material. The SSO signer alone reads private signing keys.
