#!/usr/bin/env bash
set -euo pipefail
: "${LAB_DATABASE_URL:?set the source database URL}"
: "${OUTPUT_DIR:?set a protected backup directory}"
mkdir -p "$OUTPUT_DIR"
archive="$OUTPUT_DIR/temis-sso-$(date -u +%Y%m%dT%H%M%SZ).dump"
pg_dump --format=custom --file "$archive" "$LAB_DATABASE_URL"
sha256sum "$archive" > "$archive.sha256"
echo "$archive"
