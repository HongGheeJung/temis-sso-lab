# TEMIS SSO Lab

An independent learning project for building a small FastAPI single sign-on
service. The code uses local-only defaults and contains no production data,
credentials, hosts, or source copied from an internal service.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
```

Step 1–2 tests run without infrastructure. From Step 3 onward, start the
loopback-only PostgreSQL and Redis services and apply the checked-in migration:

```bash
docker compose up -d --wait
alembic upgrade head
```

From Step 5 onward, generate the persistent local signing identity once:

```bash
python -m temis_sso.keygen
pytest -q
uvicorn temis_sso.main:app --reload
```

The generated `var/keys` directory is local state and must not be committed.
