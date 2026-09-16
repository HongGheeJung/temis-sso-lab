import subprocess
import sys
from pathlib import Path


def pytest_sessionstart() -> None:
    subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"], check=True)
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from redis import Redis; Redis(host='127.0.0.1', port=56389).flushdb()",
        ],
        check=True,
    )
    private_key = Path("var/keys/access-private.pem")
    public_key = Path("var/keys/access-public.pem")
    if not private_key.exists() or not public_key.exists():
        subprocess.run([sys.executable, "-m", "temis_sso.keygen"], check=True)
