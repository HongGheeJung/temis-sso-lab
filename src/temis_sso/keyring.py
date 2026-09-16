import base64
import fcntl
import hashlib
import json
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey


class KeyRecord(TypedDict):
    kid: str
    state: str
    published_at: float
    activated_at: float | None
    retiring_at: float | None


def _b64url(value: int) -> str:
    size = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(size, "big")).rstrip(b"=").decode()


class KeyRing:
    MINIMUM_OVERLAP_SECONDS = 600 + 60 + 300

    def __init__(
        self,
        root: Path,
        *,
        clock: Callable[[], float] = time.time,
        overlap_seconds: float = 960,
    ) -> None:
        self.root = root
        self.metadata = root / "keyring.json"
        self.lock_file = root / ".keyring.lock"
        self.clock = clock
        if overlap_seconds < self.MINIMUM_OVERLAP_SECONDS:
            raise ValueError("overlap must cover access TTL, clock skew, and JWKS cache TTL")
        self.overlap_seconds = overlap_seconds

    @contextmanager
    def _locked(self) -> Iterator[None]:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with self.lock_file.open("a+") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _records(self) -> list[KeyRecord]:
        if not self.metadata.exists():
            return []
        return cast(list[KeyRecord], json.loads(self.metadata.read_text()))

    def _save(self, records: list[KeyRecord]) -> None:
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        with tempfile.NamedTemporaryFile(
            "w", dir=self.root, prefix="keyring-", delete=False
        ) as handle:
            handle.write(json.dumps(records, indent=2) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        os.replace(temporary, self.metadata)
        self.metadata.chmod(0o600)
        directory = os.open(self.root, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def active_kid(self) -> str:
        active = next((record for record in self._records() if record["state"] == "active"), None)
        if active is None:
            raise RuntimeError("no active signing key")
        return active["kid"]

    def publish(self) -> str:
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key()
        public_der = public.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        kid = hashlib.sha256(public_der).hexdigest()[:16]
        with self._locked():
            private_path = self.root / f"{kid}.private.pem"
            public_path = self.root / f"{kid}.public.pem"
            private_path.write_bytes(
                private.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            private_path.chmod(0o600)
            public_path.write_bytes(
                public.public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
            self._save(
                [
                    *self._records(),
                    {
                        "kid": kid,
                        "state": "published",
                        "published_at": self.clock(),
                        "activated_at": None,
                        "retiring_at": None,
                    },
                ]
            )
        return kid

    def activate(self, kid: str) -> None:
        with self._locked():
            records = self._records()
            target = next((record for record in records if record["kid"] == kid), None)
            if target is None or target["state"] != "published":
                raise ValueError("only a published key can be activated")
            now = self.clock()
            for record in records:
                if record["state"] == "active":
                    record["state"] = "retiring"
                    record["retiring_at"] = now
            target["state"] = "active"
            target["activated_at"] = now
            self._save(records)

    def retire(self, kid: str) -> None:
        with self._locked():
            records = self._records()
            target = next((record for record in records if record["kid"] == kid), None)
            if target is None or target["state"] != "retiring":
                raise ValueError("only a retiring key can be retired")
            retiring_at = target["retiring_at"]
            if retiring_at is None or self.clock() - retiring_at < self.overlap_seconds:
                raise ValueError("verification overlap has not elapsed")
            target["state"] = "retired"
            self._save(records)

    def sign_claims(self, claims: dict[str, object]) -> str:
        active = next((record for record in self._records() if record["state"] == "active"), None)
        if active is None:
            raise RuntimeError("no active signing key")
        loaded = serialization.load_pem_private_key(
            (self.root / f"{active['kid']}.private.pem").read_bytes(), password=None
        )
        if not isinstance(loaded, RSAPrivateKey):
            raise TypeError("signing key must be RSA")
        return jwt.encode(claims, loaded, algorithm="RS256", headers={"kid": active["kid"]})

    def sign(self, subject: str, issuer: str, audience: str) -> str:
        now = datetime.now(UTC)
        return self.sign_claims(
            {
                "sub": subject,
                "iss": issuer,
                "aud": audience,
                "iat": now,
                "exp": now + timedelta(minutes=10),
            }
        )

    def verification_key(self, kid: str) -> RSAPublicKey:
        record = next(
            (item for item in self._records() if item["kid"] == kid and item["state"] != "retired"),
            None,
        )
        if record is None:
            raise ValueError("verification key is not published")
        loaded = serialization.load_pem_public_key((self.root / f"{kid}.public.pem").read_bytes())
        if not isinstance(loaded, RSAPublicKey):
            raise TypeError("verification key must be RSA")
        return loaded

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        keys: list[dict[str, str]] = []
        for record in self._records():
            if record["state"] == "retired":
                continue
            loaded = serialization.load_pem_public_key(
                (self.root / f"{record['kid']}.public.pem").read_bytes()
            )
            if not isinstance(loaded, RSAPublicKey):
                raise TypeError("verification key must be RSA")
            numbers = loaded.public_numbers()
            keys.append(
                {
                    "kty": "RSA",
                    "use": "sig",
                    "alg": "RS256",
                    "kid": record["kid"],
                    "n": _b64url(numbers.n),
                    "e": _b64url(numbers.e),
                }
            )
        return {"keys": keys}
