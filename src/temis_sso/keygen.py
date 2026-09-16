import argparse
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_key_pair(private_path: Path, public_path: Path, force: bool = False) -> None:
    if not force and (private_path.exists() or public_path.exists()):
        raise FileExistsError("key file already exists; refuse to replace signing identity")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate persistent lab JWT signing keys")
    parser.add_argument("--private", type=Path, default=Path("var/keys/access-private.pem"))
    parser.add_argument("--public", type=Path, default=Path("var/keys/access-public.pem"))
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    generate_key_pair(args.private, args.public, args.force)


if __name__ == "__main__":
    main()
