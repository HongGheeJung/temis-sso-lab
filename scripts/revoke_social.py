"""Unlink your own recently authenticated provider account without shell token history."""
import argparse
import getpass

import httpx


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("provider", choices=("naver", "kakao"))
    args = parser.parse_args()
    token = getpass.getpass("Paste the APP access_token from the latest login (hidden): ").strip()
    if not token:
        parser.error("An application access_token is required")
    try:
        response = httpx.post(
            f"http://localhost:8000/oauth/{args.provider}/revoke",
            headers={"Authorization": f"Bearer {token}"},
            json={},
            timeout=20,
            trust_env=False,
        )
    except httpx.HTTPError:
        raise SystemExit("Cannot reach local server or request timed out. Check server logs.") from None
    print(f"HTTP {response.status_code}")
    if response.status_code == 204:
        print("Provider credential revoked and local identity link removed. User account retained.")
    else:
        print(response.text)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
