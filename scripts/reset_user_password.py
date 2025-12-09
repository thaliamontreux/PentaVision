from __future__ import annotations

import argparse
import sys
from getpass import getpass

from argon2 import PasswordHasher
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.config import load_config
from app.models import User


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reset a user's password in the pe_users database by email.",
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Email address of the user whose password should be reset.",
    )
    parser.add_argument(
        "--password",
        help="New password value. If omitted, you will be prompted securely.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()

    email = args.email.strip().lower()
    if not email:
        print("Email is required.", file=sys.stderr)
        return 1

    password = args.password
    if not password:
        pw1 = getpass("New password: ")
        pw2 = getpass("Confirm password: ")
        if not pw1:
            print("Password cannot be empty.", file=sys.stderr)
            return 1
        if pw1 != pw2:
            print("Passwords do not match.", file=sys.stderr)
            return 1
        password = pw1

    config = load_config()
    url = config.get("USER_DB_URL") or ""
    if not url:
        print("USER_DB_URL is not configured.", file=sys.stderr)
        return 1

    try:
        engine = create_engine(url, future=True)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to create engine: {exc}", file=sys.stderr)
        return 1

    ph = PasswordHasher()
    try:
        new_hash = ph.hash(password)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to hash password: {exc}", file=sys.stderr)
        return 1

    with Session(engine) as session:
        user = session.query(User).filter(User.email == email).first()
        if user is None:
            print(f"No user found with email: {email}", file=sys.stderr)
            return 1

        user.password_hash = new_hash
        user.failed_logins = 0
        user.locked_until = None
        session.add(user)
        session.commit()

    print(f"Password updated for {email}.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
