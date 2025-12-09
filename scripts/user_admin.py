from __future__ import annotations

import argparse
import sys
from getpass import getpass
from typing import Optional

from argon2 import PasswordHasher
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import load_config
from app.models import User


def _load_engine():
    config = load_config()
    url = config.get("USER_DB_URL") or ""
    if not url:
        print("USER_DB_URL is not configured.", file=sys.stderr)
        raise SystemExit(1)
    try:
        return create_engine(url, future=True)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to create engine: {exc}", file=sys.stderr)
        raise SystemExit(1)


def _select_user(session: Session, email: Optional[str] = None) -> Optional[User]:
    if not email:
        email = input("User email: ").strip().lower()
    if not email:
        print("Email is required.")
        return None
    user = session.query(User).filter(User.email == email).first()
    if user is None:
        print(f"No user found with email: {email}")
    return user


def action_list_users(engine) -> None:
    with Session(engine) as session:
        users = session.query(User).order_by(User.email).limit(200).all()
        if not users:
            print("No users found.")
            return
        print("\nUsers (up to 200):")
        print("=" * 72)
        for u in users:
            status = getattr(u, "account_status", None) or ""
            print(f"{u.id:4d}  {u.email:40s}  status={status}")
        print("=" * 72)


def action_create_user(engine) -> None:
    with Session(engine) as session:
        email = input("New user email: ").strip().lower()
        if not email:
            print("Email is required.")
            return
        existing = session.query(User).filter(User.email == email).first()
        if existing is not None:
            print("A user with that email already exists.")
            return

        pw1 = getpass("Password: ")
        pw2 = getpass("Confirm password: ")
        if not pw1:
            print("Password cannot be empty.")
            return
        if pw1 != pw2:
            print("Passwords do not match.")
            return

        ph = PasswordHasher()
        try:
            password_hash = ph.hash(pw1)
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to hash password: {exc}")
            return

        user = User(email=email, password_hash=password_hash)
        session.add(user)
        try:
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to create user: {exc}")
            return

        print(f"Created user {email} with id={user.id}.")


def action_reset_password(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        pw1 = getpass("New password: ")
        pw2 = getpass("Confirm password: ")
        if not pw1:
            print("Password cannot be empty.")
            return
        if pw1 != pw2:
            print("Passwords do not match.")
            return

        ph = PasswordHasher()
        try:
            new_hash = ph.hash(pw1)
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to hash password: {exc}")
            return

        user.password_hash = new_hash
        user.failed_logins = 0
        user.locked_until = None
        session.add(user)
        try:
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to update password: {exc}")
            return

        print(f"Password updated for {user.email}.")


def action_update_status(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        current = getattr(user, "account_status", None) or ""
        print(f"Current status for {user.email}: '{current}'")
        print("Enter new status (e.g. active, disabled, locked) or leave blank to clear.")
        new_status = input("New status: ").strip()
        user.account_status = new_status or None
        session.add(user)
        try:
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to update status: {exc}")
            return

        print(f"Updated account_status for {user.email} to '{user.account_status or ''}'.")


def action_delete_user(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        print(f"You are about to DELETE user {user.email} (id={user.id}).")
        confirm = input("Type the email to confirm, or anything else to cancel: ").strip().lower()
        if confirm != (user.email or "").lower():
            print("Cancelled.")
            return

        try:
            session.delete(user)
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to delete user: {exc}")
            return

        print(f"Deleted user {user.email}.")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ANSI-style user admin CLI")
    parser.parse_args(argv)  # currently no CLI flags; reserved for future use

    engine = _load_engine()

    while True:
        print("\n=== PentaVision User Admin ===")
        print("1) List users")
        print("2) Create new user")
        print("3) Reset user password")
        print("4) Update user account status")
        print("5) Delete user")
        print("q) Quit")
        choice = input("> ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            break
        elif choice == "1":
            action_list_users(engine)
        elif choice == "2":
            action_create_user(engine)
        elif choice == "3":
            action_reset_password(engine)
        elif choice == "4":
            action_update_status(engine)
        elif choice == "5":
            action_delete_user(engine)
        else:
            print("Unknown option. Please choose 1-5 or q to quit.")

    print("Goodbye.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
