from __future__ import annotations

import argparse
import subprocess
import sys
from getpass import getpass
from typing import Optional

from argon2 import PasswordHasher
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.config import load_config
from app.models import Role, User, UserRole


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


def action_list_user_roles(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        rows = (
            session.query(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .filter(UserRole.user_id == user.id, UserRole.property_id.is_(None))
            .order_by(Role.name)
            .all()
        )
        if not rows:
            print(f"User {user.email} has no global roles.")
            return
        print(f"\nGlobal roles for {user.email}:")
        for (name,) in rows:
            print(f" - {name}")


def action_grant_role(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        role_name = input(
            "Role name to grant (e.g. 'System Administrator', 'Technician'): "
        ).strip()
        if not role_name:
            print("Role name is required.")
            return

        role = session.query(Role).filter(Role.name == role_name).first()
        if role is None:
            ans = input(
                f"Role '{role_name}' does not exist. Create it? [y/N]: "
            ).strip().lower()
            if ans not in {"y", "yes"}:
                print("Cancelled.")
                return
            role = Role(name=role_name, scope="global", description=None)
            session.add(role)
            session.flush()

        existing = (
            session.query(UserRole)
            .filter(
                UserRole.user_id == user.id,
                UserRole.role_id == role.id,
                UserRole.property_id.is_(None),
            )
            .first()
        )
        if existing is not None:
            print(f"User {user.email} already has role '{role.name}'.")
            return

        session.add(UserRole(user_id=user.id, role_id=role.id, property_id=None))
        try:
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to grant role: {exc}")
            return

        print(f"Granted role '{role.name}' to {user.email}.")


def action_revoke_role(engine) -> None:
    with Session(engine) as session:
        user = _select_user(session)
        if user is None:
            return

        role_name = input(
            "Role name to revoke (e.g. 'System Administrator', 'Technician'): "
        ).strip()
        if not role_name:
            print("Role name is required.")
            return

        role = session.query(Role).filter(Role.name == role_name).first()
        if role is None:
            print(f"Role '{role_name}' does not exist.")
            return

        # Prevent removing the last System Administrator, mirroring web admin safety.
        if role.name == "System Administrator":
            admin_rows = (
                session.query(UserRole, Role)
                .join(Role, Role.id == UserRole.role_id)
                .filter(Role.name == "System Administrator")
                .all()
            )
            current_admin_ids = [ur.user_id for ur, _ in admin_rows]
            if len(current_admin_ids) <= 1 and user.id in current_admin_ids:
                print(
                    "Refusing to revoke 'System Administrator': this is the only admin."
                )
                return

        deleted = (
            session.query(UserRole)
            .filter(
                UserRole.user_id == user.id,
                UserRole.role_id == role.id,
                UserRole.property_id.is_(None),
            )
            .delete(synchronize_session=False)
        )
        if not deleted:
            print(f"User {user.email} does not currently have role '{role.name}'.")
            session.rollback()
            return

        try:
            session.commit()
        except SQLAlchemyError as exc:  # noqa: BLE001
            session.rollback()
            print(f"Failed to revoke role: {exc}")
            return

        print(f"Revoked role '{role.name}' from {user.email}.")


def _systemctl_unit(unit: str, operation: str) -> None:
    cmd = ["systemctl", operation, unit]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("systemctl not found; this CLI requires systemd.")
        return
    print("$ " + " ".join(cmd))
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip())
    print(f"(exit code {result.returncode})")


def action_manage_services(engine) -> None:  # engine is unused
    while True:
        print("\nPentaVision services:")
        print("1) Status (web and video)")
        print("2) Start pentavision-web")
        print("3) Stop pentavision-web")
        print("4) Restart pentavision-web")
        print("5) Start pentavision-video")
        print("6) Stop pentavision-video")
        print("7) Restart pentavision-video")
        print("q) Back to main menu")
        choice = input("> ").strip().lower()

        if choice in {"q", "quit", "exit", ""}:
            break
        elif choice == "1":
            _systemctl_unit("pentavision-web", "status")
            _systemctl_unit("pentavision-video", "status")
        elif choice == "2":
            _systemctl_unit("pentavision-web", "start")
        elif choice == "3":
            _systemctl_unit("pentavision-web", "stop")
        elif choice == "4":
            _systemctl_unit("pentavision-web", "restart")
        elif choice == "5":
            _systemctl_unit("pentavision-video", "start")
        elif choice == "6":
            _systemctl_unit("pentavision-video", "stop")
        elif choice == "7":
            _systemctl_unit("pentavision-video", "restart")
        else:
            print("Unknown option. Choose 1-7 or q.")


def _legacy_menu(engine) -> None:
    while True:
        print("\n=== PentaVision User Admin ===")
        print("1) List users")
        print("2) Create new user")
        print("3) Reset user password")
        print("4) Update user account status")
        print("5) Delete user")
        print("6) List a user's global roles")
        print("7) Grant a global role to a user")
        print("8) Revoke a global role from a user")
        print("9) Manage services (pentavision-web / pentavision-video)")
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
        elif choice == "6":
            action_list_user_roles(engine)
        elif choice == "7":
            action_grant_role(engine)
        elif choice == "8":
            action_revoke_role(engine)
        elif choice == "9":
            action_manage_services(engine)
        else:
            print("Unknown option. Please choose 1-9 or q to quit.")
    print("Goodbye.")


def _run_action_outside_curses(action, engine, stdscr) -> None:
    import curses

    curses.def_prog_mode()
    curses.endwin()
    try:
        action(engine)
        input("Press Enter to return to the menu...")
    finally:
        curses.reset_prog_mode()
        stdscr.refresh()


def _tui_main(stdscr, engine) -> None:
    import curses

    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    items = [
        ("List users", action_list_users),
        ("Create new user", action_create_user),
        ("Reset user password", action_reset_password),
        ("Update user account status", action_update_status),
        ("Delete user", action_delete_user),
        ("List a user's global roles", action_list_user_roles),
        ("Grant a global role to a user", action_grant_role),
        ("Revoke a global role from a user", action_revoke_role),
        ("Manage services (web / video)", action_manage_services),
        ("Quit", None),
    ]

    index = 0
    while True:
        stdscr.erase()
        stdscr.addstr(0, 0, "PentaVision Admin CLI")
        stdscr.addstr(1, 0, "Use arrow keys (or j/k) to move, Enter to select, q to quit.")
        for i, (label, _) in enumerate(items):
            prefix = "\033[7m> " if i == index else "  "
            suffix = "\033[0m" if i == index else ""
            stdscr.addstr(3 + i, 0, prefix + label + suffix)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord("q"), 27):
            break
        if ch in (curses.KEY_UP, ord("k")):
            index = (index - 1) % len(items)
        elif ch in (curses.KEY_DOWN, ord("j")):
            index = (index + 1) % len(items)
        elif ch in (curses.KEY_ENTER, 10, 13):
            label, action = items[index]
            if action is None:
                break
            _run_action_outside_curses(action, engine, stdscr)


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ANSI-style user admin CLI")
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="use simple text menu instead of arrow-key interface",
    )
    args = parser.parse_args(argv)

    engine = _load_engine()

    use_tui = sys.stdout.isatty() and not args.no_tui
    if use_tui:
        try:
            import curses
        except Exception:
            _legacy_menu(engine)
        else:
            curses.wrapper(_tui_main, engine)
    else:
        _legacy_menu(engine)

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
