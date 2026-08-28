"""Admin CLI — Operational utilities for Bulwark Gateway admin portal.

Usage:
    python -m admin reset-password <username>     Reset password and force change on next login
    python -m admin list-users                    List all users and their status
    python -m admin force-change <username>       Set force_password_change flag without resetting password
"""
from __future__ import annotations

import os
import sys


def _init_store():
    """Initialize store (skip debug check for CLI operations)."""
    os.environ.setdefault("ADMIN_DEBUG", "true")
    from .services.user_store import UserStore
    store = UserStore()
    store.initialize()
    return store


def cmd_reset_password(username: str):
    """Reset user password to a random value and set force_password_change."""
    import secrets
    import string
    store = _init_store()

    user = store.get_user(username)
    if not user:
        print(f"ERROR: User '{username}' not found")
        sys.exit(1)

    # Generate strong random password (meets all complexity requirements)
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        temp_password = ''.join(secrets.choice(alphabet) for _ in range(20))
        # Verify it meets complexity (has upper, lower, digit, special)
        if (any(c.isupper() for c in temp_password) and
            any(c.islower() for c in temp_password) and
            any(c.isdigit() for c in temp_password) and
            any(c in "!@#$%^&*" for c in temp_password)):
            break

    store.change_password(user["id"], temp_password)
    # Re-set force_password_change (change_password clears it)
    store._conn.execute(
        "UPDATE users SET force_password_change = 1 WHERE id = ?", (user["id"],)
    )
    store._conn.commit()

    print(f"Password reset for user '{username}'")
    print(f"Temporary password: {temp_password}")
    print("User must change password on next login.")


def cmd_list_users():
    """List all users."""
    store = _init_store()
    users = store.list_users()
    if not users:
        print("No users found.")
        return

    print(f"{'Username':<15} {'Role':<10} {'Active':<7} {'Force Change':<13} {'Last Login'}")
    print("-" * 70)
    for u in users:
        print(f"{u['username']:<15} {u['role']:<10} {'Yes' if u['active'] else 'No':<7} "
              f"{'Yes' if u.get('force_password_change') else 'No':<13} "
              f"{u.get('last_login', 'never') or 'never'}")


def cmd_force_change(username: str):
    """Set force_password_change flag for user."""
    store = _init_store()
    user = store.get_user(username)
    if not user:
        print(f"ERROR: User '{username}' not found")
        sys.exit(1)

    store._conn.execute(
        "UPDATE users SET force_password_change = 1 WHERE id = ?", (user["id"],)
    )
    store._conn.commit()
    print(f"User '{username}' will be required to change password on next login.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "reset-password":
        if len(sys.argv) < 3:
            print("Usage: python -m admin reset-password <username>")
            sys.exit(1)
        cmd_reset_password(sys.argv[2])
    elif cmd == "list-users":
        cmd_list_users()
    elif cmd == "force-change":
        if len(sys.argv) < 3:
            print("Usage: python -m admin force-change <username>")
            sys.exit(1)
        cmd_force_change(sys.argv[2])
    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
