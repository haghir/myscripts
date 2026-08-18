# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Derive a bcrypt password hash from a passphrase.

Prompts for a password (with confirmation) unless one is supplied via
-p/--passphrase, and prints the resulting bcrypt hash string. The salt and
cost factor are embedded in that string, so it alone (passed to `myenc
encred --hash`) is enough to verify the password later.
"""

import argparse
import getpass
import sys

from myenc import _bcrypt as bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def read_password(supplied: str | None) -> str:
    if supplied is not None:
        return supplied
    while True:
        first = getpass.getpass("Password: ")
        second = getpass.getpass("Verify: ")
        if first == second:
            return first
        print("Passwords did not match, try again.", file=sys.stderr)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="myenc hashpass",
        description="Derive a bcrypt password hash from a passphrase.",
    )
    parser.add_argument("-p", "--passphrase", metavar="PASSPHRASE", help="password (default: prompt and confirm)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    password = read_password(args.passphrase)

    print(hash_password(password))
    return 0
