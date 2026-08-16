# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Derive a salted SHA-256 password hash from a passphrase.

Prompts for a password (with confirmation) unless one is supplied via
-p/--passphrase, generates a fresh random salt, and prints
`salt:hexdigest` so the hash can be reproduced later given the printed
salt and the original password.
"""

import argparse
import getpass
import hashlib
import secrets
import sys

SALT_BYTES = 16  # -> 32 random hex characters


def hash_password(password: str, salt: str) -> str:
    return hashlib.sha256(f"{salt}{password}".encode("utf-8")).hexdigest()


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
        description="Derive a salted SHA-256 password hash from a passphrase.",
    )
    parser.add_argument("-p", "--passphrase", metavar="PASSPHRASE", help="password (default: prompt and confirm)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    password = read_password(args.passphrase)

    salt = secrets.token_hex(SALT_BYTES)
    digest = hash_password(password, salt)

    print(f"{salt}:{digest}")
    return 0
