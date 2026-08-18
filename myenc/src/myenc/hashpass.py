# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Derive a bcrypt password hash from a passphrase.

Takes the password via -p/--passphrase and prints the resulting bcrypt hash
string. The salt and cost factor are embedded in that string, so it alone
(passed to `myenc encred --hash`) is enough to verify the password later.

This module does not prompt for the password itself -- entering it (and, if
desired, confirming it) is the caller's job, e.g. via the bash `read`
builtin in `bin/bash/hashpass`. That's because `getpass`'s TTY-based prompt
doesn't work in every environment this is run from (e.g. a-Shell on iOS,
which has no real TTY), whereas a shell wrapper's own `read -s` is portable
to anywhere the wrapper itself runs.
"""

import argparse

from myenc import _bcrypt as bcrypt


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="myenc hashpass",
        description="Derive a bcrypt password hash from a passphrase.",
    )
    parser.add_argument("-p", "--passphrase", required=True, metavar="PASSPHRASE", help="password to hash")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    print(hash_password(args.passphrase))
    return 0
