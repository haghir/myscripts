# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Subcommand dispatch for `python3 -m myenc`."""

import sys

SUBCOMMANDS = {"encred", "decred", "hashpass"}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if not argv or argv[0] not in SUBCOMMANDS:
        print(f"usage: python3 -m myenc {{{','.join(sorted(SUBCOMMANDS))}}} ...", file=sys.stderr)
        return 2

    command, rest = argv[0], argv[1:]
    if command == "encred":
        from myenc import encred

        return encred.main(rest)
    if command == "decred":
        from myenc import decred

        return decred.main(rest)
    if command == "hashpass":
        from myenc import hashpass

        return hashpass.main(rest)
    raise AssertionError(f"unhandled subcommand: {command}")


if __name__ == "__main__":
    sys.exit(main())
