# myenc

A hatchling-packaged Python module, `myenc`, implementing OpenPGP-based
encryption tools from scratch, without any PGP/OpenPGP library. Subcommands
live under `src/myenc/` and are invoked as `python3 -m myenc <subcommand>
...`, dispatched by `src/myenc/__main__.py`. `encred`, `decred`, and
`hashpass` exist so far.

To add a new subcommand: create `src/myenc/<name>.py` with `parse_args`
and `main(argv=None) -> int` functions (see `encred.py`/`decred.py` for the
shape), then add `"<name>"` to `SUBCOMMANDS` in `src/myenc/__main__.py` and
a matching dispatch branch.

## encred

Usage: `python3 -m myenc encred -p <passphrase> [-o <output file>]
[--hash <bcrypt hash>] [<input file>]`. Implemented in
`src/myenc/encred.py`.

Encrypts a file or stdin to an ASCII-armored OpenPGP symmetric message,
AES-256-GCM, per **RFC 9580** (the finalized "crypto-refresh" spec, not the
older RFC 4880 / draft-bis format). Wire format: a v6 Symmetric-Key
Encrypted Session Key packet (Iterated & Salted S2K) wrapping a random
session key, then a v2 SEIPD packet (chunked AES-256-GCM) containing a
Literal Data packet with the payload. Dependencies: `cryptography`, used
solely for the AES-GCM and HKDF primitives — all packet framing, S2K, and
armor logic is hand-rolled against the RFC text. Password hashing for the
optional `--hash` check below uses `src/myenc/_bcrypt.py`, a from-scratch,
pure-Python bcrypt (no compiled dependency — see that module's docstring),
not the `bcrypt` PyPI package.

`--hash` takes a bcrypt hash string as printed by `myenc hashpass`; if
given, `-p`'s passphrase is checked with `_bcrypt.checkpw` against that hash
before encrypting — this is what lets `bin/bash/encred` hard-code a
known-good hash of the intended passphrase and abort on a typo, rather than
silently encrypting under the wrong key. This replaced an earlier
`--salt`/`--digest` pair (`sha256(salt + password)`, matching `hashpass`'s
old salted-SHA-256 scheme) with a single `--hash` once both `encred` and
`hashpass` moved to bcrypt.

`-p/--passphrase` is required and `encred`/`decred`/`hashpass` never prompt
for it themselves (no `getpass` calls anywhere in `src/myenc/`): `getpass`
needs a real TTY, which isn't available in every environment these run
from — notably a-Shell on iOS. Interactive entry (and, for `hashpass`,
confirming it twice) is instead the job of the `bin/bash/*` wrapper scripts,
via bash's own `read -s`, which doesn't depend on a TTY the way `getpass`
does.

## hashpass

Usage: `python3 -m myenc hashpass -p <passphrase>`. Implemented in
`src/myenc/hashpass.py`.

Derives a bcrypt password hash (`_bcrypt.hashpw` with a freshly random
`_bcrypt.gensalt()` salt on every run) and prints the resulting hash
string. Unlike the original `bin/hashpass` shell script (fixed
`SALT1`/`SALT2` constants, so the same password always hashed the same
way) and this tool's earlier salted-SHA-256 implementation (which printed
`salt:hexdigest`, since the salt had to be tracked separately), bcrypt
embeds the salt and cost factor directly in the hash string, so that
string alone — passed to `myenc encred --hash` — is enough to verify the
password later.

### `_bcrypt.py`: pure-Python bcrypt

`src/myenc/_bcrypt.py` implements bcrypt (Provos & Mazières'
EksBlowfish-based scheme) from scratch — Blowfish cipher, its pi-digit
P-array/S-box constants, the expensive salt-dependent key schedule, and
bcrypt's own no-padding base64 variant — with no compiled dependency, so
`encred`/`hashpass` keep working in environments where the `bcrypt`
package can't be installed. It exposes the same `gensalt`/`hashpw`/
`checkpw` names as the `bcrypt` package, so the call sites in
`encred.py`/`hashpass.py` are otherwise unchanged (`from myenc import
_bcrypt as bcrypt`).

Being pure Python, it's far slower than a compiled bcrypt: several seconds
per hash at the default cost factor (12) rather than tens of milliseconds.
That's an accepted trade here, since both call sites hash/check a
passphrase interactively, a handful of times per run — not in a
high-throughput auth path.

Validated (not merely trusted) by cross-checking against the real
`bcrypt` package installed in a scratch environment for one-time
comparison only, never added as a project dependency: hash equality
across empty/short/72-byte/unicode/embedded-NUL passwords and multiple
cost factors, plus cross-verification in both directions (each
implementation's hash checked by the other's `checkpw`). If `_bcrypt.py`
is ever modified, re-validate the same way rather than trusting that a
self-consistent round trip (hash and check both via `_bcrypt.py`) proves
correctness — the real risk is drifting from the standard algorithm while
still agreeing with yourself, the same lesson as `decred`'s "check
against a third source" note below.

## decred

Usage: `python3 -m myenc decred -p <passphrase> [-o <output file>]
[<input file>]`. Implemented in `src/myenc/decred.py`; the inverse of
`encred`. Reuses `encred`'s S2K/HKDF helpers and constants via import
rather than reimplementing them (unlike the throwaway validation
decryptor described below, this is shipped code, so DRY applies
normally). Every layer (armor, a packet body possibly spread across
several Partial Body Length segments, the chunked-AEAD plaintext) is
modeled as a small class exposing a file-like `read(n)`, so the whole
pipeline streams: at most one armor line, one length-header segment, and
one AEAD chunk (plus a byte of lookahead, see below) are ever in memory
at once, regardless of message size.

### Gotchas learned while building this

- **The chunked-AEAD framing has no length prefix between segments** —
  telling the final tag-only segment (always exactly 16 octets) apart
  from an ordinary data chunk (`chunk_size + 16` octets, except a
  possibly-shorter last one) requires lookahead. The first attempt at
  `decred`'s `AeadChunkDecryptor` got this wrong by looking ahead a
  *whole segment* at a time (`read(chunk_size + 16)`): for any body
  shorter than one full chunk (i.e. most real files), that single read
  silently swallowed the last data chunk **and** the final tag together
  with no way to tell where one ended and the other began, corrupting
  every non-empty, non-multi-chunk message. The fix looks ahead **one
  octet** past a full chunk instead: if more than `chunk_size + 16`
  octets are available, the first `chunk_size + 16` must be an ordinary
  chunk (the final tag is always the very last thing in the body);
  otherwise whatever's left once the body is exhausted is `[optional
  last data chunk] + [final tag]`, and the final tag is unambiguously its
  trailing 16 octets. Caught by testing round trips at both small
  (well under one chunk) and chunk-boundary sizes — the segment-level
  version passed at exact multiples of `CHUNK_SIZE` (1 MiB) purely by
  chance, since there the ambiguous case never arose.

- **Local `gpg` cannot decrypt this output**, and that's not a bug in
  `encred`. The GnuPG on this machine (2.5.21, a pre-release dev build) only
  implements an older pre-final draft of OpenPGP AEAD: SKESK **v5** + a
  standalone tag-20 "AEAD Encrypted Data Packet", and it hardcodes OCB
  regardless of `--aead-algo GCM`/`--force-aead`. Tag 20 is `Reserved` in the
  final RFC 9580 (AEAD was folded into SEIPD v2 under tag 18 instead), so
  this gpg build simply doesn't recognize v6 SKESK / v2 SEIPD — confirmed via
  `gpg --list-packets`, which parses our packet tags/lengths correctly but
  reports "unknown version" for both. Don't assume a working local gpg round
  trip is available for regression-testing future changes here; a real
  RFC 9580–capable implementation may be needed, or fall back to the next
  point.
- **Other third-party tools reject this output too, for the same reason as
  `gpg` above** — it's not specific to that one dev build. E.g. the web tool
  lockedpgp.com (likely OpenPGP.js-based) fails with "Error parsing SKESK V6
  structure: Unsupported SKESK version 6." OpenPGP.js does implement RFC 9580
  AEAD, but gates it behind `config.aeadProtect`, off by default in many
  builds — and any implementation built before RFC 9580's 2024 finalization
  won't recognize v6 SKESK / v2 SEIPD at all. Before treating a "can't
  decrypt/parse" report from some other tool as an `encred`/`decred` bug,
  check the packet structure against the RFC text directly (as was done here
  for the SKESK v6 body/AD construction, section 5.3.2) rather than assuming
  the third-party tool's rejection is authoritative — AEAD-capable RFC 9580
  implementations are still the exception, not the rule, as of 2026.
- **How this was actually validated**: before `decred` existed, an
  independent decryptor was hand-written straight from the RFC text (not
  by importing/reusing `encred`'s code) to round-trip against `encred`'s
  output, precisely because self-consistency of one implementation proves
  nothing. Now that `decred` exists as the real decryptor, it plays that
  role for ordinary regression testing — but a wire-format *change* to
  both `encred` and `decred` together can still pass a round trip while
  being wrong per the RFC (both sides agreeing with each other, not with
  the spec), so for anything beyond routine changes, checking against a
  third source (a fresh from-the-RFC read, or a real RFC 9580 tool) is
  still worth doing rather than trusting the pair's self-consistency.
- **Regression-testing checklist** (`python3 -m myenc encred` /
  `python3 -m myenc decred` round trips, `cmp`/`diff` the result against
  the original): empty input; a small input well under one AEAD chunk;
  inputs at `CHUNK_SIZE` (1 MiB) ± 1 byte; an exact multiple of
  `CHUNK_SIZE` (tests the "no extra empty final chunk" edge case); a
  multi-chunk, non-boundary size (e.g. 2.5 MiB); a wrong passphrase
  (must fail cleanly, not decrypt); and a bit-flipped armor line (must be
  rejected, not silently produce corrupt output). This is the exact
  matrix that caught the lookahead bug above — the small-input and
  exact-multiple cases are the ones that actually distinguish a correct
  chunk boundary implementation from a subtly broken one.
- **Fetching RFC 9580 text**: `WebFetch` truncates this document — it
  consistently cuts off around section 5.2, regardless of which later
  section the prompt asks for, because the whole doc gets fed through a
  summarizer with a fixed budget before the prompt is applied. Instead:
  `curl -sL -o rfc9580.txt https://www.rfc-editor.org/rfc/rfc9580.txt`, then
  `grep -n` for the section heading and `Read` that line range directly.
  Relevant sections: 3.7 (S2K types), 5.3.2 (SKESK v6), 5.9 (Literal Data),
  5.13.2 (SEIPD v2 / chunked AEAD), 9.3/9.6 (algorithm ID tables), 6.2
  (ASCII armor — note it says CRC24 **must not** be emitted when the message
  ends in a v2 SEIPD packet).
- `encred` originally shipped as a bare, directly-executable script at the
  repo root, with the hatchling scaffold (`pyproject.toml`, `src/myenc/`,
  `tests/`) deleted in favor of that convention. It was later merged into
  the package as the `encred` subcommand — the crypto/packet-framing logic
  in `src/myenc/encred.py` is unchanged from the standalone script, only the
  entry point (`python3 -m myenc encred` via `__main__.py`) and the
  argparse `prog` string changed. `requires-python` was bumped to `>=3.10`
  because the module uses PEP 604 `X | None` annotations.
