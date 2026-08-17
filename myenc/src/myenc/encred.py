# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Encrypt a file or stdin into an ASCII-armored, passphrase-protected OpenPGP
message (RFC 9580), using AES-256 in GCM mode.

Only the "cryptography" package's AES-GCM and HKDF primitives are used; all
OpenPGP packet framing, ASCII armor, string-to-key handling, and chunked-AEAD
construction are implemented here rather than via a PGP/GnuPG library.

Output structure, per RFC 9580:
  - a version 6 Symmetric-Key Encrypted Session Key packet (Section 5.3.2),
  - a version 2 Symmetrically Encrypted Integrity Protected Data packet
    (Section 5.13.2) using the GCM AEAD mode, wrapping a single Literal Data
    packet (Section 5.9) that carries the input bytes.

The input is streamed through in fixed-size pieces (S2K hashing works on a
tiny fixed buffer; plaintext is AEAD-encrypted in bounded chunks; packet and
armor framing use bounded write buffers) so encrypting a large file never
requires holding the whole thing in memory.
"""

import argparse
import contextlib
import getpass
import hashlib
import os
import struct
import sys
from base64 import b64encode

import bcrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# --- OpenPGP registry constants used (RFC 9580 Section 9) ---
SYM_ALGO_AES256 = 9
AEAD_ALGO_GCM = 3
GCM_NONCE_LEN = 12
S2K_TYPE_ITERATED_SALTED = 3
S2K_HASH_SHA256 = 8

TAG_SKESK = 3
TAG_LITERAL = 11
TAG_SEIPD = 18

# AEAD plaintext chunk size: 1 << (CHUNK_SIZE_OCTET + 6) = 1 MiB (RFC 9580
# Section 5.13.2 caps this octet at 16, i.e. a 4 MiB maximum).
CHUNK_SIZE_OCTET = 14
CHUNK_SIZE = 1 << (CHUNK_SIZE_OCTET + 6)

# Packet-framing buffer for streamed (Partial Body Length) packets: 64 KiB.
PARTIAL_LENGTH_OCTET = 16
PARTIAL_LENGTH_SIZE = 1 << PARTIAL_LENGTH_OCTET

# Base64 armor: 48 input bytes -> 64 output characters per line, the
# conventional OpenPGP armor width (RFC 9580 allows up to 76).
ARMOR_LINE_BYTES = 48

READ_BUFSIZE = 65536

# Iterated & Salted S2K work factor: total octets hashed. ~8 MiB is in the
# same ballpark as GnuPG's own default and takes well under a second.
S2K_TARGET_OCTETS = 8 << 20


def encode_length(n: int) -> bytes:
    """RFC 9580 Section 4.2.1: a non-partial Body Length header for n octets."""
    if n < 192:
        return bytes([n])
    if n < 8384:
        n -= 192
        return bytes([(n >> 8) + 192, n & 0xFF])
    return b"\xff" + struct.pack(">I", n)


def s2k_decode_count(c: int) -> int:
    return (16 + (c & 15)) << ((c >> 4) + 6)


def s2k_encode_count(target: int) -> int:
    for c in range(256):
        if s2k_decode_count(c) >= target:
            return c
    return 255


def s2k_iterated_salted(passphrase: bytes, salt: bytes, count: int, key_len: int) -> bytes:
    """RFC 9580 Section 3.7.1.3."""
    data = salt + passphrase
    count = max(count, len(data))
    out = bytearray()
    preload = 0
    while len(out) < key_len:
        h = hashlib.sha256()
        h.update(b"\x00" * preload)
        remaining = count
        while remaining > 0:
            take = min(remaining, len(data))
            h.update(data[:take])
            remaining -= take
        out += h.digest()
        preload += 1
    return bytes(out[:key_len])


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


class PartialLengthWriter:
    """Streams an OpenPGP packet body to `sink` using Partial Body Length
    framing (RFC 9580 Section 4.2.1.4) so the body never has to be buffered
    in full: at most PARTIAL_LENGTH_SIZE octets are held at a time.
    """

    def __init__(self, tag: int, sink):
        self._ctb = bytes([0xC0 | tag])
        self._sink = sink
        self._buf = bytearray()
        self._header_written = False

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= PARTIAL_LENGTH_SIZE:
            if not self._header_written:
                self._sink.write(self._ctb)
                self._header_written = True
            self._sink.write(bytes([0xE0 | PARTIAL_LENGTH_OCTET]))
            self._sink.write(bytes(self._buf[:PARTIAL_LENGTH_SIZE]))
            del self._buf[:PARTIAL_LENGTH_SIZE]

    def close(self) -> None:
        if not self._header_written:
            self._sink.write(self._ctb)
        self._sink.write(encode_length(len(self._buf)))
        self._sink.write(bytes(self._buf))
        self._buf.clear()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class AeadChunkEncryptor:
    """Encrypts a plaintext byte stream as the chunked-AEAD body of a v2
    SEIPD packet (RFC 9580 Section 5.13.2): fixed-size plaintext chunks each
    followed by their tag, then a final empty-plaintext authentication tag
    covering the total octet count. At most CHUNK_SIZE plaintext octets are
    buffered at a time.
    """

    def __init__(self, message_key: bytes, iv_prefix: bytes, ad: bytes, sink):
        self._aesgcm = AESGCM(message_key)
        self._iv_prefix = iv_prefix
        self._ad = ad
        self._sink = sink
        self._buf = bytearray()
        self._chunk_index = 0
        self._total_octets = 0

    def _nonce(self, index: int) -> bytes:
        return self._iv_prefix + index.to_bytes(8, "big")

    def _emit_chunk(self, plaintext: bytes) -> None:
        ciphertext = self._aesgcm.encrypt(self._nonce(self._chunk_index), plaintext, self._ad)
        self._sink.write(ciphertext)
        self._chunk_index += 1

    def write(self, data: bytes) -> None:
        self._total_octets += len(data)
        self._buf += data
        while len(self._buf) >= CHUNK_SIZE:
            self._emit_chunk(bytes(self._buf[:CHUNK_SIZE]))
            del self._buf[:CHUNK_SIZE]

    def close(self) -> None:
        if self._buf or self._chunk_index == 0:
            self._emit_chunk(bytes(self._buf))
        self._buf.clear()
        final_ad = self._ad + self._total_octets.to_bytes(8, "big")
        final_tag = self._aesgcm.encrypt(self._nonce(self._chunk_index), b"", final_ad)
        self._sink.write(final_tag)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class ArmorWriter:
    """Wraps raw OpenPGP packet bytes in ASCII Armor (RFC 9580 Section 6),
    streaming base64 in bounded-size lines. No CRC24 footer is emitted: an
    armored message ending in a v2 SEIPD packet MUST NOT carry one.
    """

    def __init__(self, out):
        self._out = out
        self._buf = bytearray()

    def write(self, data: bytes) -> None:
        self._buf += data
        while len(self._buf) >= ARMOR_LINE_BYTES:
            line = bytes(self._buf[:ARMOR_LINE_BYTES])
            del self._buf[:ARMOR_LINE_BYTES]
            self._out.write(b64encode(line).decode("ascii"))
            self._out.write("\n")

    def close(self) -> None:
        if self._buf:
            self._out.write(b64encode(bytes(self._buf)).decode("ascii"))
            self._out.write("\n")

    def __enter__(self):
        self._out.write("-----BEGIN PGP MESSAGE-----\n\n")
        return self

    def __exit__(self, *exc):
        self.close()
        self._out.write("-----END PGP MESSAGE-----\n")


def build_skesk_packet(passphrase: bytes) -> tuple[bytes, bytes]:
    """RFC 9580 Section 5.3.2. Returns (packet_bytes, session_key)."""
    s2k_salt = os.urandom(8)
    count_enc = s2k_encode_count(S2K_TARGET_OCTETS)
    s2k_key = s2k_iterated_salted(passphrase, s2k_salt, s2k_decode_count(count_enc), 32)

    ad = bytes([0xC0 | TAG_SKESK, 6, SYM_ALGO_AES256, AEAD_ALGO_GCM])
    kek = hkdf_sha256(s2k_key, None, ad, 32)

    session_key = os.urandom(32)
    skesk_iv = os.urandom(GCM_NONCE_LEN)
    wrapped_key = AESGCM(kek).encrypt(skesk_iv, session_key, ad)

    s2k_specifier = bytes([S2K_TYPE_ITERATED_SALTED, S2K_HASH_SHA256]) + s2k_salt + bytes([count_enc])
    fields = bytes([SYM_ALGO_AES256, AEAD_ALGO_GCM, len(s2k_specifier)]) + s2k_specifier + skesk_iv
    body = bytes([6, len(fields)]) + fields + wrapped_key

    packet = bytes([0xC0 | TAG_SKESK]) + encode_length(len(body)) + body
    return packet, session_key


def encrypt(input_stream, output_stream, passphrase: bytes) -> None:
    skesk_packet, session_key = build_skesk_packet(passphrase)

    with ArmorWriter(output_stream) as armor:
        armor.write(skesk_packet)

        with PartialLengthWriter(TAG_SEIPD, armor) as seipd:
            seipd_salt = os.urandom(32)
            info = bytes([0xC0 | TAG_SEIPD, 2, SYM_ALGO_AES256, AEAD_ALGO_GCM, CHUNK_SIZE_OCTET])
            seipd.write(bytes([2, SYM_ALGO_AES256, AEAD_ALGO_GCM, CHUNK_SIZE_OCTET]) + seipd_salt)

            derived = hkdf_sha256(session_key, seipd_salt, info, 32 + GCM_NONCE_LEN - 8)
            message_key, iv_prefix = derived[:32], derived[32:]

            with AeadChunkEncryptor(message_key, iv_prefix, info, seipd) as aead:
                with PartialLengthWriter(TAG_LITERAL, aead) as literal:
                    literal.write(bytes([0x62, 0, 0, 0, 0, 0]))  # 'b', no filename, no timestamp
                    while True:
                        block = input_stream.read(READ_BUFSIZE)
                        if not block:
                            break
                        literal.write(block)


def read_passphrase(supplied: str | None, bcrypt_hash: str | None) -> bytes:
    """If `bcrypt_hash` (as printed by `myenc hashpass`) is given, the
    passphrase only needs to be entered once: it's checked against the hash
    instead of a second, confirmation entry.
    """
    if bcrypt_hash is not None:
        passphrase = supplied if supplied is not None else getpass.getpass("Passphrase: ")
        if not bcrypt.checkpw(passphrase.encode("utf-8"), bcrypt_hash.encode("ascii")):
            raise ValueError("passphrase does not match the given hash")
        return passphrase.encode("utf-8")
    if supplied is not None:
        return supplied.encode("utf-8")
    while True:
        first = getpass.getpass("Passphrase: ")
        second = getpass.getpass("Confirm passphrase: ")
        if first == second:
            return first.encode("utf-8")
        print("Passphrases did not match, try again.", file=sys.stderr)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="myenc encred",
        description="Encrypt a file or stdin as an ASCII-armored, AES-256-GCM OpenPGP symmetric message.",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="output file path (default: stdout)")
    parser.add_argument("-p", "--passphrase", metavar="PASSPHRASE", help="passphrase (default: prompt and confirm)")
    parser.add_argument(
        "--hash",
        metavar="BCRYPT_HASH",
        help="bcrypt hash from `myenc hashpass` output; verifies the passphrase without a second prompt",
    )
    parser.add_argument("input", nargs="?", metavar="FILE", help="input file path (default: stdin)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        passphrase = read_passphrase(args.passphrase, args.hash)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    in_ctx = open(args.input, "rb") if args.input else contextlib.nullcontext(sys.stdin.buffer)
    out_ctx = (
        open(args.output, "w", encoding="ascii", newline="\n")
        if args.output
        else contextlib.nullcontext(sys.stdout)
    )
    with in_ctx as infile, out_ctx as outfile:
        encrypt(infile, outfile, passphrase)
    return 0
