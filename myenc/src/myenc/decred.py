# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""Decrypt an ASCII-armored, passphrase-protected OpenPGP symmetric message
(RFC 9580) produced by `encred`, using AES-256 in GCM mode.

This is the inverse of `myenc.encred`: it parses a v6 Symmetric-Key
Encrypted Session Key packet (Section 5.3.2) to recover the session key,
then a v2 Symmetrically Encrypted Integrity Protected Data packet
(Section 5.13.2) to recover a Literal Data packet (Section 5.9), whose
content is the original payload. Crypto primitives and constants are
shared with `myenc.encred` rather than re-implemented.

Every stream involved (the ASCII armor, an OpenPGP packet body possibly
spread across several Partial Body Length segments, and the chunked-AEAD
plaintext) is modeled as an object with a file-like `read(n)` method that
returns fewer than `n` bytes only at true end of stream. That lets the
layers compose without ever materializing more than one armor line, one
Partial Body Length segment, or one AEAD chunk (plus its one-chunk
lookahead) in memory at a time, regardless of overall message size.

The passphrase itself must be supplied via -p/--passphrase; this module
does not prompt for it, for the same reason `encred` doesn't -- see that
module's docstring.
"""

import argparse
import contextlib
import sys
from base64 import b64decode

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from myenc.encred import (
    AEAD_ALGO_GCM,
    GCM_NONCE_LEN,
    READ_BUFSIZE,
    S2K_HASH_SHA256,
    S2K_TYPE_ITERATED_SALTED,
    SYM_ALGO_AES256,
    TAG_LITERAL,
    TAG_SEIPD,
    TAG_SKESK,
    hkdf_sha256,
    s2k_decode_count,
    s2k_iterated_salted,
)

GCM_TAG_LEN = 16


def read_exact(reader, n: int) -> bytes:
    """Read exactly n bytes from a file-like `reader`, raising if the
    stream ends first."""
    buf = bytearray()
    while len(buf) < n:
        chunk = reader.read(n - len(buf))
        if not chunk:
            raise EOFError("unexpected end of input while parsing OpenPGP message")
        buf += chunk
    return bytes(buf)


def read_all(reader, bufsize: int = READ_BUFSIZE) -> bytes:
    """Read a `reader` to exhaustion. Only used for packet bodies that are
    known to be small and fixed-size (the SKESK packet), never for bulk
    payload data."""
    buf = bytearray()
    while True:
        chunk = reader.read(bufsize)
        if not chunk:
            return bytes(buf)
        buf += chunk


class ArmorReader:
    """Reads ASCII Armor (RFC 9580 Section 6) from a text stream, decoding
    it into the raw OpenPGP packet byte stream. At most one armor line's
    worth of decoded bytes is buffered at a time.
    """

    def __init__(self, text_stream):
        self._stream = text_stream
        self._buf = bytearray()
        self._done = False
        self._enter()

    def _readline(self) -> str:
        line = self._stream.readline()
        if not line:
            raise EOFError("unexpected end of input while reading ASCII armor")
        return line.rstrip("\n")

    def _enter(self) -> None:
        line = self._readline()
        while line == "":
            line = self._readline()
        if line != "-----BEGIN PGP MESSAGE-----":
            raise ValueError("input is not an ASCII-armored OpenPGP message")
        line = self._readline()
        while line != "":  # skip any armor header lines
            line = self._readline()

    def read(self, n: int) -> bytes:
        while len(self._buf) < n and not self._done:
            line = self._readline()
            if line.startswith("-----END"):
                self._done = True
                break
            if line.startswith("=") and len(line) == 5:
                continue  # optional CRC24 footer; RFC 9580 forbids it here, but skip if present
            self._buf += b64decode(line)
        take = min(n, len(self._buf))
        data = bytes(self._buf[:take])
        del self._buf[:take]
        return data


class PacketBodyReader:
    """Presents an OpenPGP packet body as a flat `read(n)` stream,
    transparently following Partial Body Length framing (RFC 9580 Section
    4.2.1.4) across as many segments as needed -- or a single ordinary
    Body Length header, which is just the degenerate one-segment case.
    Holds no more than one length header's worth of bookkeeping; the
    underlying segment data is never buffered beyond what the caller asks
    `read` for.
    """

    def __init__(self, stream):
        self._stream = stream
        self._segment_remaining = 0
        self._exhausted = False

    def _advance(self) -> None:
        first = read_exact(self._stream, 1)[0]
        if 224 <= first <= 254:
            self._segment_remaining = 1 << (first & 0x1F)
            return
        if first < 192:
            length = first
        elif first < 255:
            second = read_exact(self._stream, 1)[0]
            length = ((first - 192) << 8) + second + 192
        else:
            length = int.from_bytes(read_exact(self._stream, 4), "big")
        self._segment_remaining = length
        self._exhausted = True

    def read(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if self._segment_remaining == 0:
                if self._exhausted:
                    break
                self._advance()
                continue
            take = min(n - len(out), self._segment_remaining)
            out += read_exact(self._stream, take)
            self._segment_remaining -= take
        return bytes(out)


class AeadChunkDecryptor:
    """Decrypts the chunked-AEAD body of a v2 SEIPD packet (RFC 9580
    Section 5.13.2) back into the plaintext byte stream it was built from.

    There is no length prefix on individual chunks: a chunk is exactly
    `chunk_ciphertext_size` octets, except the last data chunk (which may
    be shorter) and the final tag-only chunk (always GCM_TAG_LEN octets)
    that follows it. Telling those two apart from a streamed source needs
    one octet of lookahead past a full chunk: if more than
    `chunk_ciphertext_size` octets are available, the first
    `chunk_ciphertext_size` of them must be a full ordinary chunk (the
    final tag is always the very last thing in the body); otherwise
    whatever remains once the body is exhausted is `[optional last data
    chunk] + [final tag]`, and the final tag is its last GCM_TAG_LEN
    octets. At most `chunk_ciphertext_size + 1` ciphertext octets are ever
    buffered.
    """

    def __init__(self, body_reader, message_key: bytes, iv_prefix: bytes, ad: bytes, chunk_ciphertext_size: int):
        self._body = body_reader
        self._aesgcm = AESGCM(message_key)
        self._iv_prefix = iv_prefix
        self._ad = ad
        self._chunk_ciphertext_size = chunk_ciphertext_size
        self._chunk_index = 0
        self._total_octets = 0
        self._ciphertext_buf = bytearray()
        self._body_exhausted = False
        self._plaintext_buf = bytearray()
        self._finished = False

    def _nonce(self, index: int) -> bytes:
        return self._iv_prefix + index.to_bytes(8, "big")

    def _decrypt_chunk(self, ciphertext: bytes, ad: bytes) -> bytes:
        plaintext = self._aesgcm.decrypt(self._nonce(self._chunk_index), ciphertext, ad)
        self._chunk_index += 1
        return plaintext

    def _fill_ciphertext_buf(self) -> None:
        target = self._chunk_ciphertext_size + 1
        while len(self._ciphertext_buf) < target and not self._body_exhausted:
            block = self._body.read(target - len(self._ciphertext_buf))
            if not block:
                self._body_exhausted = True
                break
            self._ciphertext_buf += block

    def _pull_chunk(self) -> None:
        self._fill_ciphertext_buf()

        if len(self._ciphertext_buf) > self._chunk_ciphertext_size:
            ciphertext = bytes(self._ciphertext_buf[: self._chunk_ciphertext_size])
            del self._ciphertext_buf[: self._chunk_ciphertext_size]
            plaintext = self._decrypt_chunk(ciphertext, self._ad)
            self._total_octets += len(plaintext)
            self._plaintext_buf += plaintext
            return

        if len(self._ciphertext_buf) < GCM_TAG_LEN:
            raise ValueError("corrupt OpenPGP message: missing final authentication tag")
        final_tag_ct = bytes(self._ciphertext_buf[-GCM_TAG_LEN:])
        leading = bytes(self._ciphertext_buf[:-GCM_TAG_LEN])
        self._ciphertext_buf.clear()

        if leading:
            plaintext = self._decrypt_chunk(leading, self._ad)
            self._total_octets += len(plaintext)
            self._plaintext_buf += plaintext

        final_ad = self._ad + self._total_octets.to_bytes(8, "big")
        final_plaintext = self._decrypt_chunk(final_tag_ct, final_ad)
        if final_plaintext != b"":
            raise ValueError("corrupt OpenPGP message: final authentication tag was not empty")
        self._finished = True

    def read(self, n: int) -> bytes:
        while len(self._plaintext_buf) < n and not self._finished:
            self._pull_chunk()
        take = min(n, len(self._plaintext_buf))
        data = bytes(self._plaintext_buf[:take])
        del self._plaintext_buf[:take]
        return data


def read_ctb_tag(stream) -> int:
    """Reads a new-format Packet Tag octet (RFC 9580 Section 4.2) and
    returns its tag number."""
    ctb = read_exact(stream, 1)[0]
    if ctb & 0xC0 != 0xC0:
        raise ValueError("unsupported OpenPGP packet: expected a new-format packet tag")
    return ctb & 0x3F


def parse_skesk_packet(body_reader, passphrase: bytes) -> bytes:
    """RFC 9580 Section 5.3.2. Returns the recovered session key, or raises
    cryptography.exceptions.InvalidTag if the passphrase is wrong."""
    version = read_exact(body_reader, 1)[0]
    if version != 6:
        raise ValueError(f"unsupported SKESK packet version {version}")

    fields_len = read_exact(body_reader, 1)[0]
    fields = read_exact(body_reader, fields_len)
    wrapped_key = read_all(body_reader)

    sym_algo, aead_algo, s2k_len = fields[0], fields[1], fields[2]
    if sym_algo != SYM_ALGO_AES256:
        raise ValueError("unsupported symmetric algorithm in SKESK packet")
    if aead_algo != AEAD_ALGO_GCM:
        raise ValueError("unsupported AEAD algorithm in SKESK packet")

    s2k_specifier = fields[3 : 3 + s2k_len]
    skesk_iv = fields[3 + s2k_len :]

    if s2k_specifier[0] != S2K_TYPE_ITERATED_SALTED:
        raise ValueError("unsupported S2K type in SKESK packet")
    if s2k_specifier[1] != S2K_HASH_SHA256:
        raise ValueError("unsupported S2K hash algorithm in SKESK packet")
    s2k_salt = s2k_specifier[2:10]
    count_enc = s2k_specifier[10]

    s2k_key = s2k_iterated_salted(passphrase, s2k_salt, s2k_decode_count(count_enc), 32)
    ad = bytes([0xC0 | TAG_SKESK, version, sym_algo, aead_algo])
    kek = hkdf_sha256(s2k_key, None, ad, 32)
    return AESGCM(kek).decrypt(skesk_iv, wrapped_key, ad)


def decrypt(input_stream, output_stream, passphrase: bytes) -> None:
    armor = ArmorReader(input_stream)

    if read_ctb_tag(armor) != TAG_SKESK:
        raise ValueError("expected a Symmetric-Key Encrypted Session Key packet")
    session_key = parse_skesk_packet(PacketBodyReader(armor), passphrase)

    if read_ctb_tag(armor) != TAG_SEIPD:
        raise ValueError("expected a Symmetrically Encrypted Integrity Protected Data packet")
    seipd_body = PacketBodyReader(armor)

    header = read_exact(seipd_body, 4)
    version, sym_algo, aead_algo, chunk_size_octet = header
    if version != 2:
        raise ValueError(f"unsupported SEIPD packet version {version}")
    if sym_algo != SYM_ALGO_AES256:
        raise ValueError("unsupported symmetric algorithm in SEIPD packet")
    if aead_algo != AEAD_ALGO_GCM:
        raise ValueError("unsupported AEAD algorithm in SEIPD packet")
    seipd_salt = read_exact(seipd_body, 32)

    info = bytes([0xC0 | TAG_SEIPD, version, sym_algo, aead_algo, chunk_size_octet])
    derived = hkdf_sha256(session_key, seipd_salt, info, 32 + GCM_NONCE_LEN - 8)
    message_key, iv_prefix = derived[:32], derived[32:]
    chunk_size = 1 << (chunk_size_octet + 6)

    aead = AeadChunkDecryptor(seipd_body, message_key, iv_prefix, info, chunk_size + 16)

    if read_ctb_tag(aead) != TAG_LITERAL:
        raise ValueError("expected a Literal Data packet")
    literal_body = PacketBodyReader(aead)

    fmt_and_fnlen = read_exact(literal_body, 2)
    filename_len = fmt_and_fnlen[1]
    if filename_len:
        read_exact(literal_body, filename_len)
    read_exact(literal_body, 4)  # timestamp, unused

    while True:
        block = literal_body.read(READ_BUFSIZE)
        if not block:
            break
        output_stream.write(block)


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="myenc decred",
        description="Decrypt an ASCII-armored, AES-256-GCM OpenPGP symmetric message produced by encred.",
    )
    parser.add_argument("-o", "--output", metavar="FILE", help="output file path (default: stdout)")
    parser.add_argument("-p", "--passphrase", required=True, metavar="PASSPHRASE", help="passphrase to decrypt with")
    parser.add_argument("input", nargs="?", metavar="FILE", help="input file path (default: stdin)")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    passphrase = args.passphrase.encode("utf-8")

    in_ctx = open(args.input, "r", encoding="ascii") if args.input else contextlib.nullcontext(sys.stdin)
    out_ctx = open(args.output, "wb") if args.output else contextlib.nullcontext(sys.stdout.buffer)
    with in_ctx as infile, out_ctx as outfile:
        try:
            decrypt(infile, outfile, passphrase)
        except InvalidTag:
            print("error: wrong passphrase, or the input is corrupted or tampered with", file=sys.stderr)
            return 1
        except (ValueError, EOFError) as exc:
            print(f"error: not a valid encred message: {exc}", file=sys.stderr)
            return 1
    return 0
