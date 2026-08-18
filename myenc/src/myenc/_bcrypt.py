# SPDX-FileCopyrightText: 2026-present U.N. Owen <void@some.where>
#
# SPDX-License-Identifier: MIT
"""A from-scratch, pure-Python bcrypt (Provos & Mazières, "A Future-Adaptable
Password Scheme") implementation, exposing the same `gensalt`/`hashpw`/
`checkpw` surface as the `bcrypt` PyPI package. `hashpass.py` and
`encred.py` import this instead of that package so `myenc` has no compiled
dependency and keeps working in environments where `bcrypt` can't be
installed.

Encoding of a hash: `$<2a|2b|2y>$<cost, 2 digits>$<22-char salt><31-char
hash>`, both halves in bcrypt's own base64 variant (custom alphabet, no
padding). `checkpw` accepts hashes produced by any of those three version
markers (the algorithm itself is identical across them; only an old,
long-fixed 8-bit-charset handling bug in some C implementations
distinguished `2x`), but `gensalt` only ever produces `2b`, matching the
`bcrypt` package's own default.

Bcrypt itself is EksBlowfish: standard Blowfish (a 16-round Feistel cipher
keyed by a 18-word P-array and four 256-word S-boxes, themselves initialized
from the hex digits of pi per Bruce Schneier's original reference) run
through an expensive, salt-dependent key schedule, then used to encrypt a
fixed 24-byte string ("OrpheanBeholderScryDoubt") 64 times in ECB mode. The
P-array/S-box initialization constants below were generated (not
transcribed) from a big-precision computation of pi and hex-digit
extraction — see `hashpass`/`encred`'s test suite for the script — then
spot-checked against the well-known opening words of the standard tables.

Being pure Python, this is far slower than a C/Rust bcrypt: several seconds
per hash at the default cost of 12 rather than tens of milliseconds. That's
an acceptable trade for a tool invoked interactively, a handful of times per
run, in exchange for zero compiled dependencies.

Validated by cross-checking hashpw/checkpw against the real `bcrypt`
package (installed only in a scratch environment for this one-time
comparison, never a project dependency) across empty/short/72-byte/unicode/
embedded-NUL passwords, multiple cost factors, and both directions
(hashes produced by each implementation verified by the other) — see
the project's development history for that validation script.
"""

import hmac
import os

_MASK32 = 0xFFFFFFFF

# Standard Blowfish P-array / S-box initialization constants: the
# hexadecimal digits of pi, 32 bits at a time.
_ORIG_P_HEX = (
    "243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89452821e638d0"
    "1377be5466cf34e90c6cc0ac29b7c97c50dd3f84d5b5b54709179216d5d98979fb1b"
)

_ORIG_S0_HEX = (
    "d1310ba698dfb5ac2ffd72dbd01adfb7b8e1afed6a267e96ba7c9045f12c7f9924a19947b391"
    "6cf70801f2e2858efc16636920d871574e69a458fea3f4933d7e0d95748f728eb658718bcd58"
    "82154aee7b54a41dc25a59b59c30d5392af26013c5d1b023286085f0ca417918b8db38ef8e79"
    "dcb0603a180e6c9e0e8bb01e8a3ed71577c1bd314b2778af2fda55605c60e65525f3aa55ab94"
    "5748986263e8144055ca396a2aab10b6b4cc5c341141e8cea15486af7c72e993b3ee1411636f"
    "bc2a2ba9c55d741831f6ce5c3e169b87931eafd6ba336c24cf5c7a325381289586773b8f4898"
    "6b4bb9afc4bfe81b6628219361d809ccfb21a991487cac605dec8032ef845d5de98575b1dc26"
    "2302eb651b8823893e81d396acc50f6d6ff383f442392e0b4482a484200469c8f04a9e1f9b5e"
    "21c66842f6e96c9a670c9c61abd388f06a51a0d2d8542f68960fa728ab5133a36eef0b6c137a"
    "3be4ba3bf0507efb2a98a1f1651d39af017666ca593e82430e888cee8619456f9fb47d84a5c3"
    "3b8b5ebee06f75d885c12073401a449f56c16aa64ed3aa62363f77061bfedf72429b023d37d0"
    "d724d00a1248db0fead349f1c09b075372c980991b7b25d479d8f6e8def7e3fe501ab6794c3b"
    "976ce0bd04c006bac1a94fb6409f60c45e5c9ec2196a246368fb6faf3e6c53b51339b2eb3b52"
    "ec6f6dfc511f9b30952ccc814544af5ebd09bee3d004de334afd660f2807192e4bb3c0cba857"
    "45c8740fd20b5f39b9d3fbdb5579c0bd1a60320ad6a100c6402c7279679f25fefb1fa3cc8ea5"
    "e9f8db3222f83c7516dffd616b152f501ec8ad0552ab323db5fafd23876053317b483e00df82"
    "9e5c57bbca6f8ca01a87562edf1769dbd542a8f6287effc3ac6732c68c4f5573695b27b0bbca"
    "58c8e1ffa35db8f011a010fa3d98fd2183b84afcb56c2dd1d35b9a53e479b6f84565d28e49bc"
    "4bfb9790e1ddf2daa4cb7e3362fb1341cee4c6e8ef20cada36774c01d07e9efe2bf11fb495db"
    "da4dae909198eaad8e716b93d5a0d08ed1d0afc725e08e3c5b2f8e7594b78ff6e2fbf2122b64"
    "8888b812900df01c4fad5ea0688fc31cd1cff191b3a8c1ad2f2f2218be0e1777ea752dfe8b02"
    "1fa1e5a0cc0fb56f74e818acf3d6ce89e299b4a84fe0fd13e0b77cc43b81d2ada8d9165fa266"
    "8095770593cc7314211a1477e6ad206577b5fa86c75442f5fb9d35cfebcdaf0c7b3e89a0d641"
    "1bd3ae1e7e4900250e2d2071b35e226800bb57b8e0af2464369bf009b91e5563911d59dfa6aa"
    "78c14389d95a537f207d5ba202e5b9c5832603766295cfa911c819684e734a41b3472dca7b14"
    "a94a1b5100529a532915d60f573fbc9bc6e42b60a47681e6740008ba6fb5571be91ff296ec6b"
    "2a0dd915b6636521e7b9f9b6ff34052ec585566453b02d5da99f8fa108ba47996e85076a"
)

_ORIG_S1_HEX = (
    "4b7a70e9b5b32944db75092ec4192623ad6ea6b049a7df7d9cee60b88fedb266ecaa8c71699a"
    "17ff5664526cc2b19ee1193602a575094c29a0591340e4183a3e3f54989a5b429d656b8fe4d6"
    "99f73fd6a1d29c07efe830f54d2d38e6f0255dc14cdd20868470eb266382e9c6021ecc5e0968"
    "6b3f3ebaefc93c9718146b6a70a1687f358452a0e286b79c5305aa5007373e07841c7fdeae5c"
    "8e7d44ec5716f2b8b03ada37f0500c0df01c1f040200b3ffae0cf51a3cb574b225837a58dc09"
    "21bdd19113f97ca92ff69432477322f547013ae5e58137c2dadcc8b576349af3dda7a9446146"
    "0fd0030eecc8c73ea4751e41e238cd993bea0e2f3280bba1183eb3314e548b384f6db9086f42"
    "0d03f60a04bf2cb8129024977c795679b072bcaf89afde9a771fd9930810b38bae12dccf3f2e"
    "5512721f2e6b7124501adde69f84cd877a5847187408da17bc9f9abce94b7d8cec7aec3adb85"
    "1dfa63094366c464c3d2ef1c18473215d908dd433b3724c2ba1612a14d432a65c45150940002"
    "133ae4dd71dff89e10314e5581ac77d65f11199b043556f1d7a3c76b3c11183b5924a509f28f"
    "e6ed97f1fbfa9ebabf2c1e153c6e86e34570eae96fb1860e5e0a5a3e2ab3771fe71c4e3d06fa"
    "2965dcb999e71d0f803e89d65266c8252e4cc9789c10b36ac6150eba94e2ea78a5fc3c531e0a"
    "2df4f2f74ea7361d2b3d1939260f19c279605223a708f71312b6ebadfe6eeac31f66e3bc4595"
    "a67bc883b17f37d1018cff28c332ddefbe6c5aa56558218568ab9802eecea50fdb2f953b2aef"
    "7dad5b6e2f841521b62829076170ecdd4775619f151013cca830eb61bd960334fe1eaa0363cf"
    "b5735c904c70a239d59e9e0bcbaade14eecc86bc60622ca79cab5cabb2f3846e648b1eaf19bd"
    "f0caa02369b9655abb5040685a323c2ab4b3319ee9d5c021b8f79b540b19875fa09995f7997e"
    "623d7da8f837889a97e32d7711ed935f166812810e358829c7e61fd696dedfa17858ba9957f5"
    "84a51b2272639b83c3ff1ac24696cdb30aeb532e30548fd948e46dbc312858ebf2ef34c6ffea"
    "fe28ed61ee7c3c735d4a14d9e864b7e342105d14203e13e045eee2b6a3aaabeadb6c4f15facb"
    "4fd0c742f442ef6abbb5654f3b1d41cd2105d81e799e86854dc7e44b476a3d816250cf62a1f2"
    "5b8d2646fc8883a0c1c7b6a37f1524c369cb749247848a0b5692b285095bbf00ad19489d1462"
    "b17423820e0058428d2a0c55f5ea1dadf43e233f70613372f0928d937e41d65fecf16c223bdb"
    "7cde3759cbee74604085f2a7ce77326ea607808419f8509ee8efd85561d99735a969a7aac50c"
    "06c25a04abfc800bcadc9e447a2ec3453484fdd567050e1e9ec9db73dbd3105588cd675fda79"
    "e3674340c5c43465713e38d83d28f89ef16dff20153e21e78fb03d4ae6e39f2bdb83adf7"
)

_ORIG_S2_HEX = (
    "e93d5a68948140f7f64c261c94692934411520f77602d4f7bcf46b2ed4a20068d40824713320"
    "f46a43b7d4b7500061af1e39f62e9724454614214f74bf8b88404d95fc1d96b591af70f4ddd3"
    "66a02f45bfbc09ec03bd97857fac6dd031cb850496eb27b355fd3941da2547e6abca0a9a2850"
    "7825530429f40a2c86dae9b66dfb68dc1462d7486900680ec0a427a18dee4f3ffea2e887ad8c"
    "b58ce0067af4d6b6aace1e7cd3375fecce78a399406b2a4220fe9e35d9f385b9ee39d7ab3b12"
    "4e8b1dc9faf74b6d185626a36631eae397b23a6efa74dd5b43326841e7f7ca7820fbfb0af54e"
    "d8feb397454056acba48952755533a3a20838d87fe6ba9b7d096954b55a867bca1159a58cca9"
    "296399e1db33a62a4a563f3125f95ef47e1c9029317cfdf8e80204272f7080bb155c05282ce3"
    "95c11548e4c66d2248c1133fc70f86dc07f9c9ee41041f0f404779a45d886e17325f51ebd59b"
    "c0d1f2bcc18f41113564257b7834602a9c60dff8e8a31f636c1b0e12b4c202e1329eaf664fd1"
    "cad181156b2395e0333e92e13b240b62eebeb92285b2a20ee6ba0d99de720c8c2da2f728d012"
    "784595b794fd647d0862e7ccf5f05449a36f877d48fac39dfd27f33e8d1e0a476341992eff74"
    "3a6f6eabf4f8fd37a812dc60a1ebddf8991be14cdb6e6b0dc67b55106d672c372765d43bdcd0"
    "e804f1290dc7cc00ffa3b5390f92690fed0b667b9ffbcedb7d9ca091cf0bd9155ea3bb132f88"
    "515bad247b9479bf763bd6eb37392eb3cc1159798026e297f42e312d6842ada7c66a2b3b1275"
    "4ccc782ef11c6a124237b79251e706a1bbe64bfb63501a6b101811caedfa3d25bdd8e2e1c3c9"
    "444216590a121386d90cec6ed5abea2a64af674eda86a85fbebfe98864e4c3fe9dbc8057f0f7"
    "c08660787bf86003604dd1fd8346f6381fb07745ae04d736fccc83426b33f01eab71b0804187"
    "3c005e5f77a057bebde8ae2455464299bf582e614e58f48ff2ddfda2f474ef388789bdc25366"
    "f9c3c8b38e74b475f25546fcd9b97aeb26618b1ddf84846a0e79915f95e2466e598e20b45770"
    "8cd55591c902de4cb90bace1bb8205d011a862487574a99eb77f19b6e0a9dc09662d09a1c432"
    "4633e85a1f0209f0be8c4a99a0251d6efe101ab93d1d0ba5a4dfa186f20f2868f169dcb7da83"
    "573906fea1e2ce9b4fcd7f5250115e01a70683faa002b5c40de6d0279af88c27773f8641c360"
    "4c0661a806b5f0177a28c0f586e0006058aa30dc7d6211e69ed72338ea6353c2dd94c2c21634"
    "bbcbee5690bcb6deebfc7da1ce591d766f05e4094b7c018839720a3d7c927c2486e3725f724d"
    "9db91ac15bb4d39eb8fced54557808fca5b5d83d7cd34dad0fc41e50ef5eb161e6f8a28514d9"
    "6c51133c6fd5c7e756e14ec4362abfceddc6c837d79a323492638212670efa8e406000e0"
)

_ORIG_S3_HEX = (
    "3a39ce37d3faf5cfabc277375ac52d1b5cb0679e4fa33742d382274099bc9bbed5118e9dbf0f"
    "7315d62d1c7ec700c47bb78c1b6b21a19045b26eb1be6a366eb45748ab2fbc946e79c6a376d2"
    "6549c2c8530ff8ee468dde7dd5730a1d4cd04dc62939bbdba9ba4650ac9526e8be5ee304a1fa"
    "d5f06a2d519a63ef8ce29a86ee22c089c2b843242ef6a51e03aa9cf2d0a483c061ba9be96a4d"
    "8fe51550ba645bd62826a2f9a73a3ae14ba99586ef5562e9c72fefd3f752f7da3f046f6977fa"
    "0a5980e4a91587b086019b09e6ad3b3ee593e990fd5a9e34d7972cf0b7d9022b8b5196d5ac3a"
    "017da67dd1cf3ed67c7d2d281f9f25cfadf2b89b5ad6b4725a88f54ce029ac71e019a5e647b0"
    "acfded93fa9be8d3c48d283b57ccf8d5662979132e28785f0191ed756055f7960e44e3d35e8c"
    "15056dd488f46dba03a161250564f0bdc3eb9e153c9057a297271aeca93a072a1b3f6d9b1e63"
    "21f5f59c66fb26dcf3197533d928b155fdf5035634828aba3cbb28517711c20ad9f8abcc5167"
    "ccad925f4de817513830dc8e379d58629320f991ea7a90c2fb3e7bce5121ce64774fbe32a8b6"
    "e37ec3293d4648de53696413e680a2ae0810dd6db22469852dfd09072166b39a460a6445c0dd"
    "586cdecf1c20c8ae5bbef7dd1b588d40ccd2017f6bb4e3bbdda26a7e3a59ff453e350a44bcb4"
    "cdd572eacea8fa6484bb8d6612aebf3c6f47d29be463542f5d9eaec2771bf64e6370740e0d8d"
    "e75b1357f8721671af537d5d4040cb084eb4e2cc34d2466a0115af84e1b0042895983a1d06b8"
    "9fb4ce6ea0486f3f3b823520ab82011a1d4b277227f8611560b1e7933fdcbb3a792b344525bd"
    "a08839e151ce794b2f32c9b7a01fbac9e01cc87ebcc7d1f6cf0111c3a1e8aac71a908749d44f"
    "bd9ad0dadecbd50ada380339c32ac69136678df9317ce0b12b4ff79e59b743f5bb3af2d519ff"
    "27d9459cbf97222c15e6fc2a0f91fc719b941525fae59361ceb69cebc2a8645912baa8d1b6c1"
    "075ee3056a0c10d25065cb03a442e0ec6e0e1698db3b4c98a0be3278e9649f1f9532e0d392df"
    "d3a0342b8971f21e1b0a74414ba3348cc5be7120c37632d8df359f8d9b992f2ee60b6f470fe3"
    "f11de54cda541edad891ce6279cfcd3e7e6f1618b166fd2c1d05848fd2c5f6fb2299f523f357"
    "a632762393a8353156cccd02acf081625a75ebb56e16369788d273ccde96629281b949d04c50"
    "901b71c65614e6c6c7bd327a140a45e1d006c3f27b9ac9aa53fd62a80f00bb25bfe235bdd2f6"
    "71126905b2040222b6cbcf7ccd769c2b53113ec01640e3d338abbd602547adf0ba38209cf746"
    "ce7677afa1c52075606085cbfe4e8ae88dd87aaaf9b04cf9aa7e1948c25c02fb8a8c01c36ae4"
    "d6ebe1f990d4f869a65cdea03f09252dc208e69fb74e6132ce77e25b578fdfe33ac372e6"
)


def _hex_words(hexstr: str) -> list[int]:
    return [int(hexstr[i : i + 8], 16) for i in range(0, len(hexstr), 8)]


_ORIG_P = _hex_words(_ORIG_P_HEX)
_ORIG_S = [_hex_words(h) for h in (_ORIG_S0_HEX, _ORIG_S1_HEX, _ORIG_S2_HEX, _ORIG_S3_HEX)]


class _ByteCycler:
    """Cycles through `data` 4 bytes (1 big-endian word) at a time, wrapping
    around indefinitely; used to feed a key or salt into the Blowfish key
    schedule regardless of how its length compares to what's consumed.
    """

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def word(self) -> int:
        data, pos, n = self.data, self.pos, len(self.data)
        w = 0
        for _ in range(4):
            w = (w << 8) | data[pos]
            pos += 1
            if pos >= n:
                pos = 0
        self.pos = pos
        return w


class _Blowfish:
    __slots__ = ("P", "S")

    def __init__(self):
        self.P = list(_ORIG_P)
        self.S = [list(box) for box in _ORIG_S]

    def encrypt(self, l: int, r: int) -> tuple[int, int]:
        P = self.P
        S0, S1, S2, S3 = self.S
        for i in range(16):
            l ^= P[i]
            f = (((S0[(l >> 24) & 0xFF] + S1[(l >> 16) & 0xFF]) & _MASK32) ^ S2[(l >> 8) & 0xFF]) + S3[l & 0xFF]
            r ^= f & _MASK32
            l, r = r, l
        l, r = r, l
        r ^= P[16]
        l ^= P[17]
        return l & _MASK32, r & _MASK32

    def _expand_key(self, key_cycler: _ByteCycler, salt_cycler: _ByteCycler | None = None) -> None:
        """Blowfish's standard key schedule (XOR `key` cyclically into P,
        then overwrite P and each S-box with chained self-encryptions of a
        zero-initialized running block) — optionally also XORing `salt`
        cyclically into that running block before each encryption, which is
        bcrypt's `ExpandKey` extension used to fold the salt in.
        """
        P = self.P
        for i in range(18):
            P[i] ^= key_cycler.word()
        l = r = 0
        for i in range(0, 18, 2):
            if salt_cycler is not None:
                l ^= salt_cycler.word()
                r ^= salt_cycler.word()
            l, r = self.encrypt(l, r)
            P[i], P[i + 1] = l, r
        for box in self.S:
            for i in range(0, 256, 2):
                if salt_cycler is not None:
                    l ^= salt_cycler.word()
                    r ^= salt_cycler.word()
                l, r = self.encrypt(l, r)
                box[i], box[i + 1] = l, r

    def eks_setup(self, cost: int, salt: bytes, key: bytes) -> None:
        """EksBlowfishSetup: the expensive, salt-dependent key schedule that
        makes bcrypt tunably slow. `key` is folded in once per iteration to
        keep the whole schedule dependent on the password even at high cost.
        """
        self._expand_key(_ByteCycler(key), _ByteCycler(salt))
        for _ in range(1 << cost):
            self._expand_key(_ByteCycler(key))
            self._expand_key(_ByteCycler(salt))


# bcrypt's own base64 variant: same MSB-first 3-byte-to-4-char grouping as
# RFC 4648 base64, but a different alphabet and no padding character.
_B64_ALPHABET = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_B64_INDEX = {c: i for i, c in enumerate(_B64_ALPHABET)}


def _b64encode(data: bytes) -> bytes:
    out = bytearray()
    i, n = 0, len(data)
    while i < n:
        c1 = data[i]
        i += 1
        out.append(_B64_ALPHABET[c1 >> 2])
        c1 = (c1 & 0x03) << 4
        if i >= n:
            out.append(_B64_ALPHABET[c1])
            break
        c2 = data[i]
        i += 1
        c1 |= (c2 >> 4) & 0x0F
        out.append(_B64_ALPHABET[c1])
        c1 = (c2 & 0x0F) << 2
        if i >= n:
            out.append(_B64_ALPHABET[c1])
            break
        c2 = data[i]
        i += 1
        c1 |= (c2 >> 6) & 0x03
        out.append(_B64_ALPHABET[c1])
        out.append(_B64_ALPHABET[data[i - 1] & 0x3F])
    return bytes(out)


def _b64decode(chars: bytes, out_len: int) -> bytes:
    out = bytearray()
    p, n = 0, len(chars)
    while len(out) < out_len and p + 1 < n:
        c1, c2 = _B64_INDEX[chars[p]], _B64_INDEX[chars[p + 1]]
        out.append(((c1 << 2) | ((c2 & 0x30) >> 4)) & 0xFF)
        if len(out) >= out_len or p + 2 >= n:
            break
        c3 = _B64_INDEX[chars[p + 2]]
        out.append((((c2 & 0x0F) << 4) | ((c3 & 0x3C) >> 2)) & 0xFF)
        if len(out) >= out_len or p + 3 >= n:
            break
        c4 = _B64_INDEX[chars[p + 3]]
        out.append((((c3 & 0x03) << 6) | c4) & 0xFF)
        p += 4
    return bytes(out[:out_len])


_ORPHEAN = b"OrpheanBeholderScryDoubt"  # 24 bytes = 6 32-bit words = 3 Blowfish blocks
_VALID_PREFIXES = (b"2a", b"2b", b"2y")


def _bcrypt_raw(password: bytes, salt: bytes, cost: int) -> bytes:
    bf = _Blowfish()
    bf.eks_setup(cost, salt, password + b"\x00")

    words = [int.from_bytes(_ORPHEAN[i : i + 4], "big") for i in range(0, 24, 4)]
    for _ in range(64):
        for i in range(0, 6, 2):
            words[i], words[i + 1] = bf.encrypt(words[i], words[i + 1])
    return b"".join(w.to_bytes(4, "big") for w in words)


def gensalt(rounds: int = 12, prefix: bytes = b"2b") -> bytes:
    if not 4 <= rounds <= 31:
        raise ValueError("invalid rounds")
    if prefix not in _VALID_PREFIXES:
        raise ValueError(f"invalid prefix {prefix!r}")
    return b"$" + prefix + b"$%02d$" % rounds + _b64encode(os.urandom(16))


def _parse_salt(salt: bytes | str) -> tuple[bytes, int, bytes]:
    if isinstance(salt, str):
        salt = salt.encode("ascii")
    parts = salt.split(b"$")
    if len(parts) < 4 or parts[0] != b"" or parts[1] not in _VALID_PREFIXES:
        raise ValueError("invalid salt")
    prefix, cost, salt_chars = parts[1], int(parts[2]), parts[3][:22]
    if len(salt_chars) != 22:
        raise ValueError("invalid salt")
    return prefix, cost, _b64decode(salt_chars, 16)


def hashpw(password: bytes, salt: bytes | str) -> bytes:
    if len(password) > 72:
        raise ValueError("password cannot be longer than 72 bytes, truncate manually if necessary")
    prefix, cost, salt_bytes = _parse_salt(salt)
    raw = _bcrypt_raw(password, salt_bytes, cost)
    return b"$" + prefix + b"$%02d$" % cost + _b64encode(salt_bytes) + _b64encode(raw[:23])


def checkpw(password: bytes, hashed: bytes | str) -> bool:
    if isinstance(hashed, str):
        hashed = hashed.encode("ascii")
    return hmac.compare_digest(hashpw(password, hashed), hashed)
