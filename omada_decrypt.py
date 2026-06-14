#!/usr/bin/env python3
"""
Omada Controller backup (.cfg) decryptor.

Reverse-engineered from TP-Link Omada Controller v6.2.10.17
(com.tplink.smb.omada.common.util.b.j / .m).

Backup file format (outer layer):
    RC4( GZIP( JSON ) )

The RC4 key is a fixed 224-byte array `c` whose FIRST 8-byte block has been
TEA-decrypted (Tiny Encryption Algorithm, 64 rounds, key `a`); the remaining
216 bytes are left unchanged. BouncyCastle's RC4Engine is used with that key.

After RC4 + GZIP you get a UTF-8 JSON document containing the controller /
site configuration (the "SDN backup file").

Usage:
    python omada_decrypt.py <backup.cfg> [output.json]
    python omada_decrypt.py <backup.cfg> --raw out.bin   # raw RC4 output (gzip stream)
"""

import sys
import gzip
import json
import base64
import hashlib

MASK = 0xFFFFFFFF

# --- key material borrowed from m.class and j.class ---------------

# m.a : the TEA key (4 x int32)
TEA_KEY = [-707509657, -1887749506, 1427902494, -1686606610]
DELTA = -1640531527  # 0x9E3779B9 as a signed 32-bit int

# j.c : the obfuscated RC4 key array (signed bytes, length 224)
C = [112, 122, 14, 91, -110, 101, -10, 34, 51, 59, 94, 118, 50, 108, 63, 50,
     94, 52, 94, 104, 67, 100, 117, 114, 110, 53, 47, 79, 38, 103, 43, 59,
     70, 43, 72, 119, 107, 61, 108, 82, 84, 80, 36, 95, 106, 72, 53, 101,
     105, 81, 38, 47, 65, 110, 47, 47, 99, 79, 72, 36, 50, 108, 68, 48,
     120, 89, 68, 97, 95, 70, 65, 35, 33, 84, 53, 49, 64, 102, 105, 88,
     84, 100, 76, 49, 63, 107, 82, 45, 58, 115, 126, 101, 63, 95, 45, 72,
     50, 45, 84, 36, 100, 117, 43, 110, 114, 65, 72, 98, 112, 103, 78, 45,
     121, 98, 114, 52, 117, 37, 57, 36, 40, 126, 45, 66, 64, 101, 100, 73,
     122, 108, 114, 100, 112, 110, 98, 94, 37, 102, 37, 95, 51, 89, 90, 49,
     115, 95, 103, 89, 106, 103, 101, 56, 117, 99, 106, 115, 108, 118, 89, 33,
     69, 33, 82, 107, 102, 64, 76, 117, 61, 122, 40, 45, 38, 75, 116, 87,
     99, 100, 41, 63, 73, 119, 37, 57, 43, 57, 42, 69, 61, 36, 42, 83,
     95, 58, 112, 52, 118, 47, 77, 112, 57, 115, 57, 56, 61, 51, 108, 89,
     117, 67, 100, 99, 107, 121, 36, 101, 100, 113, 70, 108, 37, 79, 55, 47,
     49, 72, 114, 73, 56, 78, 64, 85, 122, 33, 99, 37, 76, 75, 33, 108,
     110, 117, 88, 114, 115, 73, 80, 110, 47, 118, 97, 37, 114, 89, 85, 71]


def s32(x):
    """Truncate to signed 32-bit, mirroring Java int overflow."""
    x &= MASK
    return x - 0x100000000 if x & 0x80000000 else x


def tea_decrypt_block(y, z, key, times=64):
    """Port of m.b(byte[], offset, key, times) for a single 8-byte block."""
    a, b, c, d = key
    if times == 32:
        sm = -957401312
    elif times == 16:
        sm = -478700656
    else:
        sm = s32(DELTA * times)
    for _ in range(times):
        # z -= ((y<<4)+c) ^ (y+sum) ^ ((y>>5)+d)   (Java arithmetic >>)
        z = s32(z - (s32((s32(y << 4) + c) ^ s32(y + sm) ^ s32((y >> 5) + d))))
        # y -= ((z<<4)+a) ^ (z+sum) ^ ((z>>5)+b)
        y = s32(y - (s32((s32(z << 4) + a) ^ s32(z + sm) ^ s32((z >> 5) + b))))
        sm = s32(sm - DELTA)
    return y, z


def bytes_to_ints_be(b):
    """Port of m.d: big-endian, sign-extending the top byte (Java behaviour)."""
    out = []
    for j in range(0, len(b), 4):
        b0 = b[j] if b[j] < 128 else b[j] - 256          # signed (content[j]<<24)
        v = (b[j + 3] & 0xFF) | ((b[j + 2] & 0xFF) << 8) \
            | ((b[j + 1] & 0xFF) << 16) | (b0 << 24)
        out.append(s32(v))
    return out


def ints_to_bytes_be(ints):
    """Port of m.a(int[], 0)."""
    out = bytearray(len(ints) * 4)
    for i, v in enumerate(ints):
        j = i * 4
        out[j + 3] = v & 0xFF
        out[j + 2] = (v >> 8) & 0xFF
        out[j + 1] = (v >> 16) & 0xFF
        out[j] = (v >> 24) & 0xFF
    return bytes(out)


def build_rc4_key():
    """Replicate j.a(InputStream)'s key: m.b(c, 0).

    m.b(byte[], offset) reads the WHOLE array into ints, TEA-decrypts only the
    first block (tempInt[0], tempInt[1]), then re-serialises every int. So the
    result is `c` with its first 8 bytes decrypted and the rest unchanged.
    """
    ints = bytes_to_ints_be(C)
    y, z = tea_decrypt_block(ints[0], ints[1], TEA_KEY, 64)
    ints[0], ints[1] = y, z
    return ints_to_bytes_be(ints)


def rc4(key, data):
    """Standard RC4 (matches BouncyCastle RC4Engine)."""
    S = list(range(256))
    j = 0
    klen = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % klen]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray(len(data))
    i = j = 0
    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]
    return bytes(out)


# --- per-field decryption (the "v2#" values inside the JSON) -------------
#
# Reverse-engineered from com.tplink.smb.omada.common.util.b.{a,i,b}.
#
# Some string values inside the JSON (device keys, secrets) are individually
# encrypted and prefixed with "v2#". They are:
#       AES-128/CBC/PKCS5  ( base64decode( value[3:] ) )
# with the key & IV derived from systemSetting.pbkdf2KeySaltIv (96 hex chars):
#       seed = value[0:32]   salt = hex(value[32:64])   iv = hex(value[64:96])
#       key  = PBKDF2-HMAC-SHA256("v0hGiXNmbzJdhMvx8BRMrg=="+seed, salt,
#                                 1000 iterations, 128-bit)
# "v0hGiXNmbzJdhMvx8BRMrg==" is a hard-coded prefix from class i.

FIELD_PREFIX = "v2#"
PBKDF2_PREFIX = b"v0hGiXNmbzJdhMvx8BRMrg=="

# Key appended to the decrypted JSON listing the paths of every field that was
# "v2#"-encrypted, so omada_encrypt.py can re-encrypt exactly those fields. Each
# path is a list of dict-key (str) / list-index (int) segments from the root.
METADATA_KEY = "__omada_encrypted_fields__"

# --- minimal AES-128 (decrypt only) so the script stays dependency-free ---
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
_INV_SBOX = bytearray(256)
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _xtime(a):
    a <<= 1
    return (a ^ 0x11b) & 0xFF if a & 0x100 else a


def _mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        b >>= 1
        a = _xtime(a)
    return r


def _key_expansion(key):
    """Return 11 round keys (each 16 bytes) for AES-128."""
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    # group the 44 words into 11 round keys of 16 bytes each
    return [bytes(b for word in w[4 * r:4 * r + 4] for b in word)
            for r in range(11)]


def _aes_decrypt_block(block, round_keys):
    s = [block[i] ^ round_keys[10][i] for i in range(16)]
    for rnd in range(9, 0, -1):
        # InvShiftRows
        s = _inv_shift_rows(s)
        # InvSubBytes
        s = [_INV_SBOX[b] for b in s]
        # AddRoundKey
        s = [s[i] ^ round_keys[rnd][i] for i in range(16)]
        # InvMixColumns
        s = _inv_mix_columns(s)
    s = _inv_shift_rows(s)
    s = [_INV_SBOX[b] for b in s]
    s = [s[i] ^ round_keys[0][i] for i in range(16)]
    return bytes(s)


def _inv_shift_rows(s):
    # state is column-major: index = row + 4*col
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c - r) % 4)]
    return out


def _inv_mix_columns(s):
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _mul(col[0], 14) ^ _mul(col[1], 11) ^ _mul(col[2], 13) ^ _mul(col[3], 9)
        out[4 * c + 1] = _mul(col[0], 9) ^ _mul(col[1], 14) ^ _mul(col[2], 11) ^ _mul(col[3], 13)
        out[4 * c + 2] = _mul(col[0], 13) ^ _mul(col[1], 9) ^ _mul(col[2], 14) ^ _mul(col[3], 11)
        out[4 * c + 3] = _mul(col[0], 11) ^ _mul(col[1], 13) ^ _mul(col[2], 9) ^ _mul(col[3], 14)
    return out


def aes_cbc_decrypt(key, iv, data):
    rk = _key_expansion(key)
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        dec = _aes_decrypt_block(block, rk)
        out.extend(bytes(dec[i] ^ prev[i] for i in range(16)))
        prev = block
    pad = out[-1]               # strip PKCS#5/7 padding
    if 1 <= pad <= 16:
        out = out[:-pad]
    return bytes(out)


def derive_field_key_iv(key_salt_iv):
    """Derive (aes_key, iv) from systemSetting.pbkdf2KeySaltIv (class i)."""
    seed = key_salt_iv[0:32].encode("utf-8")
    salt = bytes.fromhex(key_salt_iv[32:64])
    iv = bytes.fromhex(key_salt_iv[64:96])
    key = hashlib.pbkdf2_hmac("sha256", PBKDF2_PREFIX + seed, salt, 1000, dklen=16)
    return key, iv


def decrypt_fields(obj, key, iv, path=()):
    """Recursively replace any 'v2#...' string with its decrypted value.

    Returns (new_obj, paths) where paths is a list of segment-lists locating
    each field that was decrypted, so the operation can later be reversed."""
    if isinstance(obj, dict):
        new = {}
        paths = []
        for k, v in obj.items():
            nv, p = decrypt_fields(v, key, iv, path + (k,))
            new[k] = nv
            paths += p
        return new, paths
    if isinstance(obj, list):
        new = []
        paths = []
        for i, v in enumerate(obj):
            nv, p = decrypt_fields(v, key, iv, path + (i,))
            new.append(nv)
            paths += p
        return new, paths
    if isinstance(obj, str) and obj.startswith(FIELD_PREFIX):
        try:
            data = base64.b64decode(obj[len(FIELD_PREFIX):])
            plain = aes_cbc_decrypt(key, iv, data).decode("utf-8")
            return plain, [list(path)]
        except Exception:
            return obj, []
    return obj, []


def decrypt(path):
    with open(path, "rb") as f:
        enc = f.read()
    key = build_rc4_key()
    gz = rc4(key, enc)
    if gz[:2] != b"\x1f\x8b":
        raise ValueError(
            "RC4 output is not a gzip stream (magic=%r). "
            "Decryption key/algorithm mismatch." % gz[:4]
        )
    return gzip.decompress(gz), gz


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    path = argv[1]
    raw_mode = "--raw" in argv
    if raw_mode:
        out = argv[argv.index("--raw") + 1]
        _, gz = decrypt(path)
        with open(out, "wb") as f:
            f.write(gz)
        print("Wrote raw RC4 output (gzip stream) to", out)
        return 0
    out = argv[2] if len(argv) > 2 else path.rsplit(".", 1)[0] + ".json"
    keep_encrypted = "--keep-encrypted" in argv
    plain, _ = decrypt(path)
    print("Decrypted %d bytes of JSON -> %s" % (len(plain), out))

    if keep_encrypted:
        with open(out, "wb") as f:
            f.write(plain)
        print("(left 'v2#' fields encrypted as requested)")
        print("Preview:", plain[:200].decode("utf-8", "replace"))
        return 0

    # second pass: decrypt the individual "v2#" fields in place
    try:
        doc = json.loads(plain.decode("utf-8"))
        ksi = doc.get("systemSetting", {}).get("pbkdf2KeySaltIv")
        if ksi and len(ksi) >= 96:
            key, iv = derive_field_key_iv(ksi)
            doc, paths = decrypt_fields(doc, key, iv)
            if paths:
                doc[METADATA_KEY] = paths   # let omada_encrypt.py reverse this
            print("Decrypted %d 'v2#' inner field value(s)." % len(paths))
        else:
            print("No pbkdf2KeySaltIv found; inner fields left as-is.")
        with open(out, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        print("Preview:", json.dumps(doc.get("mainInfo", {}))[:200])
    except Exception as e:
        # fall back to writing the raw decrypted JSON if anything goes wrong
        with open(out, "wb") as f:
            f.write(plain)
        print("WARN: inner-field pass failed (%s); wrote raw JSON." % e)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
