#!/usr/bin/env python3
"""
Omada Controller backup (.cfg) encryptor -- the inverse of omada_decrypt.py.

Reverse-engineered from TP-Link Omada Controller v6.2.10.17. Produces a .cfg
file that the controller's restore routine accepts:

    RC4( GZIP( JSON ) )

The RC4 key is identical to the one used for decryption (RC4 is symmetric), so
the crypto primitives are imported from omada_decrypt.py. The only genuinely new
code here is the *forward* direction of the per-field cipher:

    "v2#" + base64( AES-128/CBC/PKCS5-encrypt( plaintext ) )

with the key/IV derived from systemSetting.pbkdf2KeySaltIv exactly as in the
decryptor. Because the IV is fixed (derived, not random), field encryption is
deterministic: re-encrypting a decrypted value reproduces the original "v2#"
string byte-for-byte.

Field handling (automatic)
--------------------------
By default omada_decrypt.py appends a "__omada_encrypted_fields__" key listing
the JSON paths of every field it decrypted. omada_encrypt.py reads that marker
and re-encrypts exactly those fields, then strips the marker -- so a plain
decrypt -> edit -> encrypt cycle restores the original encrypted layout with no
extra flags. Input forms supported:

  * decrypted JSON with the marker (default decrypt output): fields listed in
    the marker are re-encrypted automatically.

  * keep-encrypted JSON (`omada_decrypt.py --keep-encrypted`): "v2#" values are
    still present and have no marker, so they pass straight through.

  * fully decrypted JSON without a marker: pass --encrypt-fields to encrypt the
    fields named in SENSITIVE_FIELD_NAMES.

Usage:
    python omada_encrypt.py <input.json> [output.cfg]   # auto, uses marker
    python omada_encrypt.py <input.json> output.cfg --encrypt-fields
    python omada_encrypt.py --selftest <original.cfg>    # round-trip validation
"""

import sys
import zlib
import json
import base64
import struct

import omada_decrypt as dec
from omada_decrypt import (
    FIELD_PREFIX,
    METADATA_KEY,
    build_rc4_key,
    rc4,
    derive_field_key_iv,
    aes_cbc_decrypt,
    _SBOX,
    _key_expansion,
    _mul,
)


# --- AES-128 forward (encrypt) -------------------------------------------
# Mirrors the inverse primitives in omada_decrypt.py.

def _shift_rows(s):
    # state is column-major: index = row + 4*col
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def _mix_columns(s):
    out = [0] * 16
    for c in range(4):
        col = s[4 * c:4 * c + 4]
        out[4 * c + 0] = _mul(col[0], 2) ^ _mul(col[1], 3) ^ col[2] ^ col[3]
        out[4 * c + 1] = col[0] ^ _mul(col[1], 2) ^ _mul(col[2], 3) ^ col[3]
        out[4 * c + 2] = col[0] ^ col[1] ^ _mul(col[2], 2) ^ _mul(col[3], 3)
        out[4 * c + 3] = _mul(col[0], 3) ^ col[1] ^ col[2] ^ _mul(col[3], 2)
    return out


def _aes_encrypt_block(block, round_keys):
    s = [block[i] ^ round_keys[0][i] for i in range(16)]
    for rnd in range(1, 10):
        s = [_SBOX[b] for b in s]
        s = _shift_rows(s)
        s = _mix_columns(s)
        s = [s[i] ^ round_keys[rnd][i] for i in range(16)]
    s = [_SBOX[b] for b in s]
    s = _shift_rows(s)
    s = [s[i] ^ round_keys[10][i] for i in range(16)]
    return bytes(s)


def aes_cbc_encrypt(key, iv, data):
    rk = _key_expansion(key)
    pad = 16 - (len(data) % 16)        # PKCS#5/7 padding (always 1..16 bytes)
    data = data + bytes([pad]) * pad
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(data[off + i] ^ prev[i] for i in range(16))
        enc = _aes_encrypt_block(block, rk)
        out.extend(enc)
        prev = enc
    return bytes(out)


# --- per-field encryption ------------------------------------------------

# Field names whose string values are stored "v2#"-encrypted, as observed in a
# v6.2.10.17 backup. Used only with --encrypt-fields on a fully decrypted JSON.
# Extend this set if a backup uses additional encrypted fields.
SENSITIVE_FIELD_NAMES = {
    "hwId", "oemId",
}


def encrypt_field_value(plain, key, iv):
    """plaintext -> 'v2#' + base64(AES-CBC-PKCS5)."""
    ct = aes_cbc_encrypt(key, iv, plain.encode("utf-8"))
    return FIELD_PREFIX + base64.b64encode(ct).decode("ascii")


def reencrypt_by_paths(doc, key, iv, paths):
    """Re-encrypt exactly the fields recorded by omada_decrypt.py in METADATA_KEY.

    `paths` is a list of segment-lists (dict keys / list indices). Returns the
    number of fields re-encrypted."""
    count = 0
    for p in paths:
        ref = doc
        try:
            for seg in p[:-1]:
                ref = ref[seg]
            last = p[-1]
            val = ref[last]
        except (KeyError, IndexError, TypeError):
            continue                       # path no longer valid (edited JSON)
        if isinstance(val, str) and not val.startswith(FIELD_PREFIX):
            ref[last] = encrypt_field_value(val, key, iv)
            count += 1
    return count


def encrypt_fields(obj, key, iv, names):
    """Recursively re-encrypt selected string fields. Returns (obj, count)."""
    count = 0
    if isinstance(obj, dict):
        new = {}
        for k, v in obj.items():
            if isinstance(v, str) and k in names and not v.startswith(FIELD_PREFIX):
                new[k] = encrypt_field_value(v, key, iv)
                count += 1
            else:
                nv, c = encrypt_fields(v, key, iv, names)
                new[k] = nv
                count += c
        return new, count
    if isinstance(obj, list):
        new = []
        for v in obj:
            nv, c = encrypt_fields(v, key, iv, names)
            new.append(nv)
            count += c
        return new, count
    return obj, count


# --- outer layer ---------------------------------------------------------

def java_gzip(data, level=6):
    """GZIP `data` byte-for-byte like Java's GZIPOutputStream.

    Java's Deflater is a JNI wrapper around the same zlib that Python uses, so at
    the default level (6) the DEFLATE stream is identical. The only header
    difference is the OS byte: Java writes 0xFF ("unknown") and MTIME 0, whereas
    Python's gzip module writes a different OS byte -- so we frame it by hand.
    """
    co = zlib.compressobj(level, zlib.DEFLATED, -15)   # raw DEFLATE (no zlib wrapper)
    deflate = co.compress(data) + co.flush()
    header = b"\x1f\x8b\x08\x00" + b"\x00\x00\x00\x00" + b"\x00" + b"\xff"  # CM=8,FLG=0,MTIME=0,XFL=0,OS=255
    trailer = struct.pack("<II", zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return header + deflate + trailer


def encrypt_json_bytes(json_bytes):
    """JSON bytes -> RC4(GZIP(json)), byte-identical to a controller export."""
    return rc4(build_rc4_key(), java_gzip(json_bytes))


def encrypt(path, encrypt_inner_fields=False):
    """Build a .cfg from a JSON file.

    Field handling (in priority order):
      1. If the JSON carries the METADATA_KEY written by omada_decrypt.py, the
         listed fields are re-encrypted automatically and the marker removed.
      2. Else if --encrypt-fields was given, fields named in
         SENSITIVE_FIELD_NAMES are encrypted.
      3. Else the JSON is passed through unchanged (already-encrypted / keep-
         encrypted form).

    Returns (cfg_bytes, fields_encrypted)."""
    with open(path, "rb") as f:
        raw = f.read()
    n = 0
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        doc = None

    if isinstance(doc, dict) and METADATA_KEY in doc:
        paths = doc.pop(METADATA_KEY)
        ksi = doc.get("systemSetting", {}).get("pbkdf2KeySaltIv")
        if not (ksi and len(ksi) >= 96):
            raise ValueError("METADATA_KEY present but no pbkdf2KeySaltIv to derive the field key")
        key, iv = derive_field_key_iv(ksi)
        n = reencrypt_by_paths(doc, key, iv, paths)
        raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    elif encrypt_inner_fields and isinstance(doc, dict):
        ksi = doc.get("systemSetting", {}).get("pbkdf2KeySaltIv")
        if ksi and len(ksi) >= 96:
            key, iv = derive_field_key_iv(ksi)
            doc, n = encrypt_fields(doc, key, iv, SENSITIVE_FIELD_NAMES)
        raw = json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

    return encrypt_json_bytes(raw), n


# --- self-test / round-trip validation -----------------------------------

def selftest(cfg_path):
    """Prove the encryptor is a true inverse of the decryptor.

    1. AES forward path: decrypt every 'v2#' value and re-encrypt it; the
       result must equal the original 'v2#' string (deterministic IV).
    2. Outer layer: re-encrypt the exact decrypted JSON and confirm the produced
       .cfg is byte-for-byte identical to the original file.
    """
    print("== Omada encryptor self-test ==")
    print("Source:", cfg_path)

    with open(cfg_path, "rb") as f:
        original_cfg = f.read()

    # ---- outer-layer byte-identity ----
    plain_keep, gz = dec.decrypt(cfg_path)        # exact JSON bytes (v2# intact)
    rebuilt = encrypt_json_bytes(plain_keep)      # our RC4(GZIP(json))
    assert rebuilt == original_cfg, (
        "rebuilt .cfg is not byte-identical (len %d vs %d)"
        % (len(rebuilt), len(original_cfg)))
    print("[OK] outer layer: rebuilt .cfg is BYTE-IDENTICAL to the original "
          "(%d bytes)" % len(original_cfg))

    # ---- field cipher round trip ----
    doc = json.loads(plain_keep.decode("utf-8"))
    ksi = doc.get("systemSetting", {}).get("pbkdf2KeySaltIv")
    tested = ok = 0
    if ksi and len(ksi) >= 96:
        key, iv = derive_field_key_iv(ksi)

        def walk(o):
            nonlocal tested, ok
            if isinstance(o, dict):
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
            elif isinstance(o, str) and o.startswith(FIELD_PREFIX):
                tested += 1
                ct = base64.b64decode(o[len(FIELD_PREFIX):])
                pt = aes_cbc_decrypt(key, iv, ct)
                reenc = encrypt_field_value(pt.decode("utf-8"), key, iv)
                if reenc == o:
                    ok += 1
        walk(doc)
        if tested:
            assert ok == tested, "field re-encryption mismatch (%d/%d)" % (ok, tested)
            print("[OK] field cipher: re-encrypted %d 'v2#' value(s), all match "
                  "originals byte-for-byte" % tested)
        else:
            print("[--] field cipher: no 'v2#' values present to test")
    else:
        print("[--] field cipher: no pbkdf2KeySaltIv; skipped")

    print("== ALL CHECKS PASSED ==")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    if argv[1] == "--selftest":
        if len(argv) < 3:
            print("usage: omada_encrypt.py --selftest <original.cfg>")
            return 1
        return selftest(argv[2])

    path = argv[1]
    encrypt_inner = "--encrypt-fields" in argv
    positional = [a for a in argv[2:] if not a.startswith("--")]
    out = positional[0] if positional else path.rsplit(".", 1)[0] + ".cfg"

    data, n = encrypt(path, encrypt_inner_fields=encrypt_inner)
    with open(out, "wb") as f:
        f.write(data)
    if n:
        print("Re-encrypted %d inner field value(s)." % n)
    print("Wrote %d bytes -> %s" % (len(data), out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
