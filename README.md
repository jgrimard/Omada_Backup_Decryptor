# Omada Backup Decryptor

Decrypt TP-Link Omada Controller `.cfg` backup files into readable JSON — no
controller required.

## Why this exists

I needed to look up a few settings from an old Omada backup, but the `.cfg`
file is encrypted, and the only official way to read it is to restore it.
Restoring would have rolled my live controller back to that older state, which
I didn't want. I just wanted to read the configuration out of the file.

So I reverse-engineered the backup format from the controller's own Java
classes and built this decryptor. It turns a `.cfg` backup into the plain JSON
the controller stores internally, so you can inspect any backup — current or
years old — without touching your running controller.

## Features

- Decrypts Omada `.cfg` backups to formatted JSON.
- Also decrypts the individual `v2#`-encrypted fields inside the JSON.
- **Read-only** — never connects to or modifies a controller or the `.cfg`.
- **No dependencies** — pure Python 3 standard library (RC4, TEA, AES-128-CBC
  and PBKDF2 are all included or come from the stdlib).
- Works offline; the decryption keys are embedded in the file format itself,
  not tied to your controller.

## Usage

```sh
python omada_decrypt.py backup.cfg
# -> writes backup.json (pretty-printed, with inner "v2#" fields decrypted)

python omada_decrypt.py backup.cfg out.json          # explicit output path
python omada_decrypt.py backup.cfg --keep-encrypted  # leave "v2#" fields as-is
python omada_decrypt.py backup.cfg --raw stream.gz   # stop after RC4 (raw gzip)
```

Requires Python 3.6+.

## What you get

The output JSON mirrors the controller's internal "SDN backup" structure, e.g.:

```
mainInfo, systemSetting, sites, deviceBriefInfo, role, tenant,
radiusServerSetting, firmwareUpgradeConfig, globalNotification, ...
```

— site settings, WLAN/SSID config, wired networks, device lists, profiles,
schedules, and so on.

## How it works

Reverse-engineered from Omada Controller **v6.2.10.17** (classes
`com.tplink.smb.omada.common.util.b.{j,m,a,i}`, decompiled from
`backup-core-*.jar` / `omada-common-*.jar`). Tested against a v6.2.10.17
controller backup; other 6.x versions are likely compatible but unverified.

### Outer layer — the whole file

```
.cfg file  =  RC4( GZIP( JSON ) )
```

1. **RC4** (BouncyCastle `RC4Engine`) over the entire file.
2. **GZIP** decompression.
3. UTF-8 **JSON**.

The RC4 key is **not** a user password — it is hard-coded in the controller. It
is a 224-byte array (`c` in `j.class`) whose **first 8-byte block is
TEA-decrypted** (Tiny Encryption Algorithm, 64 rounds, key `a` from `m.class`);
the remaining 216 bytes are used unchanged. The script reproduces this exactly,
so it works without the controller. Because the key is static and embedded in
the software, every controller of this version uses the same key.

### Inner layer — individual `v2#` fields

A handful of values inside the JSON (hardware/OEM identifiers and similar) are
*additionally* encrypted and carry a `v2#` prefix. These are decrypted in a
second pass (skippable with `--keep-encrypted`):

```
plaintext = AES-128/CBC/PKCS5( base64decode( value[3:] ) )
```

The key and IV come from `systemSetting.pbkdf2KeySaltIv` — a 96-hex-char string
**stored inside the same backup** (the controller's `AES_KEY_IN_FILE`), split
into three 32-char parts:

| chars   | meaning                                          |
|---------|--------------------------------------------------|
| `0:32`  | key seed (used as a string, **not** hex-decoded) |
| `32:64` | salt (hex → 16 bytes)                            |
| `64:96` | IV  (hex → 16 bytes)                             |

```
key = PBKDF2-HMAC-SHA256("v0hGiXNmbzJdhMvx8BRMrg==" + seed, salt,
                         iterations = 1000, keyLen = 128 bits)
```

`"v0hGiXNmbzJdhMvx8BRMrg=="` is a hard-coded prefix in class `i`.

> These `v2#` fields are really *database* at-rest encryption that happens to
> ride along into the export — not a backup-specific protection. Since the key
> lives in the same file, decrypting them adds no real secrecy; it's mainly
> tamper/obfuscation hardening of internal identifiers.

> Legacy backups (pre-`v2#`) encrypted fields with a static, TEA-derived key in
> `AES/ECB` mode, but those values carry **no prefix**, so they can't be
> distinguished from ordinary strings and aren't auto-decrypted.

## A note on secrets

The decrypted JSON can contain **plaintext** secrets — Wi-Fi PSKs, device admin
passwords, RADIUS secrets — because the controller needs them in clear to push
to devices. Treat the output as sensitive and don't commit real backups or
their decrypted JSON to a repository.

The controller *login* password is **not** recoverable: it's stored as a
one-way Apache Shiro salted hash (`$shiro1$SHA-256$...`), not encrypted, so no
tool can turn it back into the original password.

## Disclaimer

This is an independent, unofficial project, not affiliated with or endorsed by
TP-Link. "Omada" and "TP-Link" are trademarks of their respective owners.
Provided for interoperability and personal data-recovery purposes — use it only
on backups you own or are authorized to access. No warranty of any kind.

## License

MIT
