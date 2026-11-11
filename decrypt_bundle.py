#!/usr/bin/env python3
"""Decrypt PMK EncryptedAssetBundleProvider AssetBundles (AES-128-CTR).

File layout:
  0x00  4 bytes  magic (rpu.ybe)
  0x04  1 byte   version (must be 1)
  0x05  16 bytes IV (initial counter, 128-bit big-endian)
  0x15  ...      ciphertext

Key = SHA256(ybj + ybi + ybl + ybk)[:16]

pip install pycryptodome
usage: python decrypt_bundle.py in.bundle out.bundle
"""
import os
import sys
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter

# Fill these in from rpu's static constructor data (rpu..cctor):
YBJ = bytes.fromhex("2DB740881C6FD3AA")        # 8 bytes  (field 2BB8B2DE...)
YBI = bytes.fromhex("9A146BC23FE87105")        # 8 bytes  (field 9617C506...)
YBL = bytes.fromhex("706D6B5F6173736574")      # 9 bytes  (field 51976B0A...) = b"pmk_asset"
YBK = bytes.fromhex("E159079C843B62F0")        # 8 bytes  (field F5907EB1...)

HEADER_LEN = 0x15


def derive_key() -> bytes:
    assert (len(YBJ), len(YBI), len(YBL), len(YBK)) == (8, 8, 9, 8), \
        "fill in the four byte arrays with correct lengths (8, 8, 9, 8)"
    return hashlib.sha256(YBJ + YBI + YBL + YBK).digest()[:16]


def decrypt(data: bytes) -> bytes:
    if data[4] != 1:
        raise ValueError(f"unexpected version byte: {data[4]}")
    iv = data[5:0x15]
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"),
                      allow_wraparound=True)
    cipher = AES.new(derive_key(), AES.MODE_CTR, counter=ctr)
    return cipher.decrypt(data[HEADER_LEN:])


def encrypt(plain: bytes, magic: bytes, iv: bytes = None) -> bytes:
    """Mirror of rpu::uqi: magic(4) + 0x01 + IV(16) + CTR(plain)."""
    if len(magic) != 4:
        raise ValueError("magic must be 4 bytes")
    iv = iv or os.urandom(16)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"),
                      allow_wraparound=True)
    cipher = AES.new(derive_key(), AES.MODE_CTR, counter=ctr)
    return magic + b"\x01" + iv + cipher.encrypt(plain)


def main():
    usage = ("usage:\n"
             "  python decrypt_bundle.py dec in.enc out.bundle\n"
             "  python decrypt_bundle.py enc in.bundle out.enc original.enc\n"
             "    (original.enc = any original encrypted file; its first 4 bytes are the magic)")
    if len(sys.argv) < 4 or sys.argv[1] not in ("dec", "enc"):
        sys.exit(usage)
    mode, src, dst = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(src, "rb") as f:
        data = f.read()
    if mode == "dec":
        out = decrypt(data)
        print("header:", out[:7])  # should start with b'UnityFS'
    else:
        if len(sys.argv) < 5:
            sys.exit(usage)
        with open(sys.argv[4], "rb") as f:
            magic = f.read(4)
        out = encrypt(data, magic)
        # sanity check: round-trip
        assert decrypt(out) == data, "round-trip failed"
        print("encrypted, round-trip OK")
    with open(dst, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    main()
