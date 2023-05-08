#! /usr/bin/env python3

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes

key = bytearray(
    [
        0x2B,
        0x7E,
        0x15,
        0x16,
        0x28,
        0xAE,
        0xD2,
        0xA6,
        0xAB,
        0xF7,
        0x15,
        0x88,
        0x09,
        0xCF,
        0x4F,
        0x3C,
    ]
)

iv = bytearray(
    [
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0A,
        0x0B,
        0x0C,
        0x0D,
        0x0E,
        0x0F,
    ]
)

src_ = bytearray(
    b"This is a test of AES-CBC that goes on longer than a couple blocks. It is a somewhat long test case to type out!"
)

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

h = hashes.Hash(hashes.SHA256())
for length in range(0, len(src_)):
    src = src_[0:length]
    padder = padding.PKCS7(128).padder()
    padded_src = padder.update(src)
    padded_src += padder.finalize()
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_src) + encryptor.finalize()
    h.update(ct)

res = h.finalize()
print(*res, sep=", ")
