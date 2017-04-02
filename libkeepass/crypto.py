# -*- coding: utf-8 -*-
import hashlib
import struct
from Crypto.Cipher import AES
try:
    from CryptoPlus.Cipher import python_Twofish
except ImportError:
    class _python_Twofish(object):
            def __getattribute__(self, k):
                raise IOError("The support library for this encryption method (twofish) is not installed.  Run `pip install \'https://github.com/doegox/python-cryptoplus/tarball/master\'`")
    python_Twofish = _python_Twofish()

from libkeepass.pureSalsa20 import Salsa20

AES_BLOCK_SIZE = 16


def sha256(s):
    """Return SHA256 digest of the string `s`."""
    return bytes(hashlib.sha256(s).digest())


def transform_key(key, seed, rounds):
    """Transform `key` with `seed` `rounds` times using AES ECB."""
    # create transform cipher with transform seed
    cipher = AES.new(seed, AES.MODE_ECB)
    # transform composite key rounds times
    for n in range(0, rounds):
        key = cipher.encrypt(key)
    # return hash of transformed key
    return sha256(key)


def aes_cbc_decrypt(data, key, enc_iv):
    """Decrypt and return `data` with AES CBC."""
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    return cipher.decrypt(data)


def aes_cbc_encrypt(data, key, enc_iv):
    """Encrypt and return `data` with AES CBC."""
    cipher = AES.new(key, AES.MODE_CBC, enc_iv)
    return cipher.encrypt(data)


def twofish_cbc_decrypt(data, key, enc_iv):
    """Decrypt and return `data` with Twofish CBC."""
    cipher = python_Twofish.new(key, python_Twofish.MODE_CBC, enc_iv)
    return cipher.decrypt(data)


def twofish_cbc_encrypt(data, key, enc_iv):
    """Encrypt and return `data` with Twofish CBC."""
    cipher = python_Twofish.new(key, python_Twofish.MODE_CBC, enc_iv)
    return cipher.encrypt(data)


def unpad(data):
    return data[:len(data) - bytearray(data)[-1]]


def pad(s):
    n = AES_BLOCK_SIZE - len(s) % AES_BLOCK_SIZE
    return s + n * struct.pack('b', n)


def xor(aa, bb):
    """Return a bytearray of a bytewise XOR of `aa` and `bb`."""
    return bytearray([a ^ b for a, b in zip(bytearray(aa), bytearray(bb))])
