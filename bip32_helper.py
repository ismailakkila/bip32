"""This module contains BIP39 helper functions"""

import hashlib
from ecc import PrivateKey

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def get_seed(mnemonic_bytes, passphrase=None):
    """
    This function creates a mnemonic seed from bytes encoded mnemonic.
    Passphrase is optional
    """
    if passphrase is not None:
        salt = ("mnemonic" + passphrase).encode("utf8")
    else:
        salt = "mnemonic".encode("utf8")
    seed = hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic_bytes,
        salt,
        2048,
    )
    return seed

def get_pubkey_sec(private_key_bytes):
    """
    This function returns SEC encoded public key from byte-encoded private key
    """
    secret = int.from_bytes(private_key_bytes, "big")
    private_key = PrivateKey(secret)
    public_key = private_key.point
    return public_key.sec(compressed=True)

def derivation_path_string(path, private=True):
    """
    This function returns a string friendly version of the derivation path
    """
    if private:
        result = "m"
    else:
        result = "M"
    for item in path:
        result += "/"
        index, hardened = item
        if hardened:
            result += str(index) + "'"
        else:
            result += str(index)
    return result

def decode_base58(base58_string):
    """
    This function decodes a base58 string to a number
    """
    num = 0
    for char in base58_string:
        num *= 58
        num += BASE58_ALPHABET.index(char)
    return num.to_bytes(82, byteorder='big')

def encode_base58(data):
    """
    This function encodes bytes to a base58 string
    """
    # determine how many 0 bytes (b'\x00') s starts with
    count = 0
    for byte in data:
        if byte == 0:
            count += 1
        else:
            break
    # convert to big endian integer
    num = int.from_bytes(data, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result

def encode_base58_checksum(data):
    """
    This function returns the Base58 check format
    """
    return encode_base58(data + hash256(data)[:4])

def hash160(data):
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def hash256(data):
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def sha256(data):
    """one round of sha256"""
    return hashlib.sha256(data).digest()
