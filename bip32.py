"""
This module allows you to derive master and child private and public keys
from a mnemonic according to the BIP32 spec
"""

import hmac
from hashlib import sha512
from io import BytesIO
from ecc import S256Point, N, G
from bip32_helper import (
    get_pubkey_sec,
    decode_base58,
    encode_base58_checksum,
    hash160,
    hash256
)

class Xkey:
    """
    This class allows you to create a master or child key instance
    """

    def __init__(
            self,
            key,
            chaincode,
            private_key,
            root=False,
            depth=0,
            index=0,
            parent_pubkey=None
    ):
        self.key = key
        self.chaincode = chaincode
        self.root = root
        self.private_key = private_key
        if not root:
            assert depth != 0
            assert parent_pubkey is not None
        self.depth = depth
        self.index = index
        self.parent_pubkey = parent_pubkey

    def __eq__(self, other):
        return  \
            self.key == other.key and \
            self.chaincode == other.chaincode and \
            self.root == other.root and \
            self.private_key == other.private_key and \
            self.depth == other.depth and \
            self.index == other.index and \
            self.parent_pubkey == other.parent_pubkey

    def __repr__(self):
        output = ""
        if self.root:
            output = "Master - Private key: {} - {}".format(
                self.private_key, self.serialize()
            )
        else:
            output = "Child - Depth: {} - Index: {} - Private key: {} - {}".format(
                self.depth,
                self.index,
                self.private_key,
                self.serialize()
            )
        return output

    @classmethod
    def parse_from_seed(cls, seed):
        """This function instantiates an Xkey instance from a mnemonic seed"""

        full_node = hmac.new(
            key="Bitcoin seed".encode("utf8"),
            msg=seed,
            digestmod=sha512
        ).digest()
        left_node = full_node[0:32]
        right_node = full_node[32:]
        return cls(
            left_node,
            right_node,
            True,
            root=True
        )

    @classmethod
    def parse_from_bip32(cls, bip32key, parent_pubkey=None):
        """This function instantiates an Xkey instance from a serialized Xkey (xprv/ xpub)"""

        decoded = decode_base58(bip32key)
        checksum = decoded[-4:]
        if checksum != hash256(decoded[:-4])[:4]:
            raise ValueError("Checksum mismatch!")
        stream = BytesIO(decoded[:-4])
        version = stream.read(4)
        if version == bytes.fromhex("0488ade4"):
            private_key = True
        elif version == bytes.fromhex("0488b21e"):
            private_key = False
        else:
            raise ValueError("Unsupported BIP32 Key Format")
        depth = stream.read(1)[0]
        fingerprint = stream.read(4)
        index = int.from_bytes(stream.read(4), "big")
        if depth == 0 and fingerprint == b"\x00" * 4 and index == 0:
            root = True
        else:
            if hash160(parent_pubkey)[:4] != fingerprint:
                raise ValueError("Fingerprint mismatch!")
            root = False
        chaincode = stream.read(32)
        key = stream.read(33)
        if key[0] == 0:
            key = key[1:]

        return cls(
            key,
            chaincode,
            private_key,
            root=root,
            depth=depth,
            index=index,
            parent_pubkey=parent_pubkey
        )

    def derive_child_seed(self, index_num):
        """
        This function derives a child seed with provided index.
        Please note that an index >= 2**31 is a hardened index
        """

        if self.private_key:
            pubkey = get_pubkey_sec(self.key)
            if index_num >= 2**31:
                data = b"\x00" + self.key + index_num.to_bytes(4, "big")
            else:
                data = pubkey + index_num.to_bytes(4, "big")
        else:
            pubkey = self.key
            if index_num >= 2**31:
                raise ValueError("Cannot use hardened index!")
            data = pubkey + index_num.to_bytes(4, "big")

        full_node = hmac.new(
            key=self.chaincode,
            msg=data,
            digestmod=sha512
        ).digest()

        left_node = full_node[0:32]
        right_node = full_node[32:]
        left_node_num = int.from_bytes(left_node, "big")
        key_num = int.from_bytes(self.key, "big")

        if self.private_key:
            total = key_num + left_node_num
            total = total % N
            key = total.to_bytes(32, "big")
        else:
            key_point = S256Point.parse(self.key)
            left_point = left_node_num * G
            total = key_point + left_point
            key = total.sec()

        if self.root:
            depth = 1
        else:
            depth = self.depth + 1

        return self.__class__(
            key,
            right_node,
            self.private_key,
            root=False,
            depth=depth,
            index=index_num,
            parent_pubkey=pubkey
        )

    def derive_path(self, path):
        """
        This function derives a child seed according to a provided path.
        Example: If desired path is m/0'/1/0', path must be the following
        array: [[0, True], [1, False], [0, True]]
        """

        seed = self
        for item in path:
            index, hardened = item
            if hardened:
                index += 2**31
            seed = seed.derive_child_seed(index)
        return seed

    def derive_pubkey(self):
        """
        This function derives a public key from a xprv Xkey instance
        """

        assert self.private_key
        return self.__class__(
            get_pubkey_sec(self.key),
            self.chaincode,
            False,
            root=self.root,
            depth=self.depth,
            index=self.index,
            parent_pubkey=self.parent_pubkey
        )

    def serialize(self):
        """
        The serialized xprv or xpub of the Xkey instance in bytes
        """

        result = b""
        if self.private_key:
            result += bytes.fromhex("0488ade4")
        else:
            result += bytes.fromhex("0488b21e")
        if self.root:
            result += b"\x00"
            result += b"\x00" * 4
            result += b"\x00" * 4
        else:
            result += bytes([self.depth])
            result += hash160(self.parent_pubkey)[:4]
            result += self.index.to_bytes(4, "big")
        result += self.chaincode
        if self.private_key:
            result += b"\x00" + self.key
        else:
            result += self.key
        return encode_base58_checksum(result)
