import pytest
from bip32_helper import (
    get_seed,
    get_pubkey_sec,
)
from bip32 import Xkey

MNEMONIC_FILENAME = "mnemonic_words.test"
ROOT_XPRV = "xprv9s21ZrQH143K3eWTAaVhmX3pjg5dy3qQvj5yMk63Gtnt52kunpXjB2JK3NC55eYgHKuCbp93qUPjo5iHVvdEZAWxUo5PvaH8vCxBBT5aTiN"
ROOT_XPUB = "xpub661MyMwAqRbcG8avGc2i8ezZHhv8NWZGHx1aA8VeqEKrwq64LMqyipcnteYvY8cBqUVkrYWbXnEVmTyjvQZwRuvKXfhpXi7cSBtwN1P7nGf"
DERIVATION_PATH_XPRV = [
    "xprv9zjDV8f2hhxzR73YLoA7e6sFEDwLN8XpnMEVRwwTVyG2W2hBvUMBVcvu1fEE8W7NtN7hoMdC9BohNGjYakn5UUwsq3ppuZWjArsSi1Fw7Ak",
    "xprvA16btDp914GUBy8JkyHGkW99XanQicCByhr9A1vqX5LTMSgi9Yv2yHe6C4vJJqew5sZcWRVxhfox2wHJGnq4YuVWexrTj5ou1wrhxrUgrii"
]
DERIVATION_PATH_XPUB = [
    "xpub6DiZteBvY5XHdb81Sph81EoynFmpmbFg9aA6ELM54Jo1Nq2LU1fS3RFNrtreGsBXnwJNcurR9vvBvR2zoP47nMC4nhrdRoBWx7hvnSPQmG1",
    "xpub6E5xHjM2qRpmQTCmrzpH7e5t5ccu84v3LvmjxQLT5QsSEF1rh6EHX5xa3N5UQDjhZTfwr27rUfiVzaFuFsBzMy49KC9qzZA4M5barAiDAxZ"
]
PATHS = [
    [
        (0, True),
        (0, False),
        (5, False),
        (1, True)
    ],
    [
        (0, False),
        (3, True),
        (16, True),
        (12, False)
    ]
]

@pytest.fixture
def seed():
    with open(MNEMONIC_FILENAME, "r") as handle:
        mnemonic_words = handle.read()
        mnemonic_bytes = mnemonic_words.encode("utf8")
        seed = get_seed(mnemonic_bytes, "test")
        return seed

def test_root_private_key(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    assert len(root_xprv.key) == 32
    assert len(root_xprv.chaincode) == 32
    assert root_xprv.root
    assert root_xprv.private_key
    assert root_xprv.depth is 0
    assert root_xprv.index is 0
    assert root_xprv.parent_pubkey is None
    assert ROOT_XPRV == root_xprv.serialize()
    assert Xkey.parse_from_bip32(ROOT_XPRV) == root_xprv

def test_root_public_key(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    root_xpub = root_xprv.derive_pubkey()
    assert len(root_xpub.key) == 33
    assert len(root_xpub.chaincode) == 32
    assert root_xpub.root
    assert not root_xpub.private_key
    assert root_xpub.depth is 0
    assert root_xpub.index is 0
    assert root_xpub.parent_pubkey is None
    assert ROOT_XPUB == root_xpub.serialize()
    assert Xkey.parse_from_bip32(ROOT_XPUB) == root_xpub

def test_derive_child_private_key(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    for i in range(16):
        child_xprv = root_xprv.derive_child_seed(i)
        assert len(child_xprv.key) == 32
        assert len(child_xprv.chaincode) == 32
        assert not child_xprv.root
        assert child_xprv.private_key
        assert child_xprv.depth == 1
        assert child_xprv.index == i
        assert child_xprv.parent_pubkey == get_pubkey_sec(root_xprv.key)

def test_derive_child_public_key_method_1(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    root_xpub = root_xprv.derive_pubkey()
    for i in range(16):
        child_xpub = root_xpub.derive_child_seed(i)
        assert len(child_xpub.key) == 33
        assert len(child_xpub.chaincode) == 32
        assert not child_xpub.root
        assert not child_xpub.private_key
        assert child_xpub.depth == 1
        assert child_xpub.index == i
        assert child_xpub.parent_pubkey == root_xpub.key

def test_derive_child_public_key_method_2(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    for i in range(16):
        child_xprv = root_xprv.derive_child_seed(i)
        child_xpub = child_xprv.derive_pubkey()
        assert len(child_xpub.key) == 33
        assert len(child_xpub.chaincode) == 32
        assert not child_xpub.root
        assert not child_xpub.private_key
        assert child_xpub.depth == 1
        assert child_xpub.index == i
        assert child_xpub.parent_pubkey == get_pubkey_sec(root_xprv.key)

def test_derive_private_key_based_on_path(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    for i, path in enumerate(PATHS):
        child_xprv_path = root_xprv.derive_path(path)
        child_parent_pubkey_path = child_xprv_path.parent_pubkey
        assert len(child_xprv_path.key) == 32
        assert len(child_xprv_path.chaincode) == 32
        assert not child_xprv_path.root
        assert child_xprv_path.private_key
        assert child_xprv_path.depth == len(path)
        if path[-1][1]:
            assert child_xprv_path.index == path[-1][0] + 2**31
        else:
            assert child_xprv_path.index == path[-1][0]
        assert len(child_xprv_path.parent_pubkey) == 33
        assert DERIVATION_PATH_XPRV[i] == child_xprv_path.serialize()
        assert Xkey.parse_from_bip32(
            DERIVATION_PATH_XPRV[i], parent_pubkey=child_parent_pubkey_path
        ) == child_xprv_path

def test_derive_public_key_based_on_path(seed):
    root_xprv = Xkey.parse_from_seed(seed)
    for i, path in enumerate(PATHS):
        child_xprv_path = root_xprv.derive_path(path)
        child_parent_pubkey_path = child_xprv_path.parent_pubkey
        child_xpub_path = child_xprv_path.derive_pubkey()
        assert len(child_xpub_path.key) == 33
        assert len(child_xpub_path.chaincode) == 32
        assert not child_xpub_path.root
        assert not child_xpub_path.private_key
        assert child_xpub_path.depth == len(path)
        if path[-1][1]:
            assert child_xprv_path.index == path[-1][0] + 2**31
        else:
            assert child_xprv_path.index == path[-1][0]
        assert len(child_xpub_path.parent_pubkey) == 33
        assert DERIVATION_PATH_XPUB[i] == child_xpub_path.serialize()
        assert Xkey.parse_from_bip32(
            DERIVATION_PATH_XPUB[i], parent_pubkey=child_parent_pubkey_path
        ) == child_xpub_path
