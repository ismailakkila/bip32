# BIP32 Implementation using Python

This is the BIP32 specification implementation for [Bitcoin](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki). It allows you to create a BIP39 seed (using optional passphrase) from mnemonic words. The seed can be used to derive corresponding master and child keys (xprv and xpub) from a provided derivation path.

### Installation

```
pip install -r requirements
```

## Usage

**Create a root private key from mnemonic file**
```
from bip32 import Xkey
from bip32_helper import get_seed

MNEMONIC_FILENAME = "mnemonic_words.test"
with open(MNEMONIC_FILENAME, "r") as handle:
      mnemonic_words = handle.read()
      mnemonic_bytes = mnemonic_words.encode("utf8")
seed = get_seed(mnemonic_bytes, "passphrase") #Optional passphrase
root_xprv = Xkey.parse_from_seed(seed)
print(root_xprv)

Master - Private key: True - xprv9s21ZrQH143K4Rv5SHNb7Wb6DmHft73AfmTGFYi3XnoH9HwibFWkwkiWTbcqpigja2s6tfJmWi658Y3gzzUveKg82rfvZcxHFcgQ9mmisD2
```

**Root public key**
```
root_xpub = root_xprv.derive_pubkey()
print(root_xpub)

Master - Private key: False - xpub661MyMwAqRbcGuzYYJubUeXpmo8AHZm22zNs3w7f68LG26Gs8nq1VZ2zJrGr2t6YT5u6xp2RhSgoeXqX5txgmFgRf3qLt7vbsXaFoHb4BpP
```

**Derive child private key**
```
#Non-Hardened index
index = 0
child_xprv = root_xprv.derive_child_seed(index)
print(child_xprv)

Child - Depth: 1 - Index: 0 - Private key: True - xprv9uPRFhEUka2L35CBRBEkBgeaaUR6ddqsfT3g2iFA9bSQk329ALohYSLFpwELc9iEwefSA5V8jMbetoXaEhqgK8cdHzQieBdejQPBakswUzY

#Hardened index
index = 2**31
child_xprv = root_xprv.derive_child_seed(index)
print(child_xprv)

Child - Depth: 1 - Index: 2147483648 - Private key: True - xprv9uPRFhEd6EZJCTPc3JXhrJjjLrJHDtvsvHzXszkHz8MexLqwAPLmMb5WLMAodF8cHxaXkM9xhuTLEmEM1ZXcDZxWhmBcf4z2tK25K55UyPN
```

**Derive child public key - from parent xpub**
```
#Non-Hardened index
index = 0
child_xpub = root_xpub.derive_child_seed(index)
print(child_xpub)

Child - Depth: 1 - Index: 0 - Private key: False - xpub68NmfCmNawadFZGeXCmkYpbK8WFb36Zj2fyGq6emhvyPcqMHht7x6EejgBntyBbadoXWLKhF5VtkJmwKFVB8JqkaoFz3EUAoeaEZyk2X4GJ

#Hardened index is not possible. This raises an exception
ValueError: Cannot use hardened index!
```

**Derive child public key - from child xprv**
```
#Index = 2**31 (Hardened 0)
child_xpub = child_xprv.derive_pubkey()
print(child_xpub)

Child - Depth: 1 - Index: 2147483648 - Private key: False - xpub68NmfCmWvc7bQwU59L4iDSgTtt8mdMejHWv8gP9uYTtdq9B5hvf1uPPzBc4JxAnsdrp71WEqRaSoyQDAWo6BVsArKpwk1jMgLUyws58y5RG
```

**Derive private key based on provided derivation path**
```
#The path here is: m/0'/0/5/1'
PATH = [
    (0, True),
    (0, False),
    (5, False),
    (1, True)
]
child_xprv_path = root_xprv.derive_path(PATH)
print(child_xprv_path)

Child - Depth: 4 - Index: 2147483649 - Private key: True - xprvA1rZHn97tbBydHE9Q5RbjRDtuMtioLsFHrbLj2qbvgV3NScVRqqDVpC5a6bckhjd3gU59kbm172qNJ17gHphc7rvaCfssccwZKKH551WefN
```

**Derive public key based on provided derivation path**
```
#The path here is: M/0'/0/5/1'
child_xpub_path = child_xprv_path.derive_pubkey()
print(child_xpub_path)

Child - Depth: 4 - Index: 2147483649 - Private key: False - xpub6EquhHg1ixkGqmJcW6xc6ZAdTPjDCob6f5WwXRFDV222FEwdyP9U3cWZRMttzA5vVVSSgezjjbfhFxifr9pMZjX2zbW3Cnhj2PKu2QJYpDj
```

## Tests
```
pytest --verbose bip32_test.py
```

## Acknowledgments and Resources

* [Programming Bitcoin](https://programmingbitcoin.com) by [Jimmy Song](https://github.com/jimmysong/programmingbitcoin)
