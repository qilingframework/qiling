#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import rlp

from eth_hash.auto import keccak
from eth_typing import Address

from .._utils.numeric import (
    int_to_bytes32,
)


def force_bytes_to_address(value: bytes) -> Address:
    trimmed_value = value[-20:]
    padded_value = trimmed_value.rjust(20, b'\x00')
    return Address(padded_value)


def generate_contract_address(address: Address, nonce: int) -> Address:
    return force_bytes_to_address(keccak(rlp.encode([address, nonce])))


def generate_safe_contract_address(address: Address,
                                   salt: int,
                                   call_data: bytes) -> Address:
    return force_bytes_to_address(
        keccak(b'\xff' + address + int_to_bytes32(salt) + keccak(call_data))
    )
