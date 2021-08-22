#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from .host import QlArchEVMHostInfo
from .. import constants as eth_constants
from .. import constants


MAINNET_GENESIS_HOST = QlArchEVMHostInfo(
    coinbase=constants.ZERO_ADDRESS,
    timestamp=100*10**18,
    block_number=0,
    difficulty=eth_constants.GENESIS_DIFFICULTY,
    gas_limit=eth_constants.GENESIS_GAS_LIMIT,    
    prev_hashes=constants.ZERO_HASH32,
    chain_id=1,
)
