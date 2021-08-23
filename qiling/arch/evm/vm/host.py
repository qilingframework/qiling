#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

class QlArchEVMHostInfo:
    def __init__(self, coinbase, timestamp, block_number, difficulty, gas_limit, prev_hashes, chain_id) -> None:
        self.coinbase = coinbase
        self.timestamp = timestamp
        self.block_number = block_number
        self.difficulty = difficulty
        self.gas_limit = gas_limit
        self.prev_hashes = prev_hashes
        self.chain_id = chain_id

