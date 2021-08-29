#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import (
    Iterable,
)

from eth_typing import (
    Address,
    BlockNumber,
    Hash32,
)

from ..abc import ExecutionContextAPI
from .._utils.generator import CachedIterable


class ExecutionContext(ExecutionContextAPI):
    _coinbase = None
    _timestamp = None
    _number = None
    _difficulty = None
    _gas_limit = None
    _prev_hashes = None
    _chain_id = None

    def __init__(
            self,
            coinbase: Address,
            timestamp: int,
            block_number: BlockNumber,
            difficulty: int,
            gas_limit: int,
            prev_hashes: Iterable[Hash32],
            chain_id: int) -> None:
        self._coinbase = coinbase
        self._timestamp = timestamp
        self._block_number = block_number
        self._difficulty = difficulty
        self._gas_limit = gas_limit
        self._prev_hashes = CachedIterable(prev_hashes)
        self._chain_id = chain_id

    @property
    def coinbase(self) -> Address:
        return self._coinbase

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @property
    def block_number(self) -> BlockNumber:
        return self._block_number

    @property
    def difficulty(self) -> int:
        return self._difficulty

    @property
    def gas_limit(self) -> int:
        return self._gas_limit

    @property
    def prev_hashes(self) -> Iterable[Hash32]:
        return self._prev_hashes

    @property
    def chain_id(self) -> int:
        return self._chain_id
