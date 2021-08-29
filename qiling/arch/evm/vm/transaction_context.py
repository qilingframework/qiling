#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import itertools

from eth_typing import Address

from ..abc import TransactionContextAPI
from ..validation import (
    validate_canonical_address,
    validate_uint256,
)


class BaseTransactionContext(TransactionContextAPI):
    __slots__ = ['_gas_price', '_origin', '_log_counter']

    def __init__(self, gas_price: int, origin: Address) -> None:
        validate_uint256(gas_price, title="TransactionContext.gas_price")
        self._gas_price = gas_price
        validate_canonical_address(origin, title="TransactionContext.origin")
        self._origin = origin
        self._log_counter = itertools.count()

    def get_next_log_counter(self) -> int:
        return next(self._log_counter)

    @property
    def gas_price(self) -> int:
        return self._gas_price

    @property
    def origin(self) -> Address:
        return self._origin
