#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import functools

from typing import (
    Any,
    Callable,
    Type,
    TypeVar,
)

from eth_utils import (
    ExtendedDebugLogger,
    get_extended_debug_logger,
)

from .._utils.datatypes import Configurable
from ..abc import (
    ComputationAPI,
    OpcodeAPI,
)


T = TypeVar('T')


class Opcode(Configurable, OpcodeAPI):
    mnemonic: str = None
    gas_cost: int = None

    def __init__(self) -> None:
        if self.mnemonic is None:
            raise TypeError(f"Opcode class {type(self)} missing opcode mnemonic")
        if self.gas_cost is None:
            raise TypeError(f"Opcode class {type(self)} missing opcode gas_cost")

    @property
    def logger(self) -> ExtendedDebugLogger:
        return get_extended_debug_logger(f'eth.vm.logic.{self.mnemonic}')

    @classmethod
    def as_opcode(cls: Type[T],
                  logic_fn: Callable[..., Any],
                  mnemonic: str,
                  gas_cost: int) -> T:
        if gas_cost:
            @functools.wraps(logic_fn)
            def wrapped_logic_fn(computation: ComputationAPI) -> Any:
                """
                Wrapper functionf or the logic function which consumes the base
                opcode gas cost prior to execution.
                """
                computation.consume_gas(
                    gas_cost,
                    mnemonic,
                )
                return logic_fn(computation)
        else:
            wrapped_logic_fn = logic_fn

        props = {
            '__call__': staticmethod(wrapped_logic_fn),
            'mnemonic': mnemonic,
            'gas_cost': gas_cost,
        }
        opcode_cls = type(f"opcode:{mnemonic}", (cls,), props)
        return opcode_cls()

    def __copy__(self) -> 'Opcode':
        return type(self)()

    def __deepcopy__(self, memo: Any) -> 'Opcode':
        return type(self)()


as_opcode = Opcode.as_opcode
