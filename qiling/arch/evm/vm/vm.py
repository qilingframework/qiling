#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

# from ....core import Qiling
from .state import BaseState
from .message import Message
from .defaultconf import MAINNET_GENESIS_HOST
from .execution_context import ExecutionContext
from .host import QlArchEVMHostInfo
from .._utils.datatypes import Configurable
from eth_typing import Address


class BaseVM(Configurable):
    _state_class = None
    _state = None
    _block = None

    def __init__(self, ql) -> None:
        self.ql = ql
        self.transaction_context = None

    #
    # State
    #

    @property
    def state(self) -> BaseState:
        if self._state is None:
            self._state = self.build_state(self.ql)
        return self._state

    @classmethod
    def build_state(cls, ql, HostInfo:QlArchEVMHostInfo=MAINNET_GENESIS_HOST):
        execution_context = cls.create_execution_context(HostInfo)
        return cls.get_state_class()(ql, execution_context)

    @classmethod
    def get_state_class(cls):
        if cls._state_class is None:
            raise AttributeError("No `_state_class` has been set for this VM")

        return cls._state_class

    #
    # Execution
    #

    @classmethod
    def create_execution_context(cls, HostInfo:QlArchEVMHostInfo=MAINNET_GENESIS_HOST):
        return ExecutionContext(
            coinbase=HostInfo.coinbase,
            timestamp=HostInfo.timestamp,
            block_number=HostInfo.block_number,
            difficulty=HostInfo.difficulty,
            gas_limit=HostInfo.gas_limit,
            prev_hashes=HostInfo.prev_hashes,
            chain_id=HostInfo.chain_id,
        )

    #
    # Message
    #

    def build_message(self,
                      origin: Address,
                      gas_price: int,
                      gas: int,
                      to: Address,
                      sender: Address,
                      value: int,
                      data: bytes,
                      code: bytes,
                      code_address: Address = None,
                      contract_address: Address = None
                      ):
        return self.state.get_transaction_executor().build_evm_message(origin, gas_price, gas, to, sender, value, data, code, code_address, contract_address)

    @classmethod
    def apply_create_message(
            cls,
            state,
            message,
            transaction_context):
        ...

    @classmethod
    def apply_message(
            cls,
            state,
            message,
            transaction_context):
        ...

    def execute_message(self, message:Message):
        return self.state.get_transaction_executor()(message)

    def emu_start(self, computation):
        pass

    def emu_stop(self):
        pass
