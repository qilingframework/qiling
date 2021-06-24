#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 


from eth_typing.evm import Address
from qiling.const import *
from qiling.engine.evm.vm.evm import QlEVMEmulator
from qiling.engine.evm.abi import QlEVMABI


class QlArchEVM:
    def __init__(self, ql) -> None:
        self.ql = ql
        self.emu = QlEVMEmulator(self.ql)
        self.abi = QlEVMABI()

    def create_account(self, address:Address=None, balance:int=None):
        return self.emu.create_account(address, balance)

    def create_message(self,
                      sender: Address,
                      to: Address = b'',
                      data: bytes = b'',                      
                      value: int = 0,
                      gas: int = 3000000,
                      gas_price: int = 1,
                      origin: Address = None,
                      code: bytes = b'',
                      code_address: Address = None,
                      contract_address: Address = None):
        return self.emu.create_message(sender, 
                                       to, 
                                       data, 
                                       value,
                                       gas,
                                       gas_price,
                                       origin,
                                       code,
                                       code_address,
                                       contract_address
                                      )

    def run(self, msg):
        return self.emu.vm.execute_message(msg)
