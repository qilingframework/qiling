#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys
sys.path.append("..")

import random
from eth_typing.evm import Address
from .forks import *
from .. import constants
from .vm import BaseVM
from .utils import bytecode_to_bytes, runtime_code_detector
from ..abi import QlArchEVMABI

# Code name	                    Release date	Release block   Opcode supported    

# Frontier                      2015-07-30	    0               Yes                 
# Ice Age	                    2015-09-08	    200,000         -                   
# Homestead	                    2016-03-15	    1,150,000       Yes                 
# DAO Fork (unplanned)	        2016-07-20	    1,920,000       -                   
# Tangerine Whistle (unplanned)	2016-10-18	    2,463,000       Yes                   
# Spurious Dragon	            2016-11-23	    2,675,000       Yes                 
# Byzantium	                    2017-10-16	    4,370,000       Yes                 
# Constantinople	            2019-02-28	    7,280,000       Yes                 
# Petersburg (unplanned)	    2019-02-28	    7,280,000       Yes                 
# Istanbul	                    2019-12-08	    9,069,000       Yes                   
# Muir Glacier	                2020-01-01	    9,200,000       Yes                 
# Berlin         	            TBD	            TBD             Yes                 


father_VMs = {
    constants.FRONTIER_FORK:FrontierVM,
    constants.HOMESTEAD_FORK:HomesteadVM,
    constants.TANGERINE_WHISTLE_FORK:TangerineWhistleVM,
    constants.SPURIOUS_DRAGON_FORK:SpuriousDragonVM,
    constants.BYZANTIUM_FORK:ByzantiumVM,
    constants.CONSTANTINOPLE_FORK:ConstantinopleVM,
    constants.PETERSBURG_FORK:PetersburgVM,
    constants.ISTANBUL_FORK:IstanbulVM,
    constants.MUIR_GLACIER_OFORK:MuirGlacierVM,
    constants.BERLIN_FORK:BerlinVM
}


class QlArchEVMEmulator:
    def __init__(self, ql, fork_name=constants.BERLIN_FORK) -> None:
        self.ql = ql
        self.abi = QlArchEVMABI()
        try:
            father_VM = father_VMs[fork_name]
            vm = type('QlArchEVM', (father_VM,), dict())
        except:
            raise ValueError('Fork name error')

        self.vm:BaseVM = vm(self.ql)

    def create_account(self, address:Address=None, balance:int=None):
        if address is None:
            address = random.randint(100, pow(2, 160)).to_bytes(20, 'little')
        self.vm.state.touch_account(address)
        if balance is not None:
            self.vm.state.set_balance(address, balance)
            
        return address

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
        if isinstance(data, str):
            data = bytecode_to_bytes(data)
        if isinstance(code, str):
            code = bytecode_to_bytes(code)
        if to != b'' and code == b'':
            contract_code = self.vm.state.get_code(to)
            code, _, _ = runtime_code_detector(contract_code)
            code = bytecode_to_bytes(code)

        return self.vm.build_message(origin, gas_price, gas, to, sender, value, data, code, code_address, contract_address)
