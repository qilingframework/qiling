#!/usr/bin/env python3

from eth_abi import encode_abi
from .vm.utils import bytecode_to_bytes


class QlArchEVMABI:
    @staticmethod
    def convert(datatypes:list, values:list) -> str:
        for idx, item in enumerate(datatypes):
            if item == 'address':
                if isinstance(values[idx], int):
                    values[idx] = bytecode_to_bytes(hex(values[idx]))
                elif isinstance(values[idx], str):
                    values[idx] = bytecode_to_bytes(values[idx])
        
        return encode_abi(datatypes, values).hex()