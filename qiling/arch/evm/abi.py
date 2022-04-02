#!/usr/bin/env python3

from eth_abi import encode_abi, decode_abi, encode_single, decode_single
from eth_utils.abi import collapse_if_tuple
from eth_utils import function_signature_to_4byte_selector, function_abi_to_4byte_selector, decode_hex, encode_hex
from .vm.utils import bytecode_to_bytes


class QlArchEVMABI:
    @staticmethod
    def convert(datatypes:list, values:list) -> str:
        return QlArchEVMABI.encode_params(datatypes, values)

    @staticmethod
    def encode_params(datatypes:list, values:list) -> str:
        for idx, item in enumerate(datatypes):
            if item == 'address':
                if isinstance(values[idx], int):
                    values[idx] = bytecode_to_bytes(hex(values[idx]))
                elif isinstance(values[idx], str):
                    values[idx] = bytecode_to_bytes(values[idx])
        
        return encode_abi(datatypes, values).hex()

    @staticmethod
    def decode_params(datatypes:list, value:str) -> list:
        return decode_abi(datatypes, value)

    @staticmethod
    def encode_function_call(abi:str, params:list) -> str:
        abi = abi.replace(' ', '')
        if '(' not in abi or ')' not in abi:
            raise ValueError(f'Function signature must contain "(" and ")": {abi}')
        signature = function_signature_to_4byte_selector(abi)
        inputs = abi[abi.index('('):]
        params = encode_single(inputs, params)
        return encode_hex(signature + params)

    @staticmethod
    def encode_function_call_abi(abi:dict, params:list) -> str:
        signature = function_abi_to_4byte_selector(abi)
        inputs = ",".join(
            [collapse_if_tuple(abi_input) for abi_input in abi.get("inputs", [])]
        )
        params = encode_single(f"({inputs})", params)
        return encode_hex(signature + params)