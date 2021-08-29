#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import re


def bytecode_to_bytes(bytecode):
    if str(bytecode).startswith("0x"):
        bytecode = str(bytecode)[2:]

    try:
        bytecode = bytes.fromhex(bytecode)
    # already bytes or bytearray
    except TypeError:
        pass
    return bytecode

def load_code_detector(bytecode):
    '''Check for presence of runtime code
    '''
    if isinstance(bytecode, bytes):
        bytecode = bytecode.hex()
    result = list(re.finditer('60.{2}604052', bytecode))
    load_bytecode = ''
    rtcode_auxdata = bytecode
    if len(result) > 1:
        position = result[1].start()
        # self.ql.dprint(D_INFO, "[+] Runtime code detected")
        load_bytecode = bytecode[:position]
        rtcode_auxdata = bytecode[position:]
    return load_bytecode, rtcode_auxdata

def runtime_code_detector(bytecode):
    '''Check for presence of Swarm hash at the end of bytecode
        https://github.com/ethereum/wiki/wiki/Swarm-Hash
    '''
    if isinstance(bytecode, bytes):
        bytecode = bytecode.hex()
    result = list(re.finditer('a165627a7a7230.*0029', bytecode))
    # bzzr == 0x65627a7a72
    runtime_code = bytecode
    aux_data = ''
    constructor_args = ''

    if len(result) > 0:
        auxdata_start = result[-1].start()
        auxdata_end = result[-1].end()
        if auxdata_start > 0:
            # self.ql.dprint(D_INFO, "[+] Swarm hash detected in bytecode")
            aux_data = bytecode[auxdata_start:auxdata_end]
            # self.ql.dprint(D_INFO, "[+] Swarm hash value: 0x%s"%self.swarm_hash)

            # there is possibly constructor argument
            # if there is swarm storage
            if auxdata_end != len(bytecode):
                constructor_args = bytecode[auxdata_end:]
            #     self.ql.dprint(D_INFO, "[+] Constructor arguments detected in bytecode")
            #     self.ql.dprint(D_INFO, "[+] Constructor arguments removed from bytecode")
            # self.ql.dprint(D_INFO, "[+] Swarm hash removed from bytecode")
            runtime_code = bytecode[:auxdata_start]
            aux_data = bytecode[auxdata_start:auxdata_end]
    return runtime_code, aux_data, constructor_args

def analysis_bytecode(bytecode:bytes):
    load_bytecode, rtcode_auxdata = load_code_detector(bytecode)
    runtime_code, aux_data, constructor_args = runtime_code_detector(rtcode_auxdata)
    return load_bytecode, runtime_code, aux_data, constructor_args

def padding_txdata(tx_data:str):
    if tx_data[:2] == '0x':
        tx_data = tx_data[2:]
    sign = tx_data[:8]
    args = tx_data[8:]
    last_argu_len = len(args) % 64

    if last_argu_len != 0:
        other_args = args[:-last_argu_len]
        last_argu = args[-last_argu_len:].rjust(64, '0')

    return sign + other_args + last_argu


