#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

from .instruction import EVMInsn
from .utils import bytecode_to_bytes
from .opcodes import opcodes


class EVMDisasm:
    def __init__(self) -> None:
        self.current_mnemonic = None
        self.current_pc = None
        self.current_byte = None
        self.current_imm_op = ''

    def disasm(self, code:bytes, hook_info):
        result = {}
        h = ''
        pushcnt = 0
        pc = 0
        is_push = False
        for item in code:
            if pushcnt > 0:
                h += hex(item)[2:].rjust(2, '0')
                pushcnt -= 1
                if pushcnt == 0:
                    self.current_imm_op = '0x'+h
                    result[self.current_pc] = EVMInsn(self.current_pc, self.current_byte, self.current_mnemonic, self.current_imm_op, hook_info)
                    h = ''
                    is_push = False
            elif item in opcodes:
                self.current_mnemonic = opcodes[item].mnemonic
                self.current_pc = pc
                self.current_byte = hex(item)
                if 0x60 <= item <= 0x7f:
                    is_push = True
                    pushcnt = item - 0x60 + 1
                
                if not is_push:
                    result[self.current_pc] = EVMInsn(self.current_pc, self.current_byte, self.current_mnemonic, '', hook_info)
            else:
                self.current_pc = pc
                self.current_byte = hex(item)
                result[self.current_pc] = EVMInsn(self.current_pc, self.current_byte, 'Invalid', None, hook_info)
            pc += 1
    #           raise Exception("Invalid opcode: " + str(item))
        if h:
            raise Exception("Not enough push bytes: " + h)
        return result


if __name__ == '__main__':
    hexcode='0x600035601c52'
    code = bytecode_to_bytes(hexcode)
    ret = EVMDisasm().disasm(code)
    for k, v in ret.items():
        print(v.pc, v.byte, v.mnemonic, v.imm_op)