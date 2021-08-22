#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from ..hooks import QlArchEVMHooks


class EVMInsn:
    def __init__(self, pc, byte, mnemonic, imm_op, hook_info:QlArchEVMHooks) -> None:
        self.pc = pc
        self.byte = byte
        self.mnemonic = mnemonic
        self.imm_op = imm_op
        self.hook_info = hook_info
        self.callback_list = QlArchEVMHooks()
        if mnemonic[:4] == 'PUSH':
            self.imm_size = int(mnemonic[4:])
        else:
            self.imm_size = 0
    
    @property
    def is_hook_code(self):
        flag = False
        for i in self.hook_info.hook_code_list:
            if i.end > self.pc >= i.begin or (i.begin==1 and i.end==0):
                self.callback_list.hook_code_list.append(i)
                flag = True
        self.callback_list.hook_code_list = list(dict.fromkeys(self.callback_list.hook_code_list))
        return True if flag else False

    @property
    def is_hook_insn(self):
        flag = False
        for i in self.hook_info.hook_insn_list:
            if self.mnemonic == i.intno:
                self.callback_list.hook_insn_list.append(i)
                flag = True
        self.callback_list.hook_insn_list = list(dict.fromkeys(self.callback_list.hook_insn_list))
        return True if flag else False
    
    @property
    def is_hook_addr(self):
        flag = False
        for k, v in self.hook_info.hook_addr_dict.items():
            if self.pc == k:
                self.callback_list.hook_addr_dict[k] = v
                flag = True
        
        return True if flag else False

