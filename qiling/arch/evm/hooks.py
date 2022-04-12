#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

import types
from typing import MutableMapping, MutableSequence

from qiling.core_hooks_types import Hook, HookAddr, HookIntr, HookRet

class QlArchEVMHooks:
    def __init__(self) -> None:
        self.hook_code_list: MutableSequence[Hook] = []
        self.hook_insn_list: MutableSequence[HookIntr] = []
        self.hook_addr_dict: MutableMapping[int, MutableSequence[HookAddr]] = {}

evm_hooks_info = QlArchEVMHooks()


def evm_hook_code(ql, callback, user_data=None, begin=1, end=0, *args):
    h = Hook(callback, user_data, begin, end)
    evm_hooks_info.hook_code_list.append(h)

    return HookRet(ql, 'HOOK_CODE', h)

def evm_hook_insn(ql, callback, intno, user_data=None, begin=1, end=0):
    h = HookIntr(callback, intno, user_data)
    evm_hooks_info.hook_insn_list.append(h)

    return HookRet(ql, 'HOOK_INSN', h)

def evm_hook_address(ql, callback, address, user_data):
    h = HookAddr(callback, address, user_data)

    if address not in evm_hooks_info.hook_addr_dict:
        evm_hooks_info.hook_addr_dict[address] = []

    evm_hooks_info.hook_addr_dict[address].append(h)

    return HookRet(ql, 'HOOK_ADDR', h)

def evm_hook_del(hook_type, h):
    if hook_type == "HOOK_CODE":
        evm_hooks_info.hook_code_list.remove(h)

    elif hook_type == "HOOK_INSN":
        evm_hooks_info.hook_insn_list.remove(h)

    elif hook_type == 'HOOK_ADDR':
        if h.addr in evm_hooks_info.hook_addr_dict:
            hooks_list = evm_hooks_info.hook_addr_dict[h.addr]

            if h in hooks_list:
                hooks_list.remove(h)

                if not hooks_list:
                    del evm_hooks_info.hook_addr_dict[h.addr]

def monkeypath_core_hooks(ql):
    """Monkeypath core hooks for evm
    """

    def __evm_hook_code(self, callback, user_data=None, begin=1, end=0):
        return evm_hook_code(self, callback, user_data, begin, end)

    def __evm_hook_address(self, callback, address, user_data=None):
        return evm_hook_address(self, callback, address, user_data)

    def __evm_hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
        return evm_hook_insn(self, callback, arg1, user_data, begin, end)

    def __evm_hook_del(self, *args):
        if len(args) != 1 and len(args) != 2:
            return

        if isinstance(args[0], HookRet):
            args[0].remove()
            return

        return evm_hook_del(*args)

    ql.hook_code    = types.MethodType(__evm_hook_code, ql)
    ql.hook_address = types.MethodType(__evm_hook_address, ql)
    ql.hook_insn    = types.MethodType(__evm_hook_insn, ql)
    ql.hook_del     = types.MethodType(__evm_hook_del, ql)
