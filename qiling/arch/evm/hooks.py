#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework

import types
from enum import IntEnum
from typing import MutableMapping, MutableSequence

from qiling.core_hooks_types import Hook, HookAddr, HookIntr, HookRet

class EVM_HOOK(IntEnum):
    CODE = (1 << 0)
    ADDR = (1 << 1)
    INSN = (1 << 2)

class QlArchEVMHooks:
    def __init__(self) -> None:
        self.hook_code_list: MutableSequence[Hook] = []
        self.hook_insn_list: MutableSequence[HookIntr] = []
        self.hook_addr_dict: MutableMapping[int, MutableSequence[HookAddr]] = {}

evm_hooks_info = QlArchEVMHooks()

def __evm_hook_code(ql, callback, user_data=None, begin=1, end=0):
    h = Hook(callback, user_data, begin, end)
    evm_hooks_info.hook_code_list.append(h)

    return HookRet(ql, EVM_HOOK.CODE, h)

def __evm_hook_insn(ql, callback, intno, user_data=None, begin=1, end=0):
    h = HookIntr(callback, intno, user_data)
    evm_hooks_info.hook_insn_list.append(h)

    return HookRet(ql, EVM_HOOK.INSN, h)

def __evm_hook_address(ql, callback, address, user_data=None):
    h = HookAddr(callback, address, user_data)

    if address not in evm_hooks_info.hook_addr_dict:
        evm_hooks_info.hook_addr_dict[address] = []

    evm_hooks_info.hook_addr_dict[address].append(h)

    return HookRet(ql, EVM_HOOK.ADDR, h)

def __evm_hook_del(ql, hret):
    h = hret.obj
    hook_type = hret.type

    if hook_type == EVM_HOOK.CODE:
        evm_hooks_info.hook_code_list.remove(h)

    elif hook_type == EVM_HOOK.INSN:
        evm_hooks_info.hook_insn_list.remove(h)

    elif hook_type == EVM_HOOK.ADDR:
        if h.addr in evm_hooks_info.hook_addr_dict:
            hooks_list = evm_hooks_info.hook_addr_dict[h.addr]

            if h in hooks_list:
                hooks_list.remove(h)

                if not hooks_list:
                    del evm_hooks_info.hook_addr_dict[h.addr]

def monkeypatch_core_hooks(ql):
    """Monkeypatch core hooks for evm
    """

    ql.hook_code    = types.MethodType(__evm_hook_code, ql)
    ql.hook_address = types.MethodType(__evm_hook_address, ql)
    ql.hook_insn    = types.MethodType(__evm_hook_insn, ql)
    ql.hook_del     = types.MethodType(__evm_hook_del, ql)
