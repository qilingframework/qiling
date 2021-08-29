#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework


from qiling.core_hooks_types import Hook, HookAddr, HookIntr, HookRet


class QlArchEVMHooks:
    def __init__(self) -> None:
        super().__init__()
        self.hook_code_list = []
        self.hook_insn_list = []
        self.hook_addr_dict = {}

evm_hooks_info = QlArchEVMHooks()


def _ql_evm_hook(ql, hook_type, h, *args):
    base_type = [
        "HOOK_CODE",
        "HOOK_INSN",
        "HOOK_ADDR"
    ]

    if hook_type in base_type:
        if hook_type in ["HOOK_CODE"]:
            evm_hooks_info.hook_code_list.append(h)
        elif hook_type in ["HOOK_INSN"]:
            evm_hooks_info.hook_insn_list.append(h)
        elif hook_type in ["HOOK_ADDR"]:
            address = args[0]

            if address not in evm_hooks_info.hook_addr_dict.keys():
                evm_hooks_info.hook_addr_dict[address] = []
            
            evm_hooks_info.hook_addr_dict[address].append(h)

def ql_evm_hooks(ql, hook_type, callback, user_data=None, begin=1, end=0, *args):
    h = Hook(callback, user_data, begin, end)
    _ql_evm_hook(ql, hook_type, h, *args)
    return HookRet(ql, hook_type, h)

def evm_hook_insn(ql, hook_type, callback, intno, user_data=None, begin=1, end=0):
    h = HookIntr(callback, intno, user_data)
    _ql_evm_hook(ql, hook_type, h)
    return HookRet(ql, hook_type, h)

def evm_hook_address(ql, hook_type, h, address):
    _ql_evm_hook(ql, hook_type, h, address)
    return HookRet(ql, hook_type, h)

def evm_hook_del(hook_type, h):
    base_type = [
        "HOOK_CODE",
        "HOOK_INSN",
        "HOOK_ADDR"
    ]

    if isinstance(h, HookAddr):
        if h.addr in evm_hooks_info.hook_addr_dict.keys():
            if h in evm_hooks_info.hook_addr_dict[h.addr]:
                evm_hooks_info.hook_addr_dict[h.addr].remove(h)
            if len(evm_hooks_info.hook_addr_dict[h.addr]) == 0:
                del evm_hooks_info.hook_addr_dict[h.addr]

    if hook_type in base_type:
        if hook_type in ["HOOK_CODE"]:
            evm_hooks_info.hook_code_list.remove(h)
        elif hook_type in ["HOOK_INSN"]:
            evm_hooks_info.hook_insn_list.remove(h)