#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

##############################################
# These are part of the core.py Qiling class #
# handling hooks                             #
##############################################

from typing import Callable, MutableMapping, MutableSequence

from unicorn import Uc
from unicorn.unicorn_const import *

from .core_hooks_types import Hook, HookAddr, HookIntr, HookRet
from .utils import catch_KeyboardInterrupt
from .const import QL_HOOK_BLOCK
from .exception import QlErrorCoreHook

# Don't assume self is Qiling.
class QlCoreHooks:
    def __init__(self, uc: Uc):
        self._h_uc = uc

        self._hook: MutableMapping[int, MutableSequence[Hook]] = {}
        self._hook_fuc: MutableMapping[int, int] = {}

        self._insn_hook: MutableMapping[int, MutableSequence[Hook]] = {}
        self._insn_hook_fuc: MutableMapping[int, int] = {}

        self._addr_hook: MutableMapping[int, MutableSequence[HookAddr]] = {}
        self._addr_hook_fuc: MutableMapping[int, int] = {}


    ########################
    # Callback definitions #
    ########################
    def _hook_intr_cb(self, uc: Uc, intno: int, pack_data) -> None:
        ql, hook_type = pack_data
        handled = False

        if hook_type in self._hook:
            # the hooks list might change from within a hook method.
            # iterating over a copy of the list would be a safer practice
            hooks_list = self._hook[hook_type]

            for hook in hooks_list:
                ql.log.debug(f'Received interrupt: {intno:#x}')

                if hook.check(intno):
                    handled = True
                    ret = hook.call(ql, intno)

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break

        if not handled:
            raise QlErrorCoreHook("_hook_intr_cb : not handled")


    def _hook_insn_cb(self, uc: Uc, *args):
        ql, hook_type = args[-1]
        retval = None

        if hook_type in self._insn_hook:
            hooks_list = self._insn_hook[hook_type]

            for hook in hooks_list:
                if hook.bound_check(ql.reg.arch_pc):
                    ret = hook.call(ql, *args[:-1])

                    if type(ret) is tuple:
                        ret, retval = ret

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break

        # use the last return value received
        return retval


    def _hook_trace_cb(self, uc: Uc, addr: int, size: int, pack_data) -> None:
        ql, hook_type = pack_data

        if hook_type in self._hook:
            hooks_list = self._hook[hook_type]

            for hook in hooks_list:
                if hook.bound_check(ql.reg.arch_pc):
                    ret = hook.call(ql, addr, size)

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break


    def _hook_mem_cb(self, uc: Uc, access: int, addr: int, size: int, value: int, pack_data):
        ql, hook_type = pack_data
        handled = False

        if hook_type in self._hook:
            hooks_list = self._hook[hook_type]

            for hook in hooks_list:
                if hook.bound_check(addr, size):
                    handled = True
                    ret = hook.call(ql, access, addr, size, value)

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break

        if not handled and hook_type & (UC_HOOK_MEM_UNMAPPED | UC_HOOK_MEM_PROT):
            raise QlErrorCoreHook("_hook_mem_cb : not handled")

        return True


    def _hook_insn_invalid_cb(self, uc: Uc, pack_data) -> None:
        ql, hook_type = pack_data
        handled = False

        if hook_type in self._hook:
            hooks_list = self._hook[hook_type]

            for hook in hooks_list:
                handled = True
                ret = hook.call(ql)

                if type(ret) is int and ret & QL_HOOK_BLOCK:
                    break

        if not handled:
            raise QlErrorCoreHook("_hook_insn_invalid_cb : not handled")


    def _hook_addr_cb(self, uc: Uc, addr: int, size: int, pack_data):
        ql = pack_data

        if addr in self._addr_hook:
            hooks_list = self._addr_hook[addr]

            for hook in hooks_list:
                ret = hook.call(ql)

                if type(ret) is int and ret & QL_HOOK_BLOCK:
                    break

    ###############
    # Class Hooks #
    ###############
    def _ql_hook_internal(self, hook_type, callback, user_data=None, *args) -> int:
        _callback = (catch_KeyboardInterrupt(self))(callback)
        # pack user_data & callback for wrapper _callback
        return self._h_uc.hook_add(hook_type, _callback, (self, user_data), 1, 0, *args)


    def _ql_hook_addr_internal(self, callback: Callable, address: int) -> int:
        _callback = (catch_KeyboardInterrupt(self))(callback)
        # pack user_data & callback for wrapper _callback
        return self._h_uc.hook_add(UC_HOOK_CODE, _callback, self, address, address)


    def _ql_hook(self, hook_type: int, h: Hook, *args) -> None:

        def __handle_intr(t: int) -> None:
            if t not in self._hook_fuc:
                self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_intr_cb, t)

            if t not in self._hook:
                self._hook[t] = []

            self._hook[t].append(h)

        def __handle_insn(t: int) -> None:
            ins_t = args[0]

            if ins_t not in self._insn_hook_fuc:
                self._insn_hook_fuc[ins_t] = self._ql_hook_internal(t, self._hook_insn_cb, ins_t, *args)

            if ins_t not in self._insn_hook:
                self._insn_hook[ins_t] = []

            self._insn_hook[ins_t].append(h)

        def __handle_trace(t: int) -> None:
            if t not in self._hook_fuc:
                self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_trace_cb, t)

            if t not in self._hook:
                self._hook[t] = []

            self._hook[t].append(h)

        def __handle_mem(t: int) -> None:
            if t not in self._hook_fuc:
                self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_mem_cb, t)

            if t not in self._hook:
                self._hook[t] = []

            self._hook[t].append(h)

        def __handle_invalid_insn(t: int) -> None:
            if t not in self._hook_fuc:
                self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_insn_invalid_cb, t)

            if t not in self._hook:
                self._hook[t] = []

            self._hook[t].append(h)

        type_handlers = (
            (UC_HOOK_INTR,               __handle_intr),
            (UC_HOOK_INSN,               __handle_insn),
            (UC_HOOK_CODE,               __handle_trace),
            (UC_HOOK_BLOCK,              __handle_trace),
            (UC_HOOK_MEM_READ_UNMAPPED,  __handle_mem),
            (UC_HOOK_MEM_WRITE_UNMAPPED, __handle_mem),
            (UC_HOOK_MEM_FETCH_UNMAPPED, __handle_mem),
            (UC_HOOK_MEM_READ_PROT,      __handle_mem),
            (UC_HOOK_MEM_WRITE_PROT,     __handle_mem),
            (UC_HOOK_MEM_FETCH_PROT,     __handle_mem),
            (UC_HOOK_MEM_READ,           __handle_mem),
            (UC_HOOK_MEM_WRITE,          __handle_mem),
            (UC_HOOK_MEM_FETCH,          __handle_mem),
            (UC_HOOK_MEM_READ_AFTER,     __handle_mem),
            (UC_HOOK_INSN_INVALID,       __handle_invalid_insn)
        )

        for t, handler in type_handlers:
            if hook_type & t:
                handler(t)


    def ql_hook(self, hook_type: int, callback: Callable, user_data=None, begin=1, end=0, *args) -> HookRet:
        hook = Hook(callback, user_data, begin, end)
        self._ql_hook(hook_type, hook, *args)

        return HookRet(self, hook_type, hook)


    def hook_code(self, callback, user_data=None, begin=1, end=0):
        if self.interpreter:
            from .arch.evm.hooks import ql_evm_hooks
            return ql_evm_hooks(self, 'HOOK_CODE', callback, user_data, begin, end)

        return self.ql_hook(UC_HOOK_CODE, callback, user_data, begin, end)


    def hook_intr(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_INTR, callback, user_data, begin, end)


    def hook_block(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_BLOCK, callback, user_data, begin, end)


    def hook_mem_unmapped(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_UNMAPPED, callback, user_data, begin, end)


    def hook_mem_read_invalid(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_READ_INVALID, callback, user_data, begin, end)


    def hook_mem_write_invalid(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_WRITE_INVALID, callback, user_data, begin, end)


    def hook_mem_fetch_invalid(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_FETCH_INVALID, callback, user_data, begin, end)


    def hook_mem_valid(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_VALID, callback, user_data, begin, end)


    def hook_mem_invalid(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_INVALID, callback, user_data, begin, end)


    # a convenient API to set callback for a single address
    def hook_address(self, callback, address, user_data=None):
        hook = HookAddr(callback, address, user_data)

        if self.interpreter:
            from .arch.evm.hooks import evm_hook_address
            return evm_hook_address(self, 'HOOK_ADDR', hook, address)

        if address not in self._addr_hook_fuc:
            self._addr_hook_fuc[address] = self._ql_hook_addr_internal(self._hook_addr_cb, address)

        if address not in self._addr_hook:
            self._addr_hook[address] = []

        self._addr_hook[address].append(hook)

        return HookRet(self, None, hook)


    def get_hook_address(self, address):
        return self._addr_hook.get(address, [])


    def hook_intno(self, callback, intno, user_data=None):
        hook = HookIntr(callback, intno, user_data)
        self._ql_hook(UC_HOOK_INTR, hook)

        return HookRet(self, UC_HOOK_INTR, hook)


    def hook_mem_read(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_READ, callback, user_data, begin, end)


    def hook_mem_write(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_WRITE, callback, user_data, begin, end)


    def hook_mem_fetch(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_FETCH, callback, user_data, begin, end)


    def hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
        if self.interpreter:
            from .arch.evm.hooks import evm_hook_insn
            return evm_hook_insn(self, 'HOOK_INSN', callback, arg1, user_data, begin, end)

        return self.ql_hook(UC_HOOK_INSN, callback, user_data, begin, end, arg1)


    def hook_del(self, *args):
        if len(args) != 1 and len(args) != 2:
            return

        if isinstance(args[0], HookRet):
            args[0].remove()
            return

        hook_type, h = args

        if self.interpreter:
            from .arch.evm.hooks import evm_hook_del
            return evm_hook_del(hook_type, h)

        def __handle_common(t: int) -> None:
            if t in self._hook:
                if h in self._hook[t]:
                    del self._hook[t][self._hook[t].index(h)]

                    if len(self._hook[t]) == 0:
                        self._h_uc.hook_del(self._hook_fuc[t])
                        del self._hook_fuc[t]

        def __handle_insn(t: int) -> None:
            if t in self._insn_hook:
                if h in self._insn_hook[t]:
                    del self._insn_hook[t][self._insn_hook[t].index(h)]

                    if len(self._insn_hook[t]) == 0:
                        self._h_uc.hook_del(self._insn_hook_fuc[t])
                        del self._insn_hook_fuc[t]

        def __handle_addr(t: int) -> None:
            if t in self._addr_hook:
                if h in self._addr_hook[t]:
                    del self._addr_hook[t][self._addr_hook[t].index(h)]

                    if len(self._addr_hook[t]) == 0:
                        self._h_uc.hook_del(self._addr_hook_fuc[t])
                        del self._addr_hook_fuc[t]

        type_handlers = (
            (UC_HOOK_INTR,               __handle_common),
            (UC_HOOK_INSN,               __handle_insn),
            (UC_HOOK_CODE,               __handle_common),
            (UC_HOOK_BLOCK,              __handle_common),
            (UC_HOOK_MEM_READ_UNMAPPED,  __handle_common),
            (UC_HOOK_MEM_WRITE_UNMAPPED, __handle_common),
            (UC_HOOK_MEM_FETCH_UNMAPPED, __handle_common),
            (UC_HOOK_MEM_READ_PROT,      __handle_common),
            (UC_HOOK_MEM_WRITE_PROT,     __handle_common),
            (UC_HOOK_MEM_FETCH_PROT,     __handle_common),
            (UC_HOOK_MEM_READ,           __handle_common),
            (UC_HOOK_MEM_WRITE,          __handle_common),
            (UC_HOOK_MEM_FETCH,          __handle_common),
            (UC_HOOK_MEM_READ_AFTER,     __handle_common),
            (UC_HOOK_INSN_INVALID,       __handle_common)
        )

        # address hooks are a special case of UC_HOOK_CODE and
        # should be handled separately
        if isinstance(h, HookAddr):
            __handle_addr(h.addr)
            return

        for t, handler in type_handlers:
            if hook_type & t:
                handler(t)


    def clear_hooks(self):
        for ptr in self._hook_fuc.values():
            self._h_uc.hook_del(ptr)

        for ptr in self._insn_hook_fuc.values():
            self._h_uc.hook_del(ptr)

        for ptr in self._addr_hook_fuc.values():
            self._h_uc.hook_del(ptr)

        self.clear_ql_hooks()


    def clear_ql_hooks(self):
        self._hook = {}
        self._hook_fuc = {}

        self._insn_hook = {}
        self._insn_hook_fuc = {}

        self._addr_hook = {}
        self._addr_hook_fuc = {}
