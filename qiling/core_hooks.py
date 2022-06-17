#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

##############################################
# These are part of the core.py Qiling class #
# handling hooks                             #
##############################################

from typing import Any, Callable, MutableMapping, MutableSequence, Protocol
from typing import TYPE_CHECKING

from unicorn import Uc
from unicorn.unicorn_const import *

from .core_hooks_types import Hook, HookAddr, HookIntr, HookRet
from .utils import catch_KeyboardInterrupt
from .const import QL_HOOK_BLOCK
from .exception import QlErrorCoreHook

if TYPE_CHECKING:
    from qiling import Qiling

class MemHookCallback(Protocol):
    def __call__(self, __ql: 'Qiling', __access: int, __address: int, __size: int, __value: int, *__context: Any) -> Any:
        """Memory access hook callback.

        Args:
            __ql      : the associated qiling instance
            __access  : the intercepted memory access type, one of UC_HOOK_MEM_* constants
            __addr    : the target memory location
            __size    : size of intercepted memory access
            __value   : the value to write, for write operations, 0 for others
            __context : additional context passed on hook creation. if no context was passed, this argument should be omitted

        Returns:
            an integer with `QL_HOOK_BLOCK` mask set to block execution of remaining hooks
            (if any) or `None`
        """
        pass

class TraceHookCalback(Protocol):
    def __call__(self, __ql: 'Qiling', __address: int, __size: int, *__context: Any) -> Any:
        """Execution hook callback.

        Args:
            __ql      : the associated qiling instance
            __address : address of the instruction to be executed
            __size    : instruction size
            __context : additional context passed on hook creation. if no context was passed, this argument should be omitted

        Returns:
            an integer with `QL_HOOK_BLOCK` mask set to block execution of remaining hooks
            (if any) or `None`
        """
        pass

class AddressHookCallback(Protocol):
    def __call__(self, __ql: 'Qiling', *__context: Any) -> Any:
        """Address hook callback.

        Args:
            __ql      : the associated qiling instance
            __context : additional context passed on hook creation. if no context was passed, this argument should be omitted

        Returns:
            an integer with `QL_HOOK_BLOCK` mask set to block execution of remaining hooks
            (if any) or `None`
        """
        pass

class InterruptHookCallback(Protocol):
    def __call__(self, __ql: 'Qiling', intno: int, *__context: Any) -> Any:
        """Interrupt hook callback.

        Args:
            __ql      : the associated qiling instance
            __intno   : the intercepted interrupt number
            __context : additional context passed on hook creation. if no context was passed, this argument should be omitted

        Returns:
            an integer with `QL_HOOK_BLOCK` mask set to block execution of remaining hooks
            (if any) or `None`
        """
        pass


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
        """Interrupt hooks dispatcher.
        """

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
        """Instruction hooks dispatcher.
        """

        *hook_args, (ql, insn_type) = args
        retval = None

        if insn_type in self._insn_hook:
            hooks_list = self._insn_hook[insn_type]

            for hook in hooks_list:
                if hook.bound_check(ql.arch.regs.arch_pc):
                    ret = hook.call(ql, *hook_args)

                    if type(ret) is tuple:
                        ret, retval = ret

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break

        # use the last return value received
        return retval


    def _hook_trace_cb(self, uc: Uc, addr: int, size: int, pack_data) -> None:
        """Code and block hooks dispatcher.
        """

        ql, hook_type = pack_data

        if hook_type in self._hook:
            hooks_list = self._hook[hook_type]

            for hook in hooks_list:
                if hook.bound_check(addr, size):
                    ret = hook.call(ql, addr, size)

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break


    def _hook_mem_cb(self, uc: Uc, access: int, addr: int, size: int, value: int, pack_data):
        """Memory access hooks dispatcher.
        """

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
        """Invalid instruction hooks dispatcher.
        """

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
        """Address hooks dispatcher.
        """

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
    def _ql_hook_internal(self, hook_type: int, callback: Callable, context: Any, *args) -> int:
        _callback = catch_KeyboardInterrupt(self, callback)

        return self._h_uc.hook_add(hook_type, _callback, (self, context), 1, 0, *args)


    def _ql_hook_addr_internal(self, callback: Callable, address: int) -> int:
        _callback = catch_KeyboardInterrupt(self, callback)

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
                self._insn_hook_fuc[ins_t] = self._ql_hook_internal(t, self._hook_insn_cb, ins_t, ins_t)

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


    def ql_hook(self, hook_type: int, callback: Callable, user_data: Any = None, begin: int = 1, end: int = 0, *args) -> HookRet:
        """Intercept certain emulation events within a specified range.

        Args:
            hook_type : event type to intercept; this argument is used as a bitmap and may encode multiple
            events to hook with the same calback. see UC_HOOK_* constants for available events
            callback  : a method to call upon interception; callback signature may vary
            depending on the hooked event type
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        hook = Hook(callback, user_data, begin, end)
        self._ql_hook(hook_type, hook, *args)

        return HookRet(self, hook_type, hook)


    def hook_code(self, callback: TraceHookCalback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept assembly instructions before they get executed.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_CODE, callback, user_data, begin, end)


    # TODO: remove; this is a special case of hook_intno(-1)
    def hook_intr(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_INTR, callback, user_data, begin, end)


    def hook_block(self, callback: TraceHookCalback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept landings in new basic blocks in a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_BLOCK, callback, user_data, begin, end)


    def hook_mem_unmapped(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept illegal accesses to unmapped memory in a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_UNMAPPED, callback, user_data, begin, end)


    def hook_mem_read_invalid(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept illegal reading attempts from a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_READ_INVALID, callback, user_data, begin, end)


    def hook_mem_write_invalid(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept illegal writing attempts to a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_WRITE_INVALID, callback, user_data, begin, end)


    def hook_mem_fetch_invalid(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept illegal code fetching attempts from a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_FETCH_INVALID, callback, user_data, begin, end)


    def hook_mem_valid(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept benign memory accesses within a specified range.
        This is equivalent to hooking memory reads, writes and fetches.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_VALID, callback, user_data, begin, end)


    def hook_mem_invalid(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept invalid memory accesses within a specified range.
        This is equivalent to hooking invalid memory reads, writes and fetches.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_INVALID, callback, user_data, begin, end)


    def hook_address(self, callback: AddressHookCallback, address: int, user_data: Any = None) -> HookRet:
        """Intercept execution from a certain memory address.

        Args:
            callback  : a method to call upon interception
            address   : memory location to watch
            user_data : an additional context to pass to callback (default: `None`)

        Returns:
            Hook handle
        """

        hook = HookAddr(callback, address, user_data)

        if address not in self._addr_hook_fuc:
            self._addr_hook_fuc[address] = self._ql_hook_addr_internal(self._hook_addr_cb, address)

        if address not in self._addr_hook:
            self._addr_hook[address] = []

        self._addr_hook[address].append(hook)

        # note: assuming 0 is not a valid hook type
        return HookRet(self, 0, hook)


    def hook_intno(self, callback: InterruptHookCallback, intno: int, user_data: Any = None) -> HookRet:
        """Intercept interrupts.

        Args:
            callback  : a method to call upon interception
            intono    : interrupt vector number to intercept, or -1 for any
            user_data : an additional context to pass to callback (default: `None`)

        Returns:
            Hook handle
        """

        hook = HookIntr(callback, intno, user_data)
        self._ql_hook(UC_HOOK_INTR, hook)

        return HookRet(self, UC_HOOK_INTR, hook)


    def hook_mem_read(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept benign memory reads from a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_READ, callback, user_data, begin, end)


    def hook_mem_write(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept benign memory writes to a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_WRITE, callback, user_data, begin, end)


    def hook_mem_fetch(self, callback: MemHookCallback, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept benign code fetches from a specified range.

        Args:
            callback  : a method to call upon interception
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_MEM_FETCH, callback, user_data, begin, end)


    def hook_insn(self, callback, insn_type: int, user_data: Any = None, begin: int = 1, end: int = 0) -> HookRet:
        """Intercept execution of a certain instruction type within a specified range.

        Args:
            callback  : a method to call upon interception; the callback arguments list differs
            based on the instruction type
            insn_type : instruction type to intercept
            user_data : an additional context to pass to callback (default: `None`)
            begin     : start of memory range to watch
            end       : end of memory range to watch

        Notes:
            - The set of supported instruction types is very limited and defined by unicorn.
            - If `begin` and `end` are not specified, the entire memory space will be watched.

        Returns:
            Hook handle
        """

        return self.ql_hook(UC_HOOK_INSN, callback, user_data, begin, end, insn_type)


    def hook_del(self, hret: HookRet) -> None:
        """Unregister an existing hook and release its resources.

        Args:
            hret : hook handle
        """

        h = hret.obj
        hook_type = hret.type

        def __remove(hooks_map, handles_map, key: int) -> None:
            if key in hooks_map:
                hooks_list = hooks_map[key]

                if h in hooks_list:
                    hooks_list.remove(h)

                    if not hooks_list:
                        uc_handle = handles_map.pop(key)

                        self._h_uc.hook_del(uc_handle)

        __handle_common = lambda k: __remove(self._hook, self._hook_fuc, k)
        __handle_insn   = lambda i: __remove(self._insn_hook, self._insn_hook_fuc, i)
        __handle_addr   = lambda a: __remove(self._addr_hook, self._addr_hook_fuc, a)

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
