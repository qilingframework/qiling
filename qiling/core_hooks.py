#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

##############################################
# These are part of the core.py Qiling class #
# handling hooks                             #
##############################################


from unicorn import *

from .core_hooks_types import Hook, HookAddr, HookIntr, HookRet
from .utils import catch_KeyboardInterrupt
from .const import QL_HOOK_BLOCK, QL_ARCH_NONEOS, QL_ARCH_HARDWARE
from .exception import QlErrorCoreHook


# Don't assume self is Qiling.
class QlCoreHooks:
    def __init__(self, uc=None):
        self._h_uc = uc
        self._hook = {}
        self._hook_fuc = {}
        self._insn_hook = {}
        self._insn_hook_fuc = {}
        self._addr_hook = {}
        self._addr_hook_fuc = {}
        
        self.hook_intr_fuc = None
        self.hook_insn_fuc = None
        self.hook_code_fuc = None
        self.hook_block_fuc = None
        self.hook_mem_read_unmapped_fuc = None
        self.hook_mem_write_unmapped_fuc = None
        self.hook_mem_fetch_unmapped_fuc = None
        self.hook_mem_read_prot_fuc = None
        self.hook_mem_write_prot_fuc = None
        self.hook_mem_fetch_prot_fuc = None
        self.hook_mem_read_fuc = None
        self.hook_mem_write_fuc = None
        self.hook_mem_fetch_fuc = None
        self.hook_mem_read_after_fuc = None
        self.hook_insn_invalid_fuc = None


    ########################
    # Callback definitions #
    ########################
    def _callback_type3(self, uc, intno, pack_data):
        ql, user_data, callback = pack_data     # unpack what we packed for hook_add()
        if user_data:
            return callback(ql, intno, user_data)
        return callback(ql, intno)              # callback does not require user_data
    

    def _hook_intr_cb(self, uc, intno, pack_data):
        ql, hook_type = pack_data
        catched = False
        if hook_type in self._hook.keys():
            for h in self._hook[hook_type]:
                if h.check(ql, intno):
                    catched = True
                    ret = h.call(ql, intno)
                    if isinstance(ret, int) == True and ret & QL_HOOK_BLOCK  != 0:
                        break
        
        if catched == False:
            raise QlErrorCoreHook("_hook_intr_cb : catched == False")
    

    def _hook_insn_cb(self, uc, *args):
        ql, hook_type = args[-1]

        if hook_type in self._insn_hook.keys():
            retval = None

            for h in self._insn_hook[hook_type]:
                if h.bound_check(ql.reg.arch_pc):
                    ret = h.call(ql, *args[ : -1])

                    if type(ret) is tuple:
                        ret, retval = ret

                    if type(ret) is int and ret & QL_HOOK_BLOCK:
                        break

            # use the last return value received
            return retval

    def _callback_type4(self, uc, addr, size, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, addr, size, user_data)
        return callback(ql, addr, size)


    def _callback_type4a(self, uc, _addr, _size, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, user_data)
        return callback(ql)


    def _hook_trace_cb(self, uc, addr, size, pack_data):
        ql, hook_type = pack_data
        if hook_type in self._hook.keys():
            for h in self._hook[hook_type]:
                if h.bound_check(ql.reg.arch_pc):
                    ret = h.call(ql, addr, size)
                    if isinstance(ret, int) == True and ret & QL_HOOK_BLOCK  != 0:
                        break


    def _callback_type6(self, uc, access, addr, size, value, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, addr, size, value, user_data)
        return callback(ql, addr, size, value)


    def _hook_mem_cb(self, uc, access, addr, size, value, pack_data):
        ql, hook_type = pack_data
        handled = False
        if hook_type in self._hook.keys():
            for h in self._hook[hook_type]:
                if h.bound_check(addr, size):
                    handled = True
                    ret = h.call(ql, access, addr, size, value)
                    if isinstance(ret, int) == True and ret & QL_HOOK_BLOCK  != 0:
                        break
        
        if hook_type in (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_FETCH_PROT):
            if handled == False:
                raise QlErrorCoreHook("_hook_mem_cb : handled == False")
        return True


    def _callback_x86_syscall(self, uc, pack_data):
        ql, user_data, callback = pack_data
        if user_data:
            return callback(ql, user_data)
        return callback(ql)


    def _hook_insn_invalid_cb(self, uc, pack_data):
        ql, hook_type = pack_data
        catched = False
        if hook_type in self._hook.keys():
            for h in self._hook[hook_type]:
                catched = True
                ret = h.call(ql)
                if isinstance(ret, int) == True and ret & QL_HOOK_BLOCK  != 0:
                    break
        
        if catched == False:
            raise QlErrorCoreHook("_hook_intr_invalid_cb : catched == False")


    def _hook_addr_cb(self, uc, addr, size, pack_data):
        ql, addr = pack_data
        if addr in self._addr_hook.keys():
            for h in self._addr_hook[addr]:
                ret = h.call(ql, addr, size)
                if isinstance(ret, int) == True and ret & QL_HOOK_BLOCK  != 0:
                    break

    ###############
    # Class Hooks #
    ###############
    def _ql_hook_internal(self, hook_type, callback, user_data=None, *args):
        _callback = (catch_KeyboardInterrupt(self))(callback)
        # pack user_data & callback for wrapper _callback
        return self._h_uc.hook_add(hook_type, _callback, (self, user_data), 1, 0, *args)


    def _ql_hook_addr_internal(self, callback, user_data, address):
        _callback = (catch_KeyboardInterrupt(self))(callback)
        # pack user_data & callback for wrapper _callback
        return self._h_uc.hook_add(UC_HOOK_CODE, _callback, (self, user_data), address, address)


    def _ql_hook(self, hook_type, h, *args):
        base_type = [
            UC_HOOK_INTR,
            UC_HOOK_INSN,
            UC_HOOK_CODE,
            UC_HOOK_BLOCK,
            UC_HOOK_MEM_READ_UNMAPPED,
            UC_HOOK_MEM_WRITE_UNMAPPED,
            UC_HOOK_MEM_FETCH_UNMAPPED,
            UC_HOOK_MEM_READ_PROT,
            UC_HOOK_MEM_WRITE_PROT,
            UC_HOOK_MEM_FETCH_PROT,
            UC_HOOK_MEM_READ,
            UC_HOOK_MEM_WRITE,
            UC_HOOK_MEM_FETCH,
            UC_HOOK_MEM_READ_AFTER,
            UC_HOOK_INSN_INVALID
            ]
        for t in base_type:
            if (t & hook_type) != 0:
                if t in (UC_HOOK_INTR, ):
                    if t not in self._hook_fuc.keys():
                        self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_intr_cb, t)
                    
                    if t not in self._hook.keys():
                        self._hook[t] = []
                    self._hook[t].append(h)
                
                if t in (UC_HOOK_INSN, ):
                    ins_t = args[0]
                    if ins_t not in self._insn_hook_fuc.keys():
                        self._insn_hook_fuc[ins_t] = self._ql_hook_internal(t, self._hook_insn_cb, ins_t, *args)
                    
                    if ins_t not in self._insn_hook.keys():
                        self._insn_hook[ins_t] = []
                    self._insn_hook[ins_t].append(h)
                
                if t in (UC_HOOK_CODE, UC_HOOK_BLOCK):
                    if t not in self._hook_fuc.keys():
                        self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_trace_cb, t)

                    if t not in self._hook.keys():
                        self._hook[t] = []
                    self._hook[t].append(h)
                
                if t in (UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH, UC_HOOK_MEM_READ_AFTER):
                    if t not in self._hook_fuc.keys():
                        self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_mem_cb, t)

                    if t not in self._hook.keys():
                        self._hook[t] = []
                    self._hook[t].append(h)
                
                if t in (UC_HOOK_INSN_INVALID, ):
                    if t not in self._hook_fuc.keys():
                        self._hook_fuc[t] = self._ql_hook_internal(t, self._hook_insn_invalid_cb, t)

                    if t not in self._hook.keys():
                        self._hook[t] = []
                    self._hook[t].append(h)


    def ql_hook(self, hook_type, callback, user_data=None, begin=1, end=0, *args):
        h = Hook(callback, user_data, begin, end)
        self._ql_hook(hook_type, h, *args)
        return HookRet(self, hook_type, h)


    def hook_code(self, callback, user_data=None, begin=1, end=0):
        if self.archtype in QL_ARCH_NONEOS:
            from .arch.evm.hooks import ql_evm_hooks
            return ql_evm_hooks(self, 'HOOK_CODE', callback, user_data, begin, end)
        return self.ql_hook(UC_HOOK_CODE, callback, user_data, begin, end)


    def hook_intr(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_INTR,  callback, user_data, begin, end)


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
        h = HookAddr(callback, address, user_data)
        
        if self.archtype in QL_ARCH_NONEOS:
            from .arch.evm.hooks import evm_hook_address
            return evm_hook_address(self, 'HOOK_ADDR', h, address)

        if address not in self._addr_hook_fuc.keys():
            self._addr_hook_fuc[address] = self._ql_hook_addr_internal(self._hook_addr_cb, address, address)

        if address not in self._addr_hook.keys():
            self._addr_hook[address] = []

        self._addr_hook[address].append(h)
        return HookRet(self, None, h)
    

    def get_hook_address(self, address):
        return self._addr_hook.get(address, [])

    def hook_intno(self, callback, intno, user_data=None):
        h = HookIntr(callback, intno, user_data)
        self._ql_hook(UC_HOOK_INTR, h)
        return HookRet(self, UC_HOOK_INTR, h)


    def hook_mem_read(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_READ, callback, user_data, begin, end)


    def hook_mem_write(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_WRITE, callback, user_data, begin, end)


    def hook_mem_fetch(self, callback, user_data=None, begin=1, end=0):
        return self.ql_hook(UC_HOOK_MEM_FETCH, callback, user_data, begin, end)


    def hook_insn(self, callback, arg1, user_data=None, begin=1, end=0):
        if self.archtype in QL_ARCH_NONEOS:
            from .arch.evm.hooks import evm_hook_insn
            return evm_hook_insn(self, 'HOOK_INSN', callback, arg1, user_data, begin, end)
        return self.ql_hook(UC_HOOK_INSN, callback, user_data, begin, end, arg1)


    def hook_del(self, *args):
        if len(args) != 1 and len(args) != 2:
            return

        if isinstance(args[0], HookRet):
            args[0].remove()
            return
        else:
            hook_type, h = args

        if self.archtype in QL_ARCH_NONEOS:
            from .arch.evm.hooks import evm_hook_del
            return evm_hook_del(hook_type, h)

        base_type = [
            UC_HOOK_INTR,
            UC_HOOK_INSN,
            UC_HOOK_CODE,
            UC_HOOK_BLOCK,
            UC_HOOK_MEM_READ_UNMAPPED,
            UC_HOOK_MEM_WRITE_UNMAPPED,
            UC_HOOK_MEM_FETCH_UNMAPPED,
            UC_HOOK_MEM_READ_PROT,
            UC_HOOK_MEM_WRITE_PROT,
            UC_HOOK_MEM_FETCH_PROT,
            UC_HOOK_MEM_READ,
            UC_HOOK_MEM_WRITE,
            UC_HOOK_MEM_FETCH,
            UC_HOOK_MEM_READ_AFTER,
            UC_HOOK_INSN_INVALID
            ]
        if isinstance(h, HookAddr):
            if h.addr in self._addr_hook.keys():
                if h in self._addr_hook[h.addr]:
                    del self._addr_hook[h.addr][self._addr_hook[h.addr].index(h)]

                    if len(self._addr_hook[h.addr]) == 0:
                        self._h_uc.hook_del(self._addr_hook_fuc[h.addr])
                        del self._addr_hook_fuc[h.addr]
            
            return

        for t in base_type:
            if (t & hook_type) != 0:
                if t in (UC_HOOK_INTR, UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_FETCH_PROT, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_FETCH, UC_HOOK_MEM_READ_AFTER, UC_HOOK_INSN_INVALID):
                    if t in self._hook.keys():
                        if h in self._hook[t]:
                            del self._hook[t][self._hook[t].index(h)]

                            if len(self._hook[t]) == 0:
                                self._h_uc.hook_del(self._hook_fuc[t])
                                del self._hook_fuc[t]
                
                if t in (UC_HOOK_INSN, ):
                    if t in self._insn_hook.keys():
                        if h in self._insn_hook[t]:
                            del self._insn_hook[t][self._insn_hook[t].index(h)]

                            if len(self._insn_hook[t]) == 0:
                                self._h_uc.hook_del(self._insn_hook_fuc[t])
                                del self._insn_hook_fuc[t]
                    

    def clear_hooks(self):
        for i in self._hook_fuc.keys():
            self._h_uc.hook_del(self._hook_fuc[i])
        
        for i in self._insn_hook_fuc.keys():
            self._h_uc.hook_del(self._insn_hook_fuc[i])

        for i in self._addr_hook_fuc.keys():
            self._h_uc.hook_del(self._addr_hook_fuc[i])

        self.clear_ql_hooks()
    
    
    def clear_ql_hooks(self):
        self._hook = {}
        self._hook_fuc = {}
        self._insn_hook = {}
        self._insn_hook_fuc = {}
        self._addr_hook = {}
        self._addr_hook_fuc = {}
