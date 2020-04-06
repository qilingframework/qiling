#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *

from qiling.const import *

from qiling.os.macos.syscall import *
from qiling.os.posix.syscall import *
from qiling.os.freebsd.syscall import *
from qiling.os.linux.syscall import *

class QlPosixManager:
    
    def __init__(self, ql):
        self.ql = ql
        self.dict_posix_syscall = dict()
    
    def load_syscall(self, intno= None):
        # FIXME: maybe we need a better place
        if self.ql.ostype == QL_FREEBSD:
            from qiling.os.freebsd.x8664_syscall import map_syscall
 
        elif self.ql.ostype == QL_MACOS:
            if  self.ql.arch == QL_X8664:   
                from qiling.os.macos.x8664_syscall import map_syscall
            elif  self.ql.arch == QL_ARM64:
                from qiling.os.macos.arm64_syscall import map_syscall

        elif self.ql.ostype == QL_LINUX:
            if self.ql.arch == QL_X8664:   
                from qiling.os.linux.x8664_syscall import map_syscall
            if self.ql.arch == QL_X86:   
                from qiling.os.linux.x86_syscall import map_syscall                
            elif self.ql.arch == QL_ARM64:
                from qiling.os.linux.arm64_syscall import map_syscall
            elif self.ql.arch == QL_MIPS32:   
                from qiling.os.linux.mips32_syscall import map_syscall
                if intno != 0x11:
                    raise QlErrorExecutionStop("[!] got interrupt 0x%x ???" %intno)
            elif self.ql.arch == QL_ARM:
                from qiling.os.linux.arm_syscall import map_syscall                
        
        param0 , param1, param2, param3, param4, param5 = self.ql.syscall_param

        while 1:
            _SYSCALL_FUNC = self.ql.dict_posix_syscall.get(self.ql.syscall, None)
            if _SYSCALL_FUNC != None:
                _SYSCALL_FUNC_NAME = _SYSCALL_FUNC.__name__
                break
            _SYSCALL_FUNC_NAME = map_syscall(self.ql.syscall)
            if _SYSCALL_FUNC_NAME != None:
                _SYSCALL_FUNC = eval(_SYSCALL_FUNC_NAME)
                break
            _SYSCALL_FUNC = None
            _SYSCALL_FUNC_NAME = None
            break

        if _SYSCALL_FUNC != None:
            try:
                _SYSCALL_FUNC(self.ql, param0, param1, param2, param3, param4, param5)
            except KeyboardInterrupt:
                raise            
            except Exception:
                self.ql.nprint("[!] SYSCALL ERROR: ", _SYSCALL_FUNC_NAME)
                raise QlErrorSyscallError("[!] Syscall Implementation Error: %s" % (_SYSCALL_FUNC_NAME))
        else:
            self.ql.nprint("[!] 0x%x: syscall number = 0x%x(%d) not implement" %(self.ql.pc, self.ql.syscall, self.ql.syscall))
            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound("[!] Syscall Not Found")

    # get syscall
    def get_syscall(self):
        if self.ql.arch == QL_ARM64:
            if self.ql.ostype == QL_MACOS:
                syscall_num = UC_ARM64_REG_X16
            else:
                syscall_num = UC_ARM64_REG_X8
        elif self.ql.arch == QL_ARM:
            syscall_num = UC_ARM_REG_R7
        elif self.ql.arch == QL_MIPS32:
            syscall_num = UC_MIPS_REG_V0        
        elif self.ql.arch == QL_X86:
            syscall_num = UC_X86_REG_EAX
        elif self.ql.arch == QL_X8664:
            syscall_num = UC_X86_REG_RAX           

        return self.ql.register(syscall_num)
    
    # get syscall
    def get_syscall_param(self):
        if self.ql.arch == QL_ARM64:
            param0 = self.ql.register(UC_ARM64_REG_X0)
            param1 = self.ql.register(UC_ARM64_REG_X1)
            param2 = self.ql.register(UC_ARM64_REG_X2)
            param3 = self.ql.register(UC_ARM64_REG_X3)
            param4 = self.ql.register(UC_ARM64_REG_X4)
            param5 = self.ql.register(UC_ARM64_REG_X5)
        elif self.ql.arch == QL_ARM:
            param0 = self.ql.register(UC_ARM_REG_R0)
            param1 = self.ql.register(UC_ARM_REG_R1)
            param2 = self.ql.register(UC_ARM_REG_R2)
            param3 = self.ql.register(UC_ARM_REG_R3)
            param4 = self.ql.register(UC_ARM_REG_R4)
            param5 = self.ql.register(UC_ARM_REG_R5)
        elif self.ql.arch == QL_MIPS32:
            param0 = self.ql.register(UC_MIPS_REG_A0)
            param1 = self.ql.register(UC_MIPS_REG_A1)
            param2 = self.ql.register(UC_MIPS_REG_A2)
            param3 = self.ql.register(UC_MIPS_REG_A3)
            param4 = self.ql.register(UC_MIPS_REG_SP)
            param4 = param4 + 0x10
            param5 = self.ql.register(UC_MIPS_REG_SP)
            param5 = param5 + 0x14
        elif self.ql.arch == QL_X86:
            param0 = self.ql.register(UC_X86_REG_EBX)
            param1 = self.ql.register(UC_X86_REG_ECX)
            param2 = self.ql.register(UC_X86_REG_EDX)
            param3 = self.ql.register(UC_X86_REG_ESI)
            param4 = self.ql.register(UC_X86_REG_EDI)
            param5 = self.ql.register(UC_X86_REG_EBP)
        elif self.ql.arch == QL_X8664:
            param0 = self.ql.register(UC_X86_REG_RDI)
            param1 = self.ql.register(UC_X86_REG_RSI)
            param2 = self.ql.register(UC_X86_REG_RDX)
            param3 = self.ql.register(UC_X86_REG_R10)
            param4 = self.ql.register(UC_X86_REG_R8)
            param5 = self.ql.register(UC_X86_REG_R9)                    
        
        return param0, param1, param2, param3, param4, param5