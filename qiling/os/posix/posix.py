#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# For syscall_num
from unicorn.arm64_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from unicorn.x86_const import *

from qiling.const import *
from qiling.core_utils import QlFileDes
from qiling.os.os import QlOs
from qiling.utils import *
from qiling.exception import *

from qiling.os.posix.syscall import *
from qiling.os.linux.syscall import *
from qiling.os.macos.syscall import *
from qiling.os.freebsd.syscall import *

from qiling.os.linux.function_hook import ARMFunctionArg, MIPS32FunctionArg, ARM64FunctionArg, X86FunctionArg, X64FunctionArg


class QlOsPosix(QlOs):
    def __init__(self, ql):
        super(QlOsPosix, self).__init__(ql)
        self.ql = ql
        self.sigaction_act = []
        
        if self.ql.root == True:
            self.uid = 0
            self.gid = 0
        else:    
            self.uid = self.profile.getint("KERNEL","uid")
            self.gid = self.profile.getint("KERNEL","gid")

        
        self.fd = QlFileDes([0] * 256)
        self.dict_posix_syscall = dict()
        self.dict_posix_onEnter_syscall = dict()
        self.dict_posix_onExit_syscall = dict()
        self.dict_posix_syscall_by_num = dict()
        self.dict_posix_onEnter_syscall_by_num = dict()
        self.dict_posix_onExit_syscall_by_num = dict()

        self.syscall_map = None
        self.syscall_name = None

        if self.ql.ostype in QL_OS_POSIX:
            self.fd[0] = self.stdin
            self.fd[1] = self.stdout
            self.fd[2] = self.stderr

        for _ in range(256):
            self.sigaction_act.append(0)

    # ql.syscall - get syscall for all posix series
    @property
    def syscall(self):
        return self.get_syscall()

    # ql.func_arg - get syscall for all posix series
    @property
    def function_arg(self):
        if self.ql.ostype in (QL_OS_POSIX):
            # ARM
            if self.ql.archtype== QL_ARCH.ARM:
                return ARMFunctionArg(self.ql)

            # MIPS32
            elif self.ql.archtype== QL_ARCH.MIPS:
                return MIPS32FunctionArg(self.ql)

            # ARM64
            elif self.ql.archtype== QL_ARCH.ARM64:
                return ARM64FunctionArg(self.ql)

            # X86
            elif  self.ql.archtype== QL_ARCH.X86:
                return X86FunctionArg(self.ql)

            # X8664
            elif  self.ql.archtype== QL_ARCH.X8664:
                return X64FunctionArg(self.ql)
            else:
                raise

    def load_syscall(self, intno=None):
        # import syscall mapping function
        map_syscall = self.ql.os_setup(function_name="map_syscall")
        self.syscall_name = map_syscall(self.ql, self.syscall)

        if self.dict_posix_onEnter_syscall.get(self.syscall_name) != None:
            self.syscall_onEnter = self.dict_posix_onEnter_syscall.get(self.syscall_name)
        elif self.dict_posix_onEnter_syscall_by_num.get(self.syscall) != None:
            self.syscall_onEnter = self.dict_posix_onEnter_syscall_by_num.get(self.syscall)
        else:
            self.syscall_onEnter = None    
        
        if self.dict_posix_onExit_syscall.get(self.syscall_name) != None:
            self.syscall_onExit = self.dict_posix_onExit_syscall.get(self.syscall_name)
        elif self.dict_posix_onExit_syscall_by_num.get(self.syscall) != None:
            self.syscall_onExit = self.dict_posix_onExit_syscall_by_num.get(self.syscall)
        else:
            self.syscall_onExit = None    
        
        self.syscall_map = self.dict_posix_syscall_by_num.get(self.syscall)
        syscall_name_str = None
        

        if self.syscall_map is not None:
            self.syscall_name = self.syscall_map.__name__
        else:
            self.syscall_name = map_syscall(self.ql, self.syscall)

            import qiling.os.posix.syscall
            import qiling.os.linux.syscall
            import qiling.os.macos.syscall
            import qiling.os.freebsd.syscall

            if self.syscall_name not in dir(qiling.os.posix.syscall) \
            and self.syscall_name not in dir(qiling.os.linux.syscall) \
            and self.syscall_name not in dir(qiling.os.macos.syscall) \
            and self.syscall_name not in dir(qiling.os.freebsd.syscall):

                syscall_name_str = self.syscall_name
                self.syscall_map = None
                self.syscall_name = None

                
            if self.syscall_name is not None:
                replace_func = self.dict_posix_syscall.get(self.syscall_name)
                if replace_func is not None:
                    self.syscall_map = replace_func
                    self.syscall_name = replace_func.__name__
                else:
                    self.syscall_map = eval(self.syscall_name)
            else:
                self.syscall_map = None
                self.syscall_name = None

        if self.syscall_map is not None:
            self.syscalls.setdefault(self.syscall_name, []).append({
                "params": {
                    "param0": self.get_func_arg()[0],
                    "param1": self.get_func_arg()[1],
                    "param2": self.get_func_arg()[2],
                    "param3": self.get_func_arg()[3],
                    "param4": self.get_func_arg()[4],
                    "param5": self.get_func_arg()[5]
                },
                "result": None,
                "address": self.ql.reg.arch_pc,
                "return_address": None,
                "position": self.syscalls_counter
            })

            self.syscalls_counter += 1

            try:                
                if self.syscall_onEnter == None:
                    ret = 0
                else:
                    ret = self.syscall_onEnter(self.ql, self.get_func_arg()[0], self.get_func_arg()[1], self.get_func_arg()[2], self.get_func_arg()[3], self.get_func_arg()[4], self.get_func_arg()[5])

                if isinstance(ret, int) == False or ret & QL_CALL_BLOCK == 0:
                    self.syscall_map(self.ql, self.get_func_arg()[0], self.get_func_arg()[1], self.get_func_arg()[2], self.get_func_arg()[3], self.get_func_arg()[4], self.get_func_arg()[5])
                
                if self.syscall_onExit != None:
                    self.syscall_onExit(self.ql, self.get_func_arg()[0], self.get_func_arg()[1], self.get_func_arg()[2], self.get_func_arg()[3], self.get_func_arg()[4], self.get_func_arg()[5])

            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.ql.nprint("[!] Syscall ERROR: %s DEBUG: %s" % (self.syscall_name, e))
                raise e
        else:
            self.ql.nprint(
                "[!] 0x%x: syscall %s number = 0x%x(%d) not implemented" % (self.ql.reg.arch_pc, syscall_name_str, self.syscall, self.syscall))
            if self.ql.debug_stop:
                raise QlErrorSyscallNotFound("[!] Syscall Not Found")

    # get syscall
    def get_syscall(self):
        if self.ql.archtype == QL_ARCH.ARM64:
            if self.ql.ostype == QL_OS.MACOS:
                syscall_num = UC_ARM64_REG_X16
            else:
                syscall_num = UC_ARM64_REG_X8
        elif self.ql.archtype == QL_ARCH.ARM:
            syscall_num = UC_ARM_REG_R7
        elif self.ql.archtype == QL_ARCH.MIPS:
            syscall_num = UC_MIPS_REG_V0
        elif self.ql.archtype == QL_ARCH.X86:
            syscall_num = UC_X86_REG_EAX
        elif self.ql.archtype == QL_ARCH.X8664:
            syscall_num = UC_X86_REG_RAX

        return self.ql.reg.read(syscall_num)

    def definesyscall_return(self, regreturn):
        # each name has a list of calls, we want the last one and we want to update the return value
        self.syscalls[self.syscall_name][-1]["result"] = regreturn
        if self.ql.archtype == QL_ARCH.ARM:  # ARM
            self.ql.reg.r0 = regreturn

        elif self.ql.archtype == QL_ARCH.ARM64:  # ARM64
            self.ql.reg.x0 = regreturn

        elif self.ql.archtype == QL_ARCH.X86:  # X86
            self.ql.reg.eax = regreturn

        elif self.ql.archtype == QL_ARCH.X8664:  # X8664
            self.ql.reg.rax = regreturn

        elif self.ql.archtype == QL_ARCH.MIPS:  # MIPSE32EL
            if regreturn < 0 and regreturn > -1134:
                a3return = 1
                regreturn = - regreturn
            else:
                a3return = 0

            self.ql.reg.v0 = regreturn
            self.ql.reg.a3 = a3return


    # get syscall
    def get_func_arg(self):
        if self.ql.archtype == QL_ARCH.ARM64:
            param0 = self.ql.reg.x0
            param1 = self.ql.reg.x1
            param2 = self.ql.reg.x2
            param3 = self.ql.reg.x3
            param4 = self.ql.reg.x4
            param5 = self.ql.reg.x5
        elif self.ql.archtype == QL_ARCH.ARM:
            param0 = self.ql.reg.r0
            param1 = self.ql.reg.r1
            param2 = self.ql.reg.r2
            param3 = self.ql.reg.r3
            param4 = self.ql.reg.r4
            param5 = self.ql.reg.r5
        elif self.ql.archtype == QL_ARCH.MIPS:
            param0 = self.ql.reg.a0
            param1 = self.ql.reg.a1
            param2 = self.ql.reg.a2
            param3 = self.ql.reg.a3
            param4 = self.ql.reg.sp
            param4 = param4 + 0x10
            param5 = self.ql.reg.sp
            param5 = param5 + 0x14
        elif self.ql.archtype == QL_ARCH.X86:
            param0 = self.ql.reg.ebx
            param1 = self.ql.reg.ecx
            param2 = self.ql.reg.edx
            param3 = self.ql.reg.esi
            param4 = self.ql.reg.edi
            param5 = self.ql.reg.ebp
        elif self.ql.archtype == QL_ARCH.X8664:
            param0 = self.ql.reg.rdi
            param1 = self.ql.reg.rsi
            param2 = self.ql.reg.rdx
            param3 = self.ql.reg.r10
            param4 = self.ql.reg.r8
            param5 = self.ql.reg.r9

        return [param0, param1, param2, param3, param4, param5]
