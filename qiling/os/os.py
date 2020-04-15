#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

import os

from qiling.const import *
from qiling.utils import *

from .utils import *
from .const import *
from .filestruct import ql_file

class QlOs:
    def __init__(self, ql):
        self.ql = ql
        self.stdin = ql_file('stdin', sys.stdin.fileno())
        self.stdout = ql_file('stdout', sys.stdout.fileno())
        self.stderr = ql_file('stderr', sys.stderr.fileno())
        self.child_processes = False
        self.thread_management = None
        self.current_path = '/'

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin
        
        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout
        
        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        # define analysis enviroment profile
        if not self.ql.profile:
            self.profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".." ,"profiles", ql_ostype_convert_str(self.ql.ostype) + ".ql")

        if self.ql.archbit == 32:
            self.QL_EMU_END = QL_ARCHBIT32_EMU_END
        elif self.ql.archbit == 64:
            self.QL_EMU_END = QL_ARCHBIT64_EMU_END           

    def transform_to_real_path(self, path):
        return ql_transform_to_real_path(self.ql, path)

    def transform_to_relative_path(self, path):
        return ql_transform_to_relative_path(self.ql, path)
    
    def transform_to_link_path(self, path):
        return ql_transform_to_link_path(self.ql, path)

    def post_report(self):
        ql_post_report(self)

    def setup_output(self):
        def ql_hook_block_disasm(ql, address, size):
            self.ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

        def ql_hook_code_disasm(ql, address, size):
            tmp = ql.mem.read(address, size)

            if (ql.archtype== QL_ARCH.ARM):  # QL_ARM
                reg_cpsr = ql.register(UC_ARM_REG_CPSR)
                mode = CS_MODE_ARM
                if ql.archendian == QL_ENDIAN.EB:
                    reg_cpsr_v = 0b100000
                    # reg_cpsr_v = 0b000000
                else:
                    reg_cpsr_v = 0b100000

                if reg_cpsr & reg_cpsr_v != 0:
                    mode = CS_MODE_THUMB

                if ql.archendian == QL_ENDIAN.EB:
                    md = Cs(CS_ARCH_ARM, mode)
                    # md = Cs(CS_ARCH_ARM, mode + CS_MODE_BIG_ENDIAN)
                else:
                    md = Cs(CS_ARCH_ARM, mode)

            elif (ql.archtype == QL_ARCH.X86):  # QL_X86
                md = Cs(CS_ARCH_X86, CS_MODE_32)

            elif (ql.archtype == QL_ARCH.X8664):  # QL_X86_64
                md = Cs(CS_ARCH_X86, CS_MODE_64)

            elif (ql.archtype == QL_ARCH.ARM64):  # QL_ARM64
                md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

            elif (ql.archtype == QL_ARCH.MIPS32):  # QL_MIPS32
                if ql.archendian == QL_ENDIAN.EB:
                    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
                else:
                    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

            else:
                raise QlErrorArch("[!] Unknown arch defined in utils.py (debug output mode)")

            insn = md.disasm(tmp, address)
            opsize = int(size)

            ql.nprint("[+] 0x%x\t" % (address), end="")

            for i in tmp:
                ql.nprint (" %02x " % i, end="")

            if opsize <= 6:
                ql.nprint ("\t", end="")
            
            for i in insn:
                ql.nprint ("%s %s" % (i.mnemonic, i.op_str))
            
            if ql.output == QL_OUTPUT.DUMP:
                for reg in ql.reg.table:
                    ql.reg.name = reg
                    REG_NAME = ql.reg.name
                    REG_VAL = ql.register(reg)
                    ql.dprint(D_INFO, "[-] %s\t:\t 0x%x" % (REG_NAME, REG_VAL))
        
        if self.ql.output in (QL_OUTPUT.DISASM, QL_OUTPUT.DUMP):
            if self.ql.output == QL_OUTPUT.DUMP:
                self.ql.hook_block(ql_hook_block_disasm)
            self.ql.hook_code(ql_hook_code_disasm)


    def stop(self, stop_event=THREAD_EVENT_EXIT_GROUP_EVENT):
        if self.ql.multithread == True:
            td = self.thread_management.cur_thread
            td.stop()
            td.stop_event = stop_event
        self.ql.emu_stop()