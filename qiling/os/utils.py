#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.os
"""

import struct, os
from json import dumps

from binascii import unhexlify

try:
    from keystone import *
except:
    pass

from unicorn import *
from unicorn.arm_const import *
from unicorn.x86_const import *
from unicorn.arm64_const import *
from unicorn.mips_const import *

from capstone import *
from capstone.arm_const import *
from capstone.x86_const import *
from capstone.arm64_const import *
from capstone.mips_const import *

from qiling.const import *
from qiling.exception import *
from .const import *


class QLOsUtils:
    def __init__(self, ql):
        self.ql = ql
        self.archtype = None
        self.ostype = None
        self.path = None
        self.archendian = None

    def lsbmsb_convert(self, sc, size=4):
        split_bytes = []
        n = size
        for index in range(0, len(sc), n):
            split_bytes.append((sc[index: index + n])[::-1])

        ebsc = b""
        for i in split_bytes:
            ebsc += i

        return ebsc

    def compile_asm(self, archtype, runcode, arm_thumb=None):
        try:
            loadarch = KS_ARCH_X86
        except:
            raise QlErrorOutput("Please install Keystone Engine")

        def ks_convert(arch):
            if self.ql.archendian == QL_ENDIAN.EB:
                adapter = {
                    QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                    QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                    QL_ARCH.MIPS: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN),
                    QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_BIG_ENDIAN),
                    QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                    QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_ARM),
                }
            else:
                adapter = {
                    QL_ARCH.X86: (KS_ARCH_X86, KS_MODE_32),
                    QL_ARCH.X8664: (KS_ARCH_X86, KS_MODE_64),
                    QL_ARCH.MIPS: (KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_LITTLE_ENDIAN),
                    QL_ARCH.ARM: (KS_ARCH_ARM, KS_MODE_ARM),
                    QL_ARCH.ARM_THUMB: (KS_ARCH_ARM, KS_MODE_THUMB),
                    QL_ARCH.ARM64: (KS_ARCH_ARM64, KS_MODE_ARM),
                }

            if arch in adapter:
                return adapter[arch]
            # invalid
            return None, None

        def compile_instructions(fname, archtype, archmode):
            f = open(fname, 'rb')
            assembly = f.read()
            f.close()

            ks = Ks(archtype, archmode)

            shellcode = ''
            try:
                # Initialize engine in X86-32bit mode
                encoding, count = ks.asm(assembly)
                shellcode = ''.join('%02x' % i for i in encoding)
                shellcode = unhexlify(shellcode)

            except KsError as e:
                raise

            return shellcode

        if arm_thumb1 and archtype == QL_ARCH.ARM:
            archtype = QL_ARCH.ARM_THUMB

        archtype, archmode = ks_convert(archtype)
        return compile_instructions(runcode, archtype, archmode)

    def transform_to_link_path(self, path):
        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        rootfs = self.ql.rootfs

        if path[0] == '/':
            relative_path = os.path.abspath(path)
        else:
            relative_path = os.path.abspath(cur_path + '/' + path)

        from_path = None
        to_path = None
        for fm, to in self.ql.fs_mapper:
            fm_l = len(fm)
            if len(relative_path) >= fm_l and relative_path[: fm_l] == fm:
                from_path = fm
                to_path = to
                break

        if from_path is not None:
            real_path = os.path.abspath(to_path + relative_path[fm_l:])
        else:
            real_path = os.path.abspath(rootfs + '/' + relative_path)

        return real_path

    def transform_to_real_path(self, path):
        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        rootfs = self.ql.rootfs

        if path[0] == '/':
            relative_path = os.path.abspath(path)
        else:
            relative_path = os.path.abspath(cur_path + '/' + path)

        from_path = None
        to_path = None
        for fm, to in self.ql.fs_mapper:
            fm_l = len(fm)
            if len(relative_path) >= fm_l and relative_path[: fm_l] == fm:
                from_path = fm
                to_path = to
                break

        if from_path is not None:
            real_path = os.path.abspath(to_path + relative_path[fm_l:])
        else:
            if rootfs is None:
                rootfs = ""
            real_path = os.path.abspath(rootfs + '/' + relative_path)

            if os.path.islink(real_path):
                link_path = os.readlink(real_path)
                if link_path[0] == '/':
                    real_path = self.ql.os.transform_to_real_path(link_path)
                else:
                    real_path = self.ql.os.transform_to_real_path(os.path.dirname(relative_path) + '/' + link_path)

                # FIXME: Quick and dirty fix. Need to check more
                if not os.path.exists(real_path):
                    real_path = os.path.abspath(rootfs + '/' + relative_path)

                    if os.path.islink(real_path):
                        link_path = os.readlink(real_path)
                    else:
                        link_path = relative_path

                    path_dirs = link_path.split(os.path.sep)
                    if link_path[0] == '/':
                        path_dirs = path_dirs[1:]

                    for i in range(0, len(path_dirs) - 1):
                        path_prefix = os.path.sep.join(path_dirs[:i + 1])
                        real_path_prefix = self.ql.os.transform_to_real_path(path_prefix)
                        path_remain = os.path.sep.join(path_dirs[i + 1:])
                        real_path = os.path.join(real_path_prefix, path_remain)
                        if os.path.exists(real_path):
                            break

        return real_path

    def transform_to_relative_path(self, path):
        if self.ql.multithread:
            cur_path = self.ql.os.thread_management.cur_thread.get_current_path()
        else:
            cur_path = self.ql.os.current_path

        if path[0] == '/':
            relative_path = os.path.abspath(path)
        else:
            relative_path = os.path.abspath(cur_path + '/' + path)

        return relative_path

    def post_report(self):
        self.ql.dprint(D_RPRT, "[+] Syscalls called")
        for key, values in self.ql.os.syscalls.items():
            self.ql.dprint(D_RPRT, "[-] %s:" % key)
            for value in values:
                self.ql.dprint(D_RPRT, "[-] %s " % str(dumps(value)))
        self.ql.dprint(D_RPRT, "[+] Registries accessed")
        for key, values in self.ql.os.registry_manager.accessed.items():
            self.ql.dprint(D_RPRT, "[-] %s:" % key)
            for value in values:
                self.ql.dprint(D_RPRT, "[-] %s " % str(dumps(value)))
        self.ql.dprint(D_RPRT, "[+] Strings")
        for key, values in self.ql.os.appeared_strings.items():
            val = " ".join([str(word) for word in values])
            self.ql.dprint(D_RPRT, "[-] %s: %s" % (key, val))


    def exec_arbitrary(self, start, end):
        old_sp = self.ql.reg.arch_sp

        # we read where this hook is supposed to return
        ret = self.ql.stack_read(0)

        def restore(ql):
            ql.dprint(D_INFO, "[+] Executed code from %d to %d " % (start, end))
            # now we can restore the register to be where we were supposed to
            old_hook_addr = ql.reg.arch_pc
            ql.reg.arch_sp = old_sp
            ql.reg.arch_pc = ret
            # we want to execute the code once, not more
            ql.hook_address(lambda q: None, old_hook_addr)

        # we have to set an address to restore the registers
        self.ql.hook_address(restore, end, )
        # we want to rewrite the return address to the function
        self.ql.stack_write(0, start)

    def disassembler(self, ql, address, size):
        tmp = self.ql.mem.read(address, size)

        if self.ql.archtype == QL_ARCH.ARM:  # QL_ARM
            reg_cpsr = self.ql.reg.cpsr
            mode = CS_MODE_ARM
            if self.ql.archendian == QL_ENDIAN.EB:
                reg_cpsr_v = 0b100000
                # reg_cpsr_v = 0b000000
            else:
                reg_cpsr_v = 0b100000

            if reg_cpsr & reg_cpsr_v != 0:
                mode = CS_MODE_THUMB

            if self.ql.archendian == QL_ENDIAN.EB:
                md = Cs(CS_ARCH_ARM, mode)
                # md = Cs(CS_ARCH_ARM, mode + CS_MODE_BIG_ENDIAN)
            else:
                md = Cs(CS_ARCH_ARM, mode)

        elif self.ql.archtype == QL_ARCH.X86:  # QL_X86
            md = Cs(CS_ARCH_X86, CS_MODE_32)

        elif self.ql.archtype == QL_ARCH.X8664:  # QL_X86_64
            md = Cs(CS_ARCH_X86, CS_MODE_64)

        elif self.ql.archtype == QL_ARCH.ARM64:  # QL_ARM64
            md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

        elif self.ql.archtype == QL_ARCH.MIPS:  # QL_MIPS32
            if self.ql.archendian == QL_ENDIAN.EB:
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
            else:
                md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)

        else:
            raise QlErrorArch("[!] Unknown arch defined in utils.py (debug output mode)")

        insn = md.disasm(tmp, address)
        opsize = int(size)

        self.ql.nprint("[+] 0x%x\t" % (address), end="")

        for i in tmp:
            self.ql.nprint(" %02x " % i, end="")

        if opsize <= 6:
            self.ql.nprint("\t", end="")

        for i in insn:
            self.ql.nprint("%s %s" % (i.mnemonic, i.op_str))

        if self.ql.output == QL_OUTPUT.DUMP:
            for reg in self.ql.reg.table:
                REG_NAME = reg
                REG_VAL = self.ql.reg.read(reg)
                self.ql.dprint(D_INFO, "[-] %s\t:\t 0x%x" % (REG_NAME, REG_VAL))

    def setup_output(self):
        def ql_hook_block_disasm(ql, address, size):
            self.ql.nprint("\n[+] Tracing basic block at 0x%x" % (address))

        if self.ql.output in (QL_OUTPUT.DISASM, QL_OUTPUT.DUMP):
            if self.ql.output == QL_OUTPUT.DUMP:
                self.ql.hook_block(ql_hook_block_disasm)
            self.ql.hook_code(self.disassembler)

    def stop(self, stop_event=THREAD_EVENT_EXIT_GROUP_EVENT):
        if self.ql.multithread:
            td = self.thread_management.cur_thread
            td.stop()
            td.stop_event = stop_event
        self.ql.emu_stop()
