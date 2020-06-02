#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

"""
This module is intended for general purpose functions that are only used in qiling.os
"""

import os, struct, uuid
from json import dumps

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

        self.ql.nprint( ("[+] 0x%x" % (address)).ljust( (self.ql.archbit // 8) + 15), end="")

        temp_str = ""
        for i in tmp:
            temp_str += ("%02x " % i)
        self.ql.nprint(temp_str.ljust(30), end="")

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

    def read_guid(self, address):
        result = ""
        raw_guid = self.ql.mem.read(address, 16)
        return uuid.UUID(bytes_le=bytes(raw_guid))


    def string_appearance(self, string):
        strings = string.split(" ")
        for string in strings:
            val = self.appeared_strings.get(string, set())
            val.add(self.syscalls_counter)
            self.appeared_strings[string] = val


    def read_wstring(self, address):
        result = ""
        char = self.ql.mem.read(address, 2)
        while char.decode(errors="ignore") != "\x00\x00":
            address += 2
            result += char.decode(errors="ignore")
            char = self.ql.mem.read(address, 2)
        # We need to remove \x00 inside the string. Compares do not work otherwise
        result = result.replace("\x00", "")
        self.string_appearance(result)
        return result


    def read_cstring(self, address):
        result = ""
        char = self.ql.mem.read(address, 1)
        while char.decode(errors="ignore") != "\x00":
            address += 1
            result += char.decode(errors="ignore")
            char = self.ql.mem.read(address, 1)
        self.string_appearance(result)
        return result


    def print_function(self, address, function_name, params, ret):
        function_name = function_name.replace('hook_', '')
        if function_name in ("__stdio_common_vfprintf", "__stdio_common_vfwprintf", "printf", "wsprintfW", "sprintf"):
            return
        log = '0x%0.2x: %s(' % (address, function_name)
        for each in params:
            value = params[each]
            if isinstance(value, str) or type(value) == bytearray:
                log += '%s = "%s", ' % (each, value)
            elif isinstance(value, tuple):
                # we just need the string, not the address in the log
                log += '%s = "%s", ' % (each, value[1])
            else:
                log += '%s = 0x%x, ' % (each, value)
        log = log.strip(", ")
        log += ')'
        if ret is not None:
            log += ' = 0x%x' % ret

        if self.ql.output != QL_OUTPUT.DEBUG:
            log = log.partition(" ")[-1]
            self.ql.nprint(log)
        else:
            self.ql.dprint(D_INFO, log)

    def printf(self, address, fmt, params_addr, name, wstring=False, double_pointer=False):
        count = fmt.count("%")
        params = []
        if count > 0:
            for i in range(count):
                # We don't need to mem_read here, otherwise we have a problem with strings, since read_wstring/read_cstring
                #  already take a pointer, and we will have pointer -> pointer -> STRING instead of pointer -> STRING
                params.append(
                    params_addr + i * self.ql.pointersize,
                )

            formats = fmt.split("%")[1:]
            index = 0
            for f in formats:
                if f.startswith("s"):
                    if wstring:
                        if double_pointer:
                            params[index] = self.ql.unpack32(self.ql.mem.read(params[index], self.ql.pointersize))
                        params[index] = self.ql.os.read_wstring(params[index])
                    else:
                        params[index] = self.ql.os.read_cstring(params[index])
                else:
                    # if is not a string, then they are already values!
                    pass
                index += 1

            output = '%s(format = %s' % (name, repr(fmt))
            for each in params:
                if type(each) == str:
                    output += ', "%s"' % each
                else:
                    output += ', 0x%0.2x' % each
            output += ')'
            fmt = fmt.replace("%llx", "%x")
            stdout = fmt % tuple(params)
            output += " = 0x%x" % len(stdout)
        else:
            output = '%s(format = %s) = 0x%x' % (name, repr(fmt), len(fmt))
            stdout = fmt
        self.ql.nprint(output)
        self.ql.os.stdout.write(bytes(stdout, 'utf-8'))
        return len(stdout), stdout            