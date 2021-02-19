#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import sys

from .const import *
from .filestruct import ql_file
from .mapper import QlFsMapper
from .utils import QlOsUtils

from qiling.const import QL_OS, QL_INTERCEPT, QL_OS_POSIX

class QlOs(QlOsUtils):
    def __init__(self, ql):
        #super(QlOs, self).__init__(ql)
        QlOsUtils.__init__(self, ql)

        self.ql = ql
        self.fcall = None
        self.fs_mapper = QlFsMapper(ql)
        self.child_processes = False
        self.thread_management = None
        self.profile = self.ql.profile
        self.current_path = self.profile.get("MISC", "current_path")
        self.exit_code = 0
        self.services = {}
        self.elf_mem_start = 0x0

        self.user_defined_api = {}
        self.user_defined_api_onenter = {}
        self.user_defined_api_onexit = {}

        if not hasattr(sys.stdin, "fileno") or not hasattr(sys.stdout, "fileno") or not hasattr(sys.stderr, "fileno"):
            # IDAPython has some hack on standard io streams and thus they don't have corresponding fds.

            self.stdin  = sys.stdin.buffer  if hasattr(sys.stdin,  "buffer") else sys.stdin
            self.stdout = sys.stdout.buffer if hasattr(sys.stdout, "buffer") else sys.stdout
            self.stderr = sys.stderr.buffer if hasattr(sys.stderr, "buffer") else sys.stderr
        else:
            self.stdin  = ql_file('stdin',  sys.stdin.fileno())
            self.stdout = ql_file('stdout', sys.stdout.fileno())
            self.stderr = ql_file('stderr', sys.stderr.fileno())

        if self.ql.stdin != 0:
            self.stdin = self.ql.stdin

        if self.ql.stdout != 0:
            self.stdout = self.ql.stdout

        if self.ql.stderr != 0:
            self.stderr = self.ql.stderr

        # defult exit point
        self.exit_point = {
            16: 0xfffff,            # 20bit address lane
            32: 0x8fffffff,
            64: 0xffffffffffffffff
        }.get(self.ql.archbit, None)

        if self.ql.code:
            self.code_ram_size = int(self.profile.get("CODE", "ram_size"), 16)
            # this shellcode entrypoint does not work for windows
            # windows shellcode entry point will comes from pe loader
            self.entry_point = int(self.profile.get("CODE", "entry_point"), 16)

        # We can save every syscall called
        self.syscalls = {}
        self.syscalls_counter = 0
        self.appeared_strings = {}
        self.setup_output()

    def save(self):
        return {}

    def restore(self, saved_state):
        pass

    def set_api(self, api_name, intercept_function, intercept):
        if self.ql.ostype == QL_OS.UEFI:
            api_name = "hook_" + str(api_name)

        if intercept == QL_INTERCEPT.ENTER:
            if (self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI)) or (self.ql.ostype in (QL_OS_POSIX) and self.ql.loader.is_driver):
                self.user_defined_api_onenter[api_name] = intercept_function
            else:
                self.add_function_hook(api_name, intercept_function, intercept) 

        elif intercept == QL_INTERCEPT.EXIT:
            if (self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI)) or (self.ql.ostype in (QL_OS_POSIX) and self.ql.loader.is_driver):
                self.user_defined_api_onexit[api_name] = intercept_function  
            else:
                self.add_function_hook(api_name, intercept_function, intercept)           

        else:
            if (self.ql.ostype in (QL_OS.WINDOWS, QL_OS.UEFI)) or (self.ql.ostype in (QL_OS_POSIX) and self.ql.loader.is_driver):
                self.user_defined_api[api_name] = intercept_function
            else:
                self.add_function_hook(api_name, intercept_function)  

    def find_containing_image(self, pc):
        for image in self.ql.loader.images:
            if image.base <= pc < image.end:
                return image

    def emu_error(self):
        self.ql.log.error("\n")

        for reg in self.ql.reg.register_mapping:
            if isinstance(reg, str):
                REG_NAME = reg
                REG_VAL = self.ql.reg.read(reg)
                self.ql.log.error("%s\t:\t 0x%x" % (REG_NAME, REG_VAL))

        self.ql.log.error("\n")
        self.ql.log.error("PC = 0x%x" % (self.ql.reg.arch_pc))
        containing_image = self.find_containing_image(self.ql.reg.arch_pc)
        if containing_image:
            offset = self.ql.reg.arch_pc - containing_image.base
            self.ql.log.error(" (%s+0x%x)" % (containing_image.path, offset))
        else:
            self.ql.log.info("\n")
        self.ql.mem.show_mapinfo()

        try:
            buf = self.ql.mem.read(self.ql.reg.arch_pc, 8)
            self.ql.log.error("%r" % ([hex(_) for _ in buf]))

            self.ql.log.info("\n")
            self.disassembler(self.ql, self.ql.reg.arch_pc, 64)
        except:
            self.ql.log.error("Error: PC(0x%x) Unreachable" % self.ql.reg.arch_pc)

    def clear_syscalls(self):
        self.syscalls = {}
        self.syscalls_counter = 0
        self.appeared_strings = {}


    def _call_api(self, name, params, result, address, return_address):
        if name.startswith("hook_"):
            name = name[5:]

        self.syscalls.setdefault(name, []).append({
            "params": params,
            "result": result,
            "address": address,
            "return_address": return_address,
            "position": self.syscalls_counter
        })

        self.syscalls_counter += 1