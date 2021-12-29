#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from typing import Callable
import os

from typing import Callable
from unicorn import UcError

from qiling import Qiling
from qiling.os.posix.posix import QlOsPosix
from qiling.os.qnx.const import NTO_SIDE_CHANNEL, SYSMGR_PID, SYSMGR_CHID, SYSMGR_COID
from qiling.os.qnx.helpers import QnxConn
from qiling.os.qnx.structs import _thread_local_storage

from qiling.cc import QlCC, intel, arm, mips, riscv
from qiling.const import QL_ARCH, QL_INTERCEPT
from qiling.os.fcall import QlFunctionCall
from qiling.os.const import *
from qiling.os.posix.const import NR_OPEN
from qiling.os.posix.posix import QlOsPosix

class QlOsQnx(QlOsPosix):
    def __init__(self, ql: Qiling):
        super(QlOsQnx, self).__init__(ql)

        self.ql = ql

        cc: QlCC = {
            QL_ARCH.X86   : intel.cdecl,
            QL_ARCH.X8664 : intel.amd64,
            QL_ARCH.ARM   : arm.aarch32,
            QL_ARCH.ARM64 : arm.aarch64,
            QL_ARCH.MIPS  : mips.mipso32,
            QL_ARCH.RISCV : riscv.riscv,
            QL_ARCH.RISCV64: riscv.riscv,
        }[ql.archtype](ql)

        self.fcall = QlFunctionCall(ql, cc)

        self.thread_class = None
        self.futexm = None
        self.fh = None
        self.function_after_load_list = []
        self.elf_mem_start = 0x0
        self.load()
        
        # use counters to get free Ids
        self.channel_id = 1
        # TODO: replace 0x400 with NR_OPEN from Qiling 1.25
        self.connection_id_lo = 0x400 + 1
        self.connection_id_hi = NTO_SIDE_CHANNEL + 1
        # map Connection Id (coid) to Process Id (pid) and Channel Id (chid)
        self.connections = {}
        self.connections[0] = QnxConn(SYSMGR_PID, SYSMGR_CHID, fd = self.stdin.fileno())
        self.connections[1] = QnxConn(SYSMGR_PID, SYSMGR_CHID, fd = self.stdout.fileno())
        self.connections[2] = QnxConn(SYSMGR_PID, SYSMGR_CHID, fd = self.stderr.fileno())
        self.connections[SYSMGR_COID] = QnxConn(SYSMGR_PID, SYSMGR_CHID)

    def load(self):
        if self.ql.code:
            return

        # ARM
        if self.ql.archtype == QL_ARCH.ARM:
            self.ql.arch.enable_vfp()
            self.ql.hook_intno(self.hook_syscall, 2)
            #self.thread_class = thread.QlLinuxARMThread
            self.ql.arch.init_get_tls()

    
    def hook_syscall(self, intno= None, int = None):
        return self.load_syscall()


    def add_function_hook(self, fn: str, cb: Callable, intercept: QL_INTERCEPT):
        self.ql.os.function_hook.add_function_hook(fn, cb, intercept)


    def register_function_after_load(self, function):
        if function not in self.function_after_load_list:
            self.function_after_load_list.append(function)


    def run_function_after_load(self):
        for f in self.function_after_load_list:
            f()


    def hook_sigtrap(self, intno= None, int = None):
        self.ql.log.info("Trap Found")
        self.emu_error()
        exit(1)


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point

        self.cpupage_addr        = int(self.ql.os.profile.get("OS32", "cpupage_address"), 16)
        self.cpupage_tls_addr    = int(self.ql.os.profile.get("OS32", "cpupage_tls_address"), 16)
        self.tls_data_addr       = int(self.ql.os.profile.get("OS32", "tls_data_address"), 16)
        self.syspage_addr        = int(self.ql.os.profile.get("OS32", "syspage_address"), 16)
        syspage_path             = os.path.join(self.ql.rootfs, "syspage.bin")

        self.ql.mem.map(self.syspage_addr, 0x4000, info="[syspage_mem]")
        
        with open(syspage_path, "rb") as sp:
            self.ql.mem.write(self.syspage_addr, sp.read())

        # Address of struct _thread_local_storage for our thread
        self.ql.mem.write(self.cpupage_addr, self.ql.pack32(self.cpupage_tls_addr))
        tls = _thread_local_storage(self.ql, self.cpupage_tls_addr)

        # Fill TLS structure with proper values
        tls._errptr.value = self.tls_data_addr
        tls.pid = self.ql.os.pid
        tls.tid = 1

        # Write TLS to memory
        tls.updateToMem()

        # Address of the system page
        self.ql.mem.write(self.cpupage_addr + 8, self.ql.pack32(self.syspage_addr))

        try:
            if self.ql.code:
                self.ql.emu_start(self.entry_point, (self.entry_point + len(self.ql.code)), self.ql.timeout, self.ql.count)
            else:
                if self.ql.loader.elf_entry != self.ql.loader.entry_point:
                    entry_address = self.ql.loader.elf_entry
                    if self.ql.archtype == QL_ARCH.ARM and entry_address & 1 == 1:
                        entry_address -= 1
                    self.ql.emu_start(self.ql.loader.entry_point, entry_address, self.ql.timeout)
                    self.run_function_after_load()
                    self.ql.loader.skip_exit_check = False
                    self.ql.write_exit_trap()

                self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            self.emu_error()
            raise
