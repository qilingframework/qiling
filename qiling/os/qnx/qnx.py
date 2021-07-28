#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os
from unicorn import UcError

from qiling.os.posix.posix import QlOsPosix
from qiling.os.qnx.const import NTO_SIDE_CHANNEL, SYSMGR_PID, SYSMGR_CHID, SYSMGR_COID
from qiling.os.qnx.helpers import QnxConn
from qiling.os.qnx.structs import _thread_local_storage
from qiling.const import QL_ARCH

class QlOsQnx(QlOsPosix):
    def __init__(self, ql):
        super(QlOsQnx, self).__init__(ql)
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

        if self.ql.archtype!= QL_ARCH.ARM:
            return

        self.ql.arch.enable_vfp()
        self.ql.hook_intno(self.hook_syscall, 2)

    
    def hook_syscall(self, intno= None, int = None):
        return self.load_syscall()


    def hook_sigtrap(self, intno= None, int = None):
        self.ql.log.info("Trap Found")
        self.emu_error()
        exit(1)


    def run(self):
        if self.ql.exit_point is not None:
            self.exit_point = self.ql.exit_point

        if  self.ql.entry_point is not None:
            self.ql.loader.elf_entry = self.ql.entry_point

        self.cpupage_addr = int(self.ql.os.profile.get("OS32", "cpupage_address"), 16)
        self.cpupage_tls_addr = int(self.ql.os.profile.get("OS32", "cpupage_tls_address"), 16)
        self.tls_data_addr = int(self.ql.os.profile.get("OS32", "tls_data_address"), 16)

        self.syspage_addr = int(self.ql.os.profile.get("OS32", "syspage_address"), 16)

        self.ql.mem.map(self.syspage_addr, 0x4000, info="[syspage_mem]")

        syspage_path = os.path.join(self.ql.rootfs, "syspage.bin")
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
                    self.ql.emu_start(self.ql.loader.entry_point, self.ql.loader.elf_entry, self.ql.timeout)
                    self.ql.enable_lib_patch()

                self.ql.emu_start(self.ql.loader.elf_entry, self.exit_point, self.ql.timeout, self.ql.count)

        except UcError:
            self.emu_error()
            raise
