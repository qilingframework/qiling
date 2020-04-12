#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

from qiling.os.macos.const import *
from qiling.os.macos.mach_port import *
from qiling.const import *
from struct import *
import os

# commpage is a shared mem space which is in a static address
# start at 0x7FFFFFE00000
def load_commpage(ql):
    ql.mem.write(COMM_PAGE_SIGNATURE, b'\x00')
    ql.mem.write(COMM_PAGE_CPU_CAPABILITIES64, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_UNUSED, b'\x00')
    ql.mem.write(COMM_PAGE_VERSION, b'\x0d')
    ql.mem.write(COMM_PAGE_THIS_VERSION, b'\x00')
    ql.mem.write(COMM_PAGE_CPU_CAPABILITIES, b'\x00\x00\x00\x00')
    ql.mem.write(COMM_PAGE_NCPUS, b'\x00')
    ql.mem.write(COMM_PAGE_UNUSED0, b'\x00')
    ql.mem.write(COMM_PAGE_CACHE_LINESIZE, b'\x00')
    ql.mem.write(COMM_PAGE_SCHED_GEN, b'\x00')
    ql.mem.write(COMM_PAGE_MEMORY_PRESSURE, b'\x00')
    ql.mem.write(COMM_PAGE_SPIN_COUNT, b'\x00')
    ql.mem.write(COMM_PAGE_ACTIVE_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_PHYSICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_LOGICAL_CPUS, b'\x00')
    ql.mem.write(COMM_PAGE_UNUSED1, b'\x00')
    ql.mem.write(COMM_PAGE_MEMORY_SIZE, b'\x00')
    ql.mem.write(COMM_PAGE_CPUFAMILY, b'\xec\x5e\x3b\x57')
    ql.mem.write(COMM_PAGE_KDEBUG_ENABLE, b'\x00')
    ql.mem.write(COMM_PAGE_ATM_DIAGNOSTIC_CONFIG, b'\x00')
    ql.mem.write(COMM_PAGE_UNUSED2, b'\x00')
    ql.mem.write(COMM_PAGE_TIME_DATA_START, b'\x00')
    ql.mem.write(COMM_PAGE_NT_TSC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_NT_SCALE, b'\x00')
    ql.mem.write(COMM_PAGE_NT_SHIFT, b'\x00')
    ql.mem.write(COMM_PAGE_NT_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_NT_GENERATION, b'\x01')       # someflag seem important 
    ql.mem.write(COMM_PAGE_GTOD_GENERATION, b'\x00')
    ql.mem.write(COMM_PAGE_GTOD_NS_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_GTOD_SEC_BASE, b'\x00')
    ql.mem.write(COMM_PAGE_APPROX_TIME, b'\x00')
    ql.mem.write(COMM_PAGE_APPROX_TIME_SUPPORTED, b'\x00')
    ql.mem.write(COMM_PAGE_CONT_TIMEBASE, b'\x00')
    ql.mem.write(COMM_PAGE_BOOTTIME_USEC, b'\x00')


def vm_shared_region_enter(ql):
    ql.mem.map(SHARED_REGION_BASE_X86_64, SHARED_REGION_SIZE_X86_64)
    ql.macos_shared_region = True
    ql.macos_shared_region_port = MachPort(9999)        # random port name


def map_commpage(ql):
    if ql.archtype== QL_X8664:
        addr_base = COMM_PAGE_START_ADDRESS
        addr_size = 0x100000
    elif ql.archtype== QL_ARM64:
        addr_base = 0x0000000FFFFFC000
        addr_size = 0x1000        
    ql.mem.map(addr_base, addr_size)
    time_lock_slide = 0x68
    ql.mem.write(addr_base+time_lock_slide, ql.pack32(0x1))


# reference to osfmk/mach/shared_memory_server.h
class SharedFileMappingNp:

    def __init__(self, ql):
        self.size = 32
        self.ql = ql
    
    def read_mapping(self, addr):
        content = self.ql.mem.read(addr, self.size)
        self.sfm_address = unpack("<Q", self.ql.mem.read(addr, 8))[0]
        self.sfm_size = unpack("<Q", self.ql.mem.read(addr + 8, 8))[0]
        self.sfm_file_offset = unpack("<Q", self.ql.mem.read(addr + 16, 8))[0]
        self.sfm_max_prot = unpack("<L", self.ql.mem.read(addr + 24, 4))[0]
        self.sfm_init_prot = unpack("<L", self.ql.mem.read(addr + 28, 4))[0]

        self.ql.dprint(D_INFO, "[ShareFileMapping]: addr: 0x{:X}, size: 0x{:X}, fileOffset:0x{:X}, maxProt: {}, initProt: {}".format(
            self.sfm_address, self.sfm_size, self.sfm_file_offset, self.sfm_max_prot, self.sfm_init_prot
            ))


# reference to bsd/sys/proc_info.h
class ProcRegionWithPathInfo():

    def __init__(self, ql):
        self.ql = ql
        pass
    
    def set_path(self, path):
        self.vnode_info_path_vip_path = path

    def write_info(self, addr):
        addr += 248
        self.ql.mem.write(addr, self.vnode_info_path_vip_path)


# virtual FS
# Only have some basic func now 
# tobe completed
class FileSystem():

    def __init__(self, ql):
        self.ql = ql
        self.base_path = ql.rootfs

    def get_common_attr(self, path, cmn_flags):
        real_path = self.vm_to_real_path(path)
        if not os.path.exists(real_path):
            return None
        attr = b''
        file_stat = os.stat(real_path)
        filename = ""

        if cmn_flags & ATTR_CMN_NAME != 0:
            filename = path.split("/")[-1]
            filename_len = len(filename) + 1        # add \0
            attr += pack("<L", filename_len)
            self.ql.dprint(D_INFO, "FileName :{}, len:{}".format(filename, filename_len))

        if cmn_flags & ATTR_CMN_DEVID != 0:
            attr += pack("<L", file_stat.st_dev)
            self.ql.dprint(D_INFO, "DevID: {}".format(file_stat.st_dev))

        if cmn_flags & ATTR_CMN_OBJTYPE != 0:
            if os.path.isdir(path):
                attr += pack("<L", VDIR)
                self.ql.dprint("ObjType: DIR")
            elif os.path.islink(path):
                attr += pack("<L", VLINK)
                self.ql.dprint(D_INFO, "ObjType: LINK")
            else:
                attr += pack("<L", VREG)
                self.ql.dprint(D_INFO, "ObjType: REG")
            
        if cmn_flags & ATTR_CMN_OBJID != 0:
            attr += pack("<Q", file_stat.st_ino)
            self.ql.dprint(D_INFO, "VnodeID :{}".format(file_stat.st_ino))

        # at last, add name 
        if cmn_flags & ATTR_CMN_NAME != 0:
            name_offset = len(attr) + 4
            attr = pack("<L", name_offset) + attr
            attr += filename.encode("utf8")
            attr += b'\x00'
        
        self.ql.dprint(D_INFO, "Attr : {}".format(attr))
    
        return attr

    def vm_to_real_path(self, vm_path):
        if not vm_path:
            return None
        if vm_path[0] == '/':
            # abs path 
            return os.path.join(self.base_path, vm_path[1:])
        else:
            # rel path
            return os.path.join(self.base_path, vm_path)

    def open(self, path, open_flags, open_mode):

        real_path = self.vm_to_real_path(path)
        
        if real_path:
            return os.open(real_path, open_flags, open_mode)
        else:
            return None

    def isexists(self, path):
        real_path = self.vm_to_real_path(path)
        return os.path.exists(real_path)
