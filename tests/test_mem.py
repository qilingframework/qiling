#!/usr/bin/env python3

import sys
import unittest
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE
from qiling.exception import QlMemoryMappedError
from qiling.os.posix.syscall.mman import ql_syscall_mmap2
from qiling.os.posix.syscall.unistd import ql_syscall_brk
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESI
from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_NONE, UcError
from test_shellcode import MIPS32EL_LIN, X8664_LIN, X86_LIN


test_r2 = False
if test_r2:  # use R2Qiling as Qiling instead
    from qiling.extensions.r2 import R2Qiling as Qiling

class MemTest(unittest.TestCase):
    def test_map_correct(self):
        ql = Qiling(code=X8664_LIN, archtype="x86_64", ostype="linux")
        ql.mem.map(0x40000, 0x1000 * 16, UC_PROT_ALL)  # [0x40000, 0x50000]
        ql.mem.map(0x60000, 0x1000 * 16, UC_PROT_ALL)  # [0x60000, 0x70000]
        ql.mem.map(0x20000, 0x1000 * 16, UC_PROT_ALL)  # [0x20000, 0x30000]
        self.assertRaises(QlMemoryMappedError, ql.mem.map,
                          0x10000, 0x2000 * 16, UC_PROT_ALL)
        self.assertRaises(QlMemoryMappedError, ql.mem.map,
                          0x25000, 0x1000 * 16, UC_PROT_ALL)
        self.assertRaises(QlMemoryMappedError, ql.mem.map,
                          0x35000, 0x1000 * 16, UC_PROT_ALL)
        self.assertRaises(QlMemoryMappedError, ql.mem.map,
                          0x45000, 0x1000 * 16, UC_PROT_ALL)
        self.assertRaises(QlMemoryMappedError, ql.mem.map,
                          0x55000, 0x2000 * 16, UC_PROT_ALL)
        ql.mem.map(0x50000, 0x5000, UC_PROT_ALL)
        ql.mem.map(0x35000, 0x5000, UC_PROT_ALL)
        self.assertEqual(len(ql.mem.map_info), 5 + 2)  # GDT, shellcode_stack

    def test_mem_protect(self):
        ql = Qiling(code=X86_LIN, archtype="x86", ostype="linux")
        code = bytes([0x01, 0x70, 0x04])
        r_eax = 0x2000
        r_esi = 0xdeadbeef
        ql.arch.regs.write(UC_X86_REG_EAX, r_eax)
        ql.arch.regs.write(UC_X86_REG_ESI, r_esi)
        ql.mem.map(0x1000, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        ql.mem.map(0x2000, 0x1000, UC_PROT_READ)
        ql.mem.protect(0x2000, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        ql.mem.write(0x1000, code)
        ql.emu_start(0x1000, 0x1000 + len(code) - 1, 0, 1)
        buf = ql.mem.read(0x2000 + 4, 4)
        self.assertEqual(int.from_bytes(buf, "little"), 0xdeadbeef)

    def test_splitting_mem_unmap(self):
        ql = Qiling(code=X86_LIN, archtype="x86", ostype="linux")
        ql.mem.map(0x20000, 0x1000, UC_PROT_NONE)
        ql.mem.map(0x21000, 0x2000, UC_PROT_NONE)
        try:
            ql.mem.unmap(0x21000, 0x1000)
        except UcError as e:
            print(e)
            for s, e, p in ql.uc.mem_regions():
                print(hex(s), hex(e), p)
            for line in ql.mem.get_formatted_mapinfo():
                print(line)

    @unittest.skipUnless(test_r2, "Requires R2Qiling refactoring ql.mem")
    def test_mem_protect_map_ptr(self):
        ql = Qiling(code=X8664_LIN, archtype="x86_64", ostype="linux")
        val = 0x114514
        data1 = bytearray(0x4000)
        data2 = bytearray(0x2000)
        ql.mem.map(0x4000, 0x4000, UC_PROT_ALL, "data1", data1)
        ql.mem.unmap(0x6000, 0x2000)
        ql.mem.change_mapinfo(0x4000, 0x4000 + 0x2000, UC_PROT_ALL, "data1")

        # ql.mem.map will call map_ptr and add_mapinfo
        ql.mem.map_ptr(0x6000, 0x2000, UC_PROT_ALL, data2)
        ql.mem.add_mapinfo(0x6000, 0x6000 + 0x2000,
                           UC_PROT_ALL, "data2", False, data2)

        ql.mem.write(0x6004, val.to_bytes(8, "little"))
        ql.mem.protect(0x6000, 0x1000, UC_PROT_READ)
        buf = ql.mem.read(0x6004, 8)
        self.assertEqual(int.from_bytes(buf, 'little'), val)

    def test_map_at_the_end(self):
        ql = Qiling(code=X8664_LIN, archtype="x86_64", ostype="linux")
        mem = bytearray(0x1000)
        mem[:0x100] = [0xff] * 0x100
        mem = bytes(mem)
        ql.mem.map(0xfffffffffffff000, 0x1000, UC_PROT_ALL)
        ql.mem.write(0xfffffffffffff000, mem)
        self.assertRaises(UcError, ql.mem.write, 0xffffffffffffff00, mem)
        self.assertRaises(UcError, ql.mem.write, 0, mem)

    def test_mmap2(self):
        ql = Qiling(code=X86_LIN, archtype="x86", ostype="linux", verbose=QL_VERBOSE.DEBUG)
        ql.loader.mmap_address = int(ql.profile.get('OS32', 'mmap_address'), 0)
        ql_syscall_mmap2(ql, 0, 8192, 3, 2050, 4294967295, 0)
        del ql

        ql = Qiling(code=MIPS32EL_LIN, archtype="mips", ostype="linux", verbose=QL_VERBOSE.DEBUG)
        ql.loader.mmap_address = int(ql.profile.get('OS32', 'mmap_address'), 0)
        ql_syscall_mmap2(ql, 0, 8192, 3, 2050, 4294967295, 0)
        del ql


if __name__ == "__main__":
    unittest.main()
