#!/usr/bin/env python3

from test_shellcode import X8664_LIN, X86_LIN
from qiling.exception import QlMemoryMappedError
from qiling import Qiling
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_ESI
from unicorn import UC_PROT_ALL, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC, UC_PROT_NONE, UcError
import sys
import unittest
sys.path.append("..")


class MemTest(unittest.TestCase):
    def assert_mem_equal(self, ql: "Qiling"):
        map_info = ql.mem.map_info
        mem_regions = list(ql.uc.mem_regions())
        self.assertEqual(len(map_info), len(mem_regions))
        for i, mem_region in enumerate(mem_regions):
            s, e, p, _, _, data = map_info[i]
            self.assertEqual((s, e - 1, p), mem_region)
            uc_mem = ql.mem.read(
                mem_region[0], mem_region[1] - mem_region[0] + 1)
            self.assertEqual(data, uc_mem)

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
        self.assert_mem_equal(ql)

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
        self.assert_mem_equal(ql)

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
        self.assert_mem_equal(ql)

    def test_mem_protect_map_ptr(self):
        ql = Qiling(code=X8664_LIN, archtype="x86_64", ostype="linux")
        val = 0x114514
        data1 = bytearray(0x4000)
        data2 = bytearray(0x2000)
        ql.mem.map(0x4000, 0x4000, UC_PROT_ALL, "data1", data1)
        ql.mem.unmap(0x6000, 0x2000)
        ql.mem.change_mapinfo(0x4000, 0x4000 + 0x2000, UC_PROT_ALL, "data1")
        self.assert_mem_equal(ql)

        # ql.mem.map will call map_ptr and add_mapinfo
        ql.mem.map_ptr(0x6000, 0x2000, UC_PROT_ALL, data2)
        ql.mem.add_mapinfo(0x6000, 0x6000 + 0x2000,
                           UC_PROT_ALL, "data2", False, data2)

        ql.mem.write(0x6004, val.to_bytes(8, "little"))
        ql.mem.protect(0x6000, 0x1000, UC_PROT_READ)
        buf = ql.mem.read(0x6004, 8)
        self.assertEqual(int.from_bytes(buf, 'little'), val)
        self.assert_mem_equal(ql)

    def test_map_at_the_end(self):
        ql = Qiling(code=X8664_LIN, archtype="x86_64", ostype="linux")
        mem = bytearray(0x1000)
        mem[:0x100] = [0xff] * 0x100
        mem = bytes(mem)
        ql.mem.map(0xfffffffffffff000, 0x1000, UC_PROT_ALL)
        ql.mem.write(0xfffffffffffff000, mem)
        self.assertRaises(UcError, ql.mem.write, 0xffffffffffffff00, mem)
        self.assertRaises(UcError, ql.mem.write, 0, mem)
        self.assert_mem_equal(ql)


if __name__ == "__main__":
    unittest.main()
