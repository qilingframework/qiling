#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.utils import ql_get_module_function

from .context import Context
from .arch import ArchCORTEX_M, ArchARM, ArchMIPS, ArchX86

class MemoryManager(Context, ArchX86, ArchCORTEX_M, ArchARM, ArchMIPS):
    """
    memory manager for handing memory access 
    """

    def __init__(self, ql):
        super().__init__(ql)

        for arch in ("ArchARM", "ArchMIPS", "ArchCORTEX_M", "ArchX86"):
            if ql.archtype.name in str(arch):
                imp_arch = ql_get_module_function("qiling.debugger.qdb.arch", arch)

        imp_arch.__init__(self)

        self.DEFAULT_FMT = ('x', 4, 1)

        self.FORMAT_LETTER = {
                "o", # octal
                "x", # hex
                "d", # decimal
                "u", # unsigned decimal
                "t", # binary
                "f", # float
                "a", # address
                "i", # instruction
                "c", # char
                "s", # string
                "z", # hex, zero padded on the left
                }

        self.SIZE_LETTER = {
            "b": 1, # 1-byte, byte
            "h": 2, # 2-byte, halfword
            "w": 4, # 4-byte, word
            "g": 8, # 8-byte, giant
            }

    def extract_count(self, t):
        return "".join([s for s in t if s.isdigit()])

    def get_fmt(self, text):
        f, s, c = self.DEFAULT_FMT
        if self.extract_count(text):
            c = int(self.extract_count(text))

        for char in text.strip(str(c)):
            if char in self.SIZE_LETTER.keys():
                s = self.SIZE_LETTER.get(char)

            elif char in self.FORMAT_LETTER:
                f = char

        return (f, s, c)

    def fmt_unpack(self, bs: bytes, sz: int) -> int:
        return {
                1: lambda x: x[0],
                2: self.unpack16,
                4: self.unpack32,
                8: self.unpack64,
                }.get(sz)(bs)

    def parse(self, line: str):

        # test case
        # x/wx address
        # x/i address
        # x $sp
        # x $sp +0xc
        # x $sp+0xc
        # x $sp + 0xc

        if line.startswith("/"):  # followed by format letter and size letter

            fmt, *rest = line.strip("/").split()

            fmt = self.get_fmt(fmt)

        else:
            args = line.split()
            rest = args[0] if  len(args) == 1 else args
            fmt = self.DEFAULT_FMT

        if (regs_dict := getattr(self, "regs_need_swapped", None)):
            for each in rest:
                if each in regs_dict:

        # for simple calculation with register and address 
        new_line = rest

        # substitue register name with real value  
        for each_reg in filter(lambda r: len(r) == 3, self.ql.reg.register_mapping.keys()):
            if each_reg in new_line:
                new_line = re.sub(each_reg, hex(self.read_reg(each_reg)), new_line)

        items = []

        for elem in elems:
            if elem in self.ql.reg.register_mapping.keys():
                if (value := self.ql.reg.read(elem)):
                    items.append(value)
            else:
                items.append(self.read_int(elem))

        addr = sum(items)

        ft, sz, ct = fmt

        if ft == "i":

            for offset in range(addr, addr+ct*4, 4):
                line = self.disasm(offset)
                if line:
                    print(f"0x{line.address:x}: {line.mnemonic}\t{line.op_str}")


        else:
            lines = 1 if ct <= 4 else math.ceil(ct / 4)

            mem_read = []
            for offset in range(ct):
                # append data if read successfully, otherwise return error message
                if (data := self.try_read(addr+(offset*sz), sz))[0] is not None:
                    mem_read.append(data[0])

                else:
                    return data[1]

            for line in range(lines):
                offset = line * sz * 4
                print(f"0x{addr+offset:x}:\t", end="")

                idx = line * self.ql.pointersize
                for each in mem_read[idx:idx+self.ql.pointersize]:
                    data = self.fmt_unpack(each, sz)
                    prefix = "0x" if ft in ("x", "a") else ""
                    pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                    ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")
                    print(f"{prefix}{data:{pad}{ft}}\t", end="")

        print()

        return True
