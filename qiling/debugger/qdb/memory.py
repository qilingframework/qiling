#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from qiling.const import QL_ARCH

from .context import Context
from .arch import ArchCORTEX_M, ArchARM, ArchMIPS, ArchX86
from .misc import check_and_eval
import re, math



def setup_memory_Manager(ql):

    arch_type = {
            QL_ARCH.X86: ArchX86,
            QL_ARCH.MIPS: ArchMIPS,
            QL_ARCH.ARM: ArchARM,
            QL_ARCH.CORTEX_M: ArchCORTEX_M,
            }.get(ql.arch.type)
    
    ret = type(
            "MemoryManager", 
            (MemoryManager, arch_type),
            {}
            )
    
    return ret(ql)


class MemoryManager(Context):
    """
    memory manager for handing memory access
    """

    def __init__(self, ql):
        super().__init__(ql)

    @property
    def get_default_fmt(self):
        return ('x', 4, 1)

    @property
    def get_format_letter(self):
        return {
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

    @property
    def get_size_letter(self):
        return {
            "b": 1, # 1-byte, byte
            "h": 2, # 2-byte, halfword
            "w": 4, # 4-byte, word
            "g": 8, # 8-byte, giant
            }

    def extract_count(self, t):
        return "".join([s for s in t if s.isdigit()])

    def get_fmt(self, text):
        f, s, c = self.get_default_fmt
        if self.extract_count(text):
            c = int(self.extract_count(text))

        for char in text.strip(str(c)):
            if char in self.get_size_letter.keys():
                s = self.get_size_letter.get(char)

            elif char in self.get_format_letter:
                f = char

        return (f, s, c)

    def fmt_unpack(self, bs: bytes, sz: int) -> int:
        return {
                1: lambda x: x[0],
                2: self.unpack16,
                4: self.unpack32,
                8: self.unpack64,
                }.get(sz)(bs)

    def handle_i(self, addr, ct=1):
        result = []

        for offset in range(addr, addr+ct*4, 4):
            if (line := self.disasm(offset)):
                result.append(line)

        return result


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

            rest = [args[0]] if len(args) == 1 else args

            fmt = self.get_default_fmt

        if len(rest) == 0:
            return

        line = []
        if (regs_dict := getattr(self, "regs_need_swapped", None)):
            for each in rest:
                for reg in regs_dict:
                    if each in regs_dict:
                        line.append(regs_dict[each])
                else:
                    line.append(each)
        else:
            line = rest

        # for simple calculation with register and address

        line = " ".join(line)
        # substitue register name with real value
        for each_reg in filter(lambda r: len(r) == 3, self.ql.arch.regs.register_mapping):
            reg = f"${each_reg}"
            if reg in line:
                line = re.sub(f"\\{reg}", hex(self.ql.arch.regs.read(each_reg)), line)

        for each_reg in filter(lambda r: len(r) == 2, self.ql.arch.regs.register_mapping):
            reg = f"${each_reg}"
            if reg in line:
                line = re.sub(f"\\{reg}", hex(self.ql.arch.regs.read(each_reg)), line)


        ft, sz, ct = fmt

        try:
            addr = check_and_eval(line)
        except:
            return "something went wrong ..."

        if ft == "i":
            output = self.handle_i(addr, ct)
            for each in output:
                print(f"0x{each.address:x}: {each.mnemonic}\t{each.op_str}")

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

                idx = line * self.ql.arch.pointersize
                for each in mem_read[idx:idx+self.ql.arch.pointersize]:
                    data = self.fmt_unpack(each, sz)
                    prefix = "0x" if ft in ("x", "a") else ""
                    pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                    ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")
                    print(f"{prefix}{data:{pad}{ft}}\t", end="")

                print()

        return True
