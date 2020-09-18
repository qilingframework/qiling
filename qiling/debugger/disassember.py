#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 
from elftools.elf.elffile import ELFFile
from qiling import *
from qiling.const import *
from capstone import *


class QlDisassember():
    def __init__(self, ql:Qiling):
        pass

    def disasm_all_lines(self, ql:Qiling, seg_name='.text'):
        def disasm(ql, address, size):
            md = ql.os.create_disassembler()
            md.detail = True
            return md.disasm(ql.mem.read(address, size), address)

        disasm_result = []
        if ql.archtype == QL_ARCH.X86 and ql.ostype == QL_OS.LINUX:
            BASE = int(ql.profile.get("OS32", "load_address"), 16)
            seg_start = 0x0
            seg_end = 0x0

            f = open(ql.path, 'rb')
            elffile = ELFFile(f)
            elf_header = elffile.header
            reladyn = elffile.get_section_by_name(seg_name)

            # No PIE
            if elf_header['e_type'] == 'ET_EXEC':
                seg_start = reladyn.header.sh_addr
                seg_end = seg_start + reladyn.data_size
            # PIE
            elif elf_header['e_type'] == 'ET_DYN':
                seg_start = BASE + reladyn.header.sh_addr
                seg_end = seg_start + reladyn.data_size

            for insn in disasm(ql, seg_start, seg_end-seg_start):
                disasm_result.append(insn)

        return disasm_result