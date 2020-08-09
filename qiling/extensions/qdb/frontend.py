import os, math
from contextlib import contextmanager

from .utils import dump_stack, dump_regs



# read data from memory of qiling instance
def examine_mem(ql, xaddr, count):

    lines = 1 if count <= 4 else math.ceil(count / 4)

    mem_read = [ql.mem.read(xaddr+(offset*4), 4) for offset in range(count)]

    for line in range(lines):
        offset = line * 0x10
        ql.nprint("0x%08x:\t" % (xaddr+offset), end="")

        idx = line * 4
        for each in mem_read[idx:idx+4]:
            ql.nprint("0x%08x\t" % (ql.unpack(each)), end="")

        ql.nprint()

# get terminal window height and width
def get_terminal_size():
    return map(int, os.popen('stty size', 'r').read().split())


# try to read data from ql memory
def _try_read(ql, address, size):
    try:
        result = ql.mem.read(address, size)
    except:
        result = None

    return result

# divider printer
@contextmanager
def context_printer(ql, field_name, ruler="="):
    _height, _width = get_terminal_size()
    ql.nprint(field_name, ruler * (_width - len(field_name) - 1))
    yield
    ql.nprint(ruler * _width)


def context_reg(ql, *args, **kwargs):

    # context render for registers
    with context_printer(ql, "[Registers]"):
        dump_regs(ql)

    # context render for Stack
    with context_printer(ql, "[Stack]", ruler="-"):
        dump_stack(ql)


def print_asm(ql, instructions):
    for ins in instructions:
        fmt = (ins.address, ins.mnemonic.ljust(6), ins.op_str)
        if ql.reg.arch_pc == ins.address:
            ql.nprint("PC ==>  0x%x\t%s %s" % fmt)
        else:
            ql.nprint("\t0x%x\t%s %s" % fmt)


def context_asm(ql, address, size, *args, **kwargs):

    with context_printer(ql, field_name="[Code]"):
        md = ql.os.create_disassembler()

        # assembly before current location

        pre_tmp = _try_read(ql, address-0x10, 0x10)
        if pre_tmp:
            pre_ins = md.disasm(pre_tmp, address-0x10)
            print_asm(ql, pre_ins)

        # assembly for current locaton

        tmp = ql.mem.read(address, size)
        cur_ins = md.disasm(tmp, address)
        print_asm(ql, cur_ins)

        # assembly after current locaton

        pos_tmp = _try_read(ql, address+4, 0x10)
        if pos_tmp:
            pos_ins = md.disasm(pos_tmp, address+4)
            print_asm(ql, pos_ins)
