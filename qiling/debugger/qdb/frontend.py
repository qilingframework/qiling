#!/usr/bin/env python3

import os, math, copy
from contextlib import contextmanager

from .utils import dump_regs



# class for colorful prints
class color:
   CYAN      = '\033[96m'
   PURPLE    = '\033[95m'
   BLUE      = '\033[94m'
   YELLOW    = '\033[93m'
   GREEN     = '\033[92m'
   RED       = '\033[91m'
   DARKGRAY  = '\033[90m'
   WHITE     = '\033[48m'
   DARKCYAN  = '\033[36m'
   BLACK     = '\033[35m'
   UNDERLINE = '\033[4m'
   BOLD      = '\033[1m'
   END       = '\033[0m'


# read data from memory of qiling instance
def examine_mem(ql, xaddr, count):

    lines = 1 if count <= 4 else math.ceil(count / 4)

    mem_read = [ql.mem.read(xaddr+(offset*4), 4) for offset in range(count)]

    for line in range(lines):
        offset = line * 0x10
        print("0x%08x:\t" % (xaddr+offset), end="")

        idx = line * 4
        for each in mem_read[idx:idx+4]:
            print("0x%08x\t" % (ql.unpack(each)), end="")

        print()


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
    print(field_name, ruler * (_width - len(field_name) - 1))
    yield
    print(ruler * _width)


def context_reg(ql, saved_states, *args, **kwargs):

    # context render for registers
    with context_printer(ql, "[Registers]"):

        _cur_regs = dump_regs(ql)
        _cur_regs.update({"fp": _cur_regs.pop("s8")})
        _colors = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

        if saved_states is not None:
            _saved_states = copy.deepcopy(saved_states)
            _saved_states.update({"fp": _saved_states.pop("s8")})
            _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

        else:
            _diff = None

        lines = ""
        for idx, r in enumerate(_cur_regs, 1):
            line = "{}{}: 0x{{:08x}} {}\t".format(_colors[(idx-1) // 4], r, color.END)

            if _diff and r in _diff:
                line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

            if idx % 4 == 0 and idx != 32:
                line += "\n"

            lines += line

        print(lines.format(*_cur_regs.values()))

    # context render for Stack
    with context_printer(ql, "[Stack]", ruler="-"):

        for idx in range(8):
            _addr = ql.reg.arch_sp + idx * 4
            _val = ql.mem.read(_addr, ql.archbit // 8)
            print("$sp+0x%02x|[0x%08x]=> 0x%08x" % (idx*4, _addr, ql.unpack(_val)), end="")

            try: # try to deference wether its a pointer
                _deref = ql.mem.read(_addr, 4)
            except:
                _deref = None

            if _deref:
                print(" => 0x%08x" % ql.unpack(_deref))


def print_asm(ql, instructions):
    for ins in instructions:
        fmt = (ins.address, ins.mnemonic.ljust(6), ins.op_str)
        if ql.reg.arch_pc == ins.address:
            print("PC ==>  0x%x\t%s %s" % fmt)
        else:
            print("\t0x%x\t%s %s" % fmt)


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
