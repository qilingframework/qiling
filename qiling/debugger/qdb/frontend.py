#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

from __future__ import annotations
from typing import Optional, Mapping, Iterable, Union

import copy, math, os
from contextlib import contextmanager

from qiling.const import QL_ARCH

from .utils import dump_regs, get_arm_flags, disasm, parse_int
from .const import *


# read data from memory of qiling instance
def examine_mem(ql: Qiling, line: str) -> Union[bool, (str, int, int)]:

    _args = line.split()
    DEFAULT_FMT = ('x', 4, 1)

    if line.startswith("/"):  # followed by format letter and size letter

        def get_fmt(text):
            def extract_count(t):
                return "".join([s for s in t if s.isdigit()])

            f, s, c = DEFAULT_FMT
            if extract_count(text):
                c = int(extract_count(text))

            for char in text.strip(str(c)):
                if char in SIZE_LETTER.keys():
                    s = SIZE_LETTER.get(char)

                elif char in FORMAT_LETTER:
                    f = char

            return (f, s, c)

        fmt, addr = line.strip("/").split()

        fmt = get_fmt(fmt)

    elif len(_args) == 1:  # only address
        addr = _args[0]
        fmt = DEFAULT_FMT

    else:
        return False

    addr = addr.strip('$')

    if ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):
        addr = addr.replace("fp", "r11")

    elif ql.archtype == QL_ARCH.MIPS:
        addr = addr.replace("fp", "s8")

    addr = getattr(ql.reg, addr) if addr in ql.reg.register_mapping.keys() else parse_int(addr)

    def unpack(bs, sz):
        return {
                1: lambda x: x[0],
                2: ql.unpack16,
                4: ql.unpack32,
                8: ql.unpack64,
                }.get(sz)(bs)

    ft, sz, ct = fmt

    if ft == "i":

        for offset in range(addr, addr+ct*4, 4):
            line = disasm(ql, offset)
            if line:
                print(f"0x{line.address:x}: {line.mnemonic}\t{line.op_str}")

        print()

    else:
        lines = 1 if ct <= 4 else math.ceil(ct / 4)

        mem_read = [ql.mem.read(addr+(offset*sz), sz) for offset in range(ct)]

        for line in range(lines):
            offset = line * sz * 4
            print("0x{addr+offset:x}:\t", end="")

            idx = line * ql.pointersize
            for each in mem_read[idx:idx+ql.pointersize]:
                data = unpack(each, sz)
                prefix = "0x" if ft in ("x", "a") else ""
                pad = '0' + str(sz*2) if ft in ('x', 'a', 't') else ''
                ft = ft.lower() if ft in ("x", "o", "b", "d") else ft.lower().replace("t", "b").replace("a", "x")

                print(f"{prefix}{data:{pad}{ft}}\t", end="")

            print()

    return True


# get terminal window height and width
def get_terminal_size() -> Iterable:
    return map(int, os.popen('stty size', 'r').read().split())


# try to read data from ql memory
def _try_read(ql: Qiling, address: int, size: int) -> Optional[bytes]:
    try:
        result = ql.mem.read(address, size)
    except:
        result = None

    return result


# divider printer
@contextmanager
def context_printer(ql: Qiling, field_name: str, ruler: str = "=") -> None:
    _height, _width = get_terminal_size()
    print(field_name, ruler * (_width - len(field_name) - 1))
    yield
    print(ruler * _width)


def context_reg(ql: Qiling, saved_states: Optional[Mapping[str, int]] = None, /, *args, **kwargs) -> None:

    # context render for registers
    with context_printer(ql, "[Registers]"):

        _cur_regs = dump_regs(ql)

        _colors = (color.DARKCYAN, color.BLUE, color.RED, color.YELLOW, color.GREEN, color.PURPLE, color.CYAN, color.WHITE)

        if ql.archtype == QL_ARCH.MIPS:

            _cur_regs.update({"fp": _cur_regs.pop("s8")})

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
                    line = f"{color.UNDERLINE}{color.BOLD}{line}"

                if idx % 4 == 0 and idx != 32:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))

        elif ql.archtype in (QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

            _cur_regs.update({"sl": _cur_regs.pop("r10")})
            _cur_regs.update({"fp": _cur_regs.pop("r11")})
            _cur_regs.update({"ip": _cur_regs.pop("r12")})

            if saved_states is not None:
                _saved_states = copy.deepcopy(saved_states)
                _saved_states.update({"sl": _saved_states.pop("r10")})
                _saved_states.update({"fp": _saved_states.pop("r11")})
                _saved_states.update({"ip": _saved_states.pop("r12")})
                _diff = [k for k in _cur_regs if _cur_regs[k] != _saved_states[k]]

            else:
                _diff = None

            lines = ""
            for idx, r in enumerate(_cur_regs, 1):
                line = "{}{:}: 0x{{:08x}} {}\t".format(_colors[(idx-1) // 4], r, color.END)

                if _diff and r in _diff:
                    line = "{}{}".format(color.UNDERLINE, color.BOLD) + line

                if idx % 4 == 0:
                    line += "\n"

                lines += line

            print(lines.format(*_cur_regs.values()))
            print(color.GREEN, "[{cpsr[mode]} mode], Thumb: {cpsr[thumb]}, FIQ: {cpsr[fiq]}, IRQ: {cpsr[irq]}, NEG: {cpsr[neg]}, ZERO: {cpsr[zero]}, Carry: {cpsr[carry]}, Overflow: {cpsr[overflow]}".format(cpsr=get_arm_flags(ql.reg.cpsr)), color.END, sep="")

    # context render for Stack
    with context_printer(ql, "[Stack]", ruler="-"):

        for idx in range(8):
            _addr = ql.reg.arch_sp + idx * 4
            _val = ql.mem.read(_addr, ql.pointersize)
            print(f"$sp+0x{idx*4:02x}|[0x{_addr:08x}]=> 0x{ql.unpack(_val):08x}", end="")

            try:  # try to deference wether its a pointer
                _deref = ql.mem.read(_addr, ql.pointersize)
            except:
                _deref = None

            if _deref:
                print(f" => 0x{ql.unpack(_deref):08x}")


def print_asm(ql: Qiling, ins: CsInsn) -> None:
    fmt = (ins.address, ins.mnemonic.ljust(6), ins.op_str)
    if ql.reg.arch_pc == ins.address:
        print(f"PC ==>  0x{fmt[0]:x}\t{fmt[1]} {fmt[2]}")
    else:
        print(f"\t0x{fmt[0]:x}\t{fmt[1]} {fmt[2]}")


def context_asm(ql: Qiling, address: int) -> None:

    with context_printer(ql, field_name="[Code]"):

        # assembly before current location

        past_list = []

        if ql.archtype in (QL_ARCH.MIPS, QL_ARCH.ARM, QL_ARCH.ARM_THUMB):

            line = disasm(ql, address-0x10)

        while line:
            if line.address == address:
                break

            addr = line.address + line.size
            line = disasm(ql, addr)

            if not line:
                break

            past_list.append(line)

        # print four insns before current location
        for line in past_list[:-1][:4]:
            print_asm(ql, line)

        # assembly for current location

        cur_ins = disasm(ql, address)
        print_asm(ql, cur_ins)

        # assembly after current location

        forward_insn_size = cur_ins.size
        for _ in range(5):
            forward_insn = disasm(ql, address+forward_insn_size)
            if forward_insn:
                print_asm(ql, forward_insn)
                forward_insn_size += forward_insn.size
